/*
Copyright 2020 Skyscanner Limited.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certmanager

import (
	"context"

	"github.com/go-logr/logr"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	kmsiapi "github.com/Skyscanner/kms-issuer/v4/apis/certmanager/v1alpha1"
	kmsca "github.com/Skyscanner/kms-issuer/v4/pkg/kmsca"
)

// NewKMSKeyReconciler Initialise a new NewKMSKeyReconciler
func NewKMSKeyReconciler(mgr manager.Manager, ca *kmsca.KMSCA) *KMSKeyReconciler {
	return &KMSKeyReconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("kmskey_controller"),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("kmskey_controller"),
		KMSCA:    ca,
	}
}

// KMSKeyReconciler reconciles a KMSKey object
type KMSKeyReconciler struct {
	client.Client
	Log      logr.Logger
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	KMSCA    *kmsca.KMSCA
}

// Annotation for generating RBAC role for writing Events
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// +kubebuilder:rbac:groups=cert-manager.skyscanner.net,resources=kmskeys,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert-manager.skyscanner.net,resources=kmskeys/status,verbs=get;update;patch

func (r *KMSKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("kmskey", req.NamespacedName)

	// retrieve the KMSKey resource to reconcile.
	kmsKey := &kmsiapi.KMSKey{}
	if err := r.Client.Get(ctx, req.NamespacedName, kmsKey); err != nil {
		log.Error(err, "failed to retrieve KMSKey resource")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Register finalizer.
	if NeedToAddFinalizer(kmsKey) {
		log.Info("register finalizer")
		AddFinalizer(kmsKey)
		if err := r.Update(ctx, kmsKey); err != nil {
			return ctrl.Result{}, r.manageFailure(ctx, log, kmsKey, err, "Failed to add the object finalizer")
		}
	}

	// The object is being deleted
	if IsBeingDeleted(kmsKey) {
		// our finalizer is present, so lets handle any external dependency.
		if !NeedToAddFinalizer(kmsKey) {
			if kmsKey.Spec.DeletionPolicy == "Delete" {
				log.Info("delete KMSKey")
				err := r.KMSCA.DeleteKey(ctx, &kmsca.DeleteKeyInput{
					AliasName:           kmsKey.Spec.AliasName,
					PendingWindowInDays: kmsKey.Spec.DeletionPendingWindowInDays,
				})
				if err != nil {
					return ctrl.Result{}, r.manageFailure(ctx, log, kmsKey, err, "Failed to delete the KMS key")
				}
			}
			// remove our finalizer from the list and update it.
			RemoveFinalizer(kmsKey)
			if err := r.Update(ctx, kmsKey); err != nil {
				return ctrl.Result{}, r.manageFailure(ctx, log, kmsKey, err, "Failed to remove the object finalizer")
			}
		}
		return ctrl.Result{}, nil
	}

	// Create the KMS key
	keyID, err := r.KMSCA.CreateKey(ctx, &kmsca.CreateKeyInput{
		AliasName:             kmsKey.Spec.AliasName,
		Description:           kmsKey.Spec.Description,
		CustomerMasterKeySpec: kmsKey.Spec.CustomerMasterKeySpec,
		Policy:                kmsKey.Spec.Policy,
		Tags:                  kmsKey.Spec.Tags,
	})
	if err != nil {
		return ctrl.Result{}, r.manageFailure(ctx, log, kmsKey, err, "Failed to create the kms key")
	}
	kmsKey.Status.KeyID = keyID
	if err := r.patchKeyStatus(ctx, kmsKey); err != nil {
		return ctrl.Result{}, r.manageFailure(ctx, log, kmsKey, err, "Failed to update kmsKey.Status.KeyId")
	}
	return ctrl.Result{}, r.manageSuccess(ctx, log, kmsKey)
}

func (r *KMSKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kmsiapi.KMSKey{}).
		Complete(r)
}

// patchStatus updates the kmsiapi.KMSIssuer using a MergeFrom strategy
func (r *KMSKeyReconciler) patchKeyStatus(ctx context.Context, issuer *kmsiapi.KMSKey) error {
	var latest kmsiapi.KMSKey

	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(issuer), &latest); err != nil {
		return err
	}

	patch := client.MergeFrom(latest.DeepCopy())
	latest.Status = issuer.Status

	return r.Client.Status().Patch(ctx, &latest, patch)
}

// manageSuccess
func (r *KMSKeyReconciler) manageSuccess(ctx context.Context, log logr.Logger, kmskey *kmsiapi.KMSKey) error {
	reason := kmsiapi.KMSKeyReasonIssued
	msg := ""
	log.Info("successfully reconciled kms key")
	r.Recorder.Event(kmskey, core.EventTypeNormal, reason, msg)
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionTrue, reason, msg)
	kmskey.Status.SetCondition(&ready)
	return r.patchKeyStatus(ctx, kmskey)
}

// manageFailure
func (r *KMSKeyReconciler) manageFailure(ctx context.Context, log logr.Logger, kmskey *kmsiapi.KMSKey, issue error, msg string) error {
	reason := kmsiapi.KMSKeyReasonFailed
	log.Error(issue, msg)
	r.Recorder.Event(kmskey, core.EventTypeWarning, reason, msg)
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionFalse, reason, msg)
	kmskey.Status.SetCondition(&ready)
	return r.patchKeyStatus(ctx, kmskey)
}
