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
	"crypto/x509"
	"net"
	"testing"
	"time"

	kmsiapi "github.com/Skyscanner/kms-issuer/apis/certmanager/v1alpha1"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"

	"github.com/Skyscanner/kms-issuer/pkg/kmsca"
	"github.com/jetstack/cert-manager/test/e2e/util"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	fakeclock "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var _ = Context("CertificateRequestReconciler", func() {
	Describe("when a new CertificateRequest is created", func() {
		It("should sign the certificate request", func() {
			By("Creating a KMSIssuer")
			keyID, err := ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})
			Expect(err).To(BeNil())
			issuerKey := client.ObjectKey{
				Name:      "test-kms-issuer",
				Namespace: "default",
			}
			issuer := &kmsiapi.KMSIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      issuerKey.Name,
					Namespace: issuerKey.Namespace,
				},
				Spec: kmsiapi.KMSIssuerSpec{
					KeyID:      keyID,
					CommonName: "RootCA",
					Duration:   &metav1.Duration{},
				},
			}
			Expect(k8sClient.Create(context.Background(), issuer)).Should(Succeed(), "failed to create test KMSIssuer resource")
			Eventually(
				func() bool {
					issuer := &kmsiapi.KMSIssuer{}
					Expect(k8sClient.Get(context.Background(), issuerKey, issuer)).Should(Succeed(), "failed to get KMSIssuer resource")
					return len(issuer.Status.Certificate) > 0
				},
				time.Second*1, time.Millisecond*100,
			).Should(BeTrue(), "Certificate should be set")

			By("Creating a Certificate Request to be signed by the KMS Issuer")
			crKey := client.ObjectKey{
				Name:      "test-kms-issuer",
				Namespace: "default",
			}
			exampleDNSNames := []string{"dnsName1.co", "dnsName2.ninja"}
			exampleIPAddresses := []net.IP{
				[]byte{8, 8, 8, 8},
				[]byte{1, 1, 1, 1},
			}
			exampleURIs := []string{"spiffe://foo.foo.example.net", "spiffe://foo.bar.example.net"}
			cr, _, err := util.NewCertManagerBasicCertificateRequest( //nolint:staticcheck // TODO: fixed when refactored
				crKey.Name, issuerKey.Name, "KMSIssuer",
				&metav1.Duration{
					Duration: time.Hour * 24 * 90,
				},
				exampleDNSNames, exampleIPAddresses, exampleURIs, x509.RSA,
			)
			cr.ObjectMeta.Namespace = crKey.Namespace
			cr.Spec.IssuerRef.Group = kmsiapi.GroupVersion.Group
			Expect(err).To(BeNil())
			Expect(k8sClient.Create(context.Background(), cr)).Should(Succeed(), "failed to create test CertificateRequest resource")

			By("Approving request so it may be signed")
			Expect(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(cr), cr)).Should(Succeed(), "failed to get CertificateRequest resource")
			apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "Approved", "")
			Expect(k8sClient.Status().Update(context.Background(), cr)).Should(Succeed(), "failed to approve CertificateRequest resource")

			By("Checking the certificate is signed by the KMS issuer")
			Eventually(
				func() bool {
					cr := &cmapi.CertificateRequest{}
					Expect(k8sClient.Get(context.Background(), crKey, cr)).Should(Succeed(), "failed to get CertificateRequest resource")
					return len(cr.Status.Certificate) > 0
				},
				time.Second*1, time.Millisecond*100,
			).Should(BeTrue(), "status.Certificate field should be set")
		})
	})
})

func TestRequestShouldBeProcessed(t *testing.T) {
	fixedTime := time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)
	fclock := fakeclock.NewFakeClock(fixedTime)

	tests := map[string]struct {
		conds         []cmapi.CertificateRequestCondition
		checkApproved bool

		expConds         []cmapi.CertificateRequestCondition
		expShouldProcess bool
		expEvent         *string
		expFailureTime   *metav1.Time
	}{
		"if request has true ready condition, exit false": {
			conds: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionTrue,
					Reason: cmapi.CertificateRequestReasonIssued,
				},
			},
			checkApproved: false,
			expConds: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionTrue,
					Reason: cmapi.CertificateRequestReasonIssued,
				},
			},
			expShouldProcess: false,
			expEvent:         nil,
			expFailureTime:   nil,
		},
		"if request has ready condition reason failed, exit false": {
			conds: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionFalse,
					Reason: cmapi.CertificateRequestReasonFailed,
				},
			},
			checkApproved: false,
			expConds: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionFalse,
					Reason: cmapi.CertificateRequestReasonFailed,
				},
			},
			expShouldProcess: false,
			expEvent:         nil,
			expFailureTime:   nil,
		},
		"if request has ready condition reason denied, exit false": {
			conds: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionFalse,
					Reason: cmapi.CertificateRequestReasonDenied,
				},
			},
			checkApproved: false,
			expConds: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionFalse,
					Reason: cmapi.CertificateRequestReasonDenied,
				},
			},
			expShouldProcess: false,
			expEvent:         nil,
			expFailureTime:   nil,
		},
		"if request has been denied, exit false and update ready reason with ready denied": {
			conds: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionDenied,
					Status: cmmeta.ConditionTrue,
					Reason: "Denied",
				},
			},
			checkApproved: false,
			expConds: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionDenied,
					Status: cmmeta.ConditionTrue,
					Reason: "Denied",
				},
				{
					Type:               cmapi.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             cmapi.CertificateRequestReasonDenied,
					Message:            "The CertificateRequest was denied by an approval controller",
					LastTransitionTime: &metav1.Time{Time: fixedTime},
				},
			},
			expShouldProcess: false,
			expEvent:         strP("Warning Denied The CertificateRequest was denied by an approval controller"),
			expFailureTime:   &metav1.Time{Time: fixedTime},
		},
		"if request has been denied and has a ready denied condition, exit false": {
			conds: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionDenied,
					Status: cmmeta.ConditionTrue,
					Reason: "Denied",
				},
				{
					Type:               cmapi.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             cmapi.CertificateRequestReasonDenied,
					Message:            "The CertificateRequest was denied by an approval controller",
					LastTransitionTime: &metav1.Time{Time: fixedTime},
				},
			},
			checkApproved: false,
			expConds: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionDenied,
					Status: cmmeta.ConditionTrue,
					Reason: "Denied",
				},
				{
					Type:               cmapi.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             cmapi.CertificateRequestReasonDenied,
					Message:            "The CertificateRequest was denied by an approval controller",
					LastTransitionTime: &metav1.Time{Time: fixedTime},
				},
			},
			expShouldProcess: false,
			expEvent:         nil,
			expFailureTime:   nil,
		},
		"if request has not been approved, but check approved condition is false, return true": {
			conds:            []cmapi.CertificateRequestCondition{},
			checkApproved:    false,
			expConds:         []cmapi.CertificateRequestCondition{},
			expShouldProcess: true,
			expEvent:         nil,
			expFailureTime:   nil,
		},
		"if request has not been approved, and check approved condition is true, return false": {
			conds:            []cmapi.CertificateRequestCondition{},
			checkApproved:    true,
			expConds:         []cmapi.CertificateRequestCondition{},
			expShouldProcess: false,
			expEvent:         nil,
			expFailureTime:   nil,
		},
		"if request has been approved and check approved condition is true, return true": {
			conds: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionApproved,
					Status: cmmeta.ConditionTrue,
					Reason: "Approved",
				},
			},
			checkApproved: true,
			expConds: []cmapi.CertificateRequestCondition{
				{
					Type:   cmapi.CertificateRequestConditionApproved,
					Status: cmmeta.ConditionTrue,
					Reason: "Approved",
				},
			},
			expShouldProcess: true,
			expEvent:         nil,
			expFailureTime:   nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			apiutil.Clock = fclock
			scheme := runtime.NewScheme()
			_ = clientgoscheme.AddToScheme(scheme)
			_ = cmapi.AddToScheme(scheme)

			request := &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cr",
					Namespace: "test-ns",
				},
				Status: cmapi.CertificateRequestStatus{
					Conditions: test.conds,
				},
			}

			fclient := fakeclient.NewClientBuilder().
				WithRuntimeObjects(request).
				WithScheme(scheme).
				Build()

			fakeRecorder := record.NewFakeRecorder(1)

			c := CertificateRequestReconciler{
				Client:                 fclient,
				Log:                    logf.Log,
				Recorder:               fakeRecorder,
				Clock:                  fclock,
				CheckApprovedCondition: test.checkApproved,
			}

			shouldProcess, err := c.requestShouldBeProcessed(context.TODO(), logf.Log, request)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			if shouldProcess != test.expShouldProcess {
				t.Errorf("unexpected shouldProcess, exp=%t got=%t",
					test.expShouldProcess, shouldProcess)
			}

			updatedRequest := new(cmapi.CertificateRequest)
			err = fclient.Get(context.TODO(), client.ObjectKeyFromObject(request), updatedRequest)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			if !apiequality.Semantic.DeepEqual(request.Status.Conditions, test.expConds) {
				t.Errorf("unexpected conditions, exp=%#+v got=%#+v",
					test.expConds, request.Status.Conditions)
			}
			if !apiequality.Semantic.DeepEqual(request.Status.FailureTime, test.expFailureTime) {
				t.Errorf("unexpected failureTime, exp=%#+v got=%#+v",
					test.expFailureTime, request.Status.FailureTime)
			}

			select {
			case event := <-fakeRecorder.Events:
				if test.expEvent == nil {
					t.Errorf("expected no event, got='%s'", event)
				} else if *test.expEvent != event {
					t.Errorf("unexpected event, exp='%s' got='%s'", *test.expEvent, event)
				}
				break
			default:
				if test.expEvent != nil {
					t.Errorf("unexpected event, exp='%s' got=''", *test.expEvent)
				}
			}
		})
	}
}

func strP(s string) *string {
	return &s
}
