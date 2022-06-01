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
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	kmsca "github.com/Skyscanner/kms-issuer/pkg/kmsca"
	mocks "github.com/Skyscanner/kms-issuer/pkg/kmsmock"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

	certmanagerv1alpha1 "github.com/Skyscanner/kms-issuer/apis/certmanager/v1alpha1"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	k8sClient client.Client
	testEnv   *envtest.Environment
	ctx       context.Context
	cancel    context.CancelFunc
	ca        kmsca.KMSCA
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	ctx, cancel = context.WithCancel(context.TODO())

	_, ok := os.LookupEnv("KMS_ISSUER_USE_EXISTING_CLUSTER")

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		UseExistingCluster:    &ok,
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = certmanagerv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())
	err = cmapi.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(k8sManager).NotTo(BeNil())
	Expect(err).NotTo(HaveOccurred())

	ca.Client = mocks.New()

	err = (&CertificateRequestReconciler{
		Client:                 k8sManager.GetClient(),
		Log:                    logf.Log,
		Recorder:               k8sManager.GetEventRecorderFor("certificaterequests-controller"),
		KMSCA:                  &ca,
		CheckApprovedCondition: true,
		Clock:                  clock.RealClock{},
	}).SetupWithManager(k8sManager)
	Expect(err).NotTo(HaveOccurred(), "failed to setup the CertificateRequestReconciler controller")

	err = NewKMSIssuerReconciler(k8sManager, &ca).SetupWithManager(k8sManager)
	Expect(err).NotTo(HaveOccurred(), "failed to setup the KMSIssuerReconciler controller")

	err = NewKMSKeyReconciler(k8sManager, &ca).SetupWithManager(k8sManager)
	Expect(err).NotTo(HaveOccurred(), "failed to setup the KMSKeyReconciler controller")

	go func() {
		defer GinkgoRecover()
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred(), "failed to run manager")
	}()

}, 60)

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
