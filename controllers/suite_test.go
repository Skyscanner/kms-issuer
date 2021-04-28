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

package controllers

import (
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap/zapcore"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	kmsca "github.com/Skyscanner/kms-issuer/pkg/kmsca"
	mocks "github.com/Skyscanner/kms-issuer/pkg/kmsmock"

	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

	certmanagerv1alpha1 "github.com/Skyscanner/kms-issuer/api/v1alpha1"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment
var ca kmsca.KMSCA

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func(done Done) {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.Level(zapcore.Level(4))))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "config", "crd", "bases")},
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	err = certmanagerv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	err = certmanager.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sClient).ToNot(BeNil())

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		HealthProbeBindAddress: "0",
		MetricsBindAddress:     "0",
	})
	Expect(err).NotTo(HaveOccurred(), "failed to create manager")
	ca.Client = mocks.New()

	err = (&CertificateRequestReconciler{
		Client:                 mgr.GetClient(),
		Log:                    logf.Log,
		Recorder:               mgr.GetEventRecorderFor("certificaterequests-controller"),
		KMSCA:                  &ca,
		CheckApprovedCondition: true,
		Clock:                  clock.RealClock{},
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred(), "failed to setup the CertificateRequestReconciler controller")

	err = NewKMSIssuerReconciler(mgr, &ca).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred(), "failed to setup the KMSIssuerReconciler controller")

	err = NewKMSKeyReconciler(mgr, &ca).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred(), "failed to setup the KMSKeyReconciler controller")

	go func() {
		defer GinkgoRecover()
		err := mgr.Start(ctrl.SetupSignalHandler())
		Expect(err).NotTo(HaveOccurred(), "failed to start manager")
	}()

	close(done)
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})
