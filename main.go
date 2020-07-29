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

package main

import (
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	certmanagerv1alpha1 "github.com/Skyscanner/kms-issuer/api/v1alpha1"
	"github.com/Skyscanner/kms-issuer/controllers"
	"github.com/Skyscanner/kms-issuer/pkg/kmsca"
	"github.com/aws/aws-sdk-go/aws/session"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
	port     = 9443
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = cmapi.AddToScheme(scheme)
	_ = certmanagerv1alpha1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               port,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "8655c165.skyscanner.net",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Create a new aws session
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	ca := kmsca.NewKMSCA(sess)

	if err = (controllers.NewKMSIssuerReconciler(mgr, ca)).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KMSIssuer")
		os.Exit(1)
	}

	if err = (&controllers.CertificateRequestReconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("CertificateRequest"),
		Recorder: mgr.GetEventRecorderFor("certificaterequests-controller"),
		KMSCA:    ca,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CertificateRequest")
		os.Exit(1)
	}

	if err = (controllers.NewKMSKeyReconciler(mgr, ca)).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KMSKey")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
