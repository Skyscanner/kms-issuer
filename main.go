/*
Copyright 2021.

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
	"context"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/utils/clock"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	certmanagerskyscannernetv1alpha1 "github.com/Skyscanner/kms-issuer/apis/certmanager/v1alpha1"
	"github.com/Skyscanner/kms-issuer/controllers/certmanager"
	"github.com/Skyscanner/kms-issuer/pkg/kmsca"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	//+kubebuilder:scaffold:imports
)

var scheme = runtime.NewScheme()

const webhookPort = 9943

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(cmapi.AddToScheme(scheme))
	utilruntime.Must(certmanagerskyscannernetv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection, enableApprovedCheck bool
	var probeAddr string
	var localAWSEndpoint string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&enableApprovedCheck, "enable-approved-check", true,
		"Enable waiting for CertificateRequests to have an approved condition before signing.")
	flag.StringVar(&localAWSEndpoint, "local-aws-endpoint", "", "local-kms endpoint for testing")
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	// Set up logging and set up logger (use in this function only)
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   webhookPort,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "dcb53387.skyscanner.net",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// If using a local endpoint we create a custom endpoint resolver, hard code
	// the region and test credentials.
	// Otherwise we leave the config loading to the default aws order (env vars,
	// EC2 IMDS, etc.)
	awsLoadConfigOpts := []func(*config.LoadOptions) error{}
	if localAWSEndpoint != "" {
		setupLog.Info("Using custom AWS Endpoint", "endpoint", localAWSEndpoint)
		awsEndpointsResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{PartitionID: "aws", URL: localAWSEndpoint, SigningRegion: "eu-west-1"}, nil
		})
		awsLoadConfigOpts = append(
			awsLoadConfigOpts,
			config.WithEndpointResolverWithOptions(awsEndpointsResolver),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
			config.WithRegion("eu-west-1"),
		)
	} else {
		setupLog.Info("Using default AWS endpoint")
	}

	// Load the config with the given options and create a new KMSCA
	cfg, err := config.LoadDefaultConfig(context.Background(), awsLoadConfigOpts...)
	if err != nil {
		setupLog.Error(err, "Error loading default aws config")
		os.Exit(1)
	}
	setupLog.Info("Using region", "region", cfg.Region)
	ca := kmsca.NewKMSCA(&cfg)

	if err = (certmanager.NewKMSIssuerReconciler(mgr, ca)).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KMSIssuer")
		os.Exit(1)
	}

	if err = (&certmanager.CertificateRequestReconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("CertificateRequest"),
		Recorder: mgr.GetEventRecorderFor("certificaterequests-controller"),
		KMSCA:    ca,

		Clock:                  clock.RealClock{},
		CheckApprovedCondition: enableApprovedCheck,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CertificateRequest")
		os.Exit(1)
	}

	if err = (certmanager.NewKMSKeyReconciler(mgr, ca)).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KMSKey")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
