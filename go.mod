module github.com/Skyscanner/kms-issuer

go 1.16

require (
	github.com/aws/aws-sdk-go v1.42.18
	github.com/go-logr/logr v0.4.0
	github.com/google/uuid v1.3.0
	github.com/jetstack/cert-manager v1.6.1
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.15.0
	go.uber.org/zap v1.19.0
	k8s.io/api v0.22.4
	k8s.io/apimachinery v0.22.4
	k8s.io/client-go v0.22.4
	k8s.io/kubectl v0.22.4
	k8s.io/utils v0.0.0-20210819203725-bdf08cb9a70a
	sigs.k8s.io/controller-runtime v0.10.1
)
