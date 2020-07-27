
# KMS Issuer

[![Build Status](https://travis-ci.org/Skyscanner/kms-issuer.svg?branch=master)](https://travis-ci.org/Skyscanner/kms-issuer)

KMS issuer is a [cert-manager](https://cert-manager.io/) Certificate Request controller that uses [AWS KMS](https://aws.amazon.com/kms/) to sign the certificate request.

## Getting started

In this guide, we assume that you have a [Kubernetes](https://kubernetes.io/) environment with a cert-manager version supporting CertificateRequest issuers, cert-manager v0.11.0 or higher.

For any details on Cert-Manager, check the [official documentation](https://cert-manager.io/docs/usage/).

### Usage

1. Install [cert-manager](https://cert-manager.io/docs/installation/). The operator has been tested with version 1.15.

  ```bash
  kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v0.15.1/cert-manager.yaml
  ```

2. Install and run the kms-issuer

  Install the kms-issuer [Kubernetes Custom Resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) and start the controller.

  ```bash
  # Install CRD
  make install
  # Run the controller (you must have have a role able to create/access KMS keys)
  make run
  ```

3. Create a KMS Key

  You need a valid KMS asymetric key that as the ability to [SIGN_VERIFY](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html) messages.
  Currently, Cloudformation [does not support](https://github.com/aws-cloudformation/aws-cloudformation-coverage-roadmap/issues/337) KMS SIGN_VERIFY keys.
  To simply the provisioning process, the kms-issuer operator provides a dedicated controller for provisioning a valid KMS key.

  ```yaml
  cat << EOF | kubectl apply -f -
  ---
  apiVersion: cert-manager.skyscanner.net/v1alpha1
  kind: KMSKey
  metadata:
    name: kmskey-sample
  spec:
    aliasName: alias/kms-issuer-example
    description: a kms-issuer example kms key
    customerMasterKeySpec: RSA_2048
    tags:
      project: kms-issuer
    deletionPolicy: Delete
    deletionPendingWindowInDays: 7
  EOF
  ```

4. Install the kms-issuer operator.
  ```bash
  kubectl apply -f https://raw.githubusercontent.com/Skyscanner/kms-issuer/master/deploy/kubernetes/kms-issuer.yaml
  ```

5. Create a KMS issuer object

  ```yaml
  cat << EOF | kubectl apply -f -
  ---
  apiVersion: cert-manager.skyscanner.net/v1alpha1
  kind: KMSIssuer
  metadata:
    name: kms-issuer
    namespace: default
  spec:
    keyId: alias/kms-issuer-example # The KMS key id or alias
    commonName: My Root CA # The common name for the root certificate
    duration: 87600h # 10 years
  EOF
  ```

  At this point, the operator geneates a public root certificate signed using the provided KMS key. You can inspect it with the following command:

  ```bash
  kubectl get kmsissuer kms-issuer -o json | jq -r ".status.certificate" |  base64 --decode  | openssl x509 -noout -text
  ```

6. Finally, create a Certificate request that will be signed by our KMS issuer.

  ```yaml
  cat << EOF | kubectl apply -f -
  ---
  apiVersion: cert-manager.io/v1alpha2
  kind: Certificate
  metadata:
    name: example-com
    namespace: default
  spec:
    # Secret names are always required.
    secretName: example-com-tls
    duration: 8760h # 1 year
    renewBefore: 360h # 15d
    organization:
    - skyscanner
    # The use of the common name field has been deprecated since 2000 and is
    # discouraged from being used.
    commonName: example.com
    isCA: false
    keySize: 2048
    keyAlgorithm: rsa
    keyEncoding: pkcs1
    usages:
      - server auth
      - client auth
    # At least one of a DNS Name, URI, or IP address is required.
    dnsNames:
    - example.com
    - www.example.com
    uriSANs:
    - spiffe://cluster.local/ns/sandbox/sa/example
    ipAddresses:
    - 192.168.0.5
    # Issuer references are always required.
    issuerRef:
      name: kms-issuer
      # We can reference ClusterIssuers by changing the kind here.
      # The default value is Issuer (i.e. a locally namespaced Issuer)
      kind: KMSIssuer
      # This is optional since cert-manager will default to this value however
      # if you are using an external issuer, change this to that issuer group.
      group: cert-manager.skyscanner.net
  EOF
  ```

  You now have a key pair signed by KMS

  ```bash
  kubectl get secret example-com-tls
  ```

## Contributing

Check [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Check [SECURITY.md](SECURITY.md).
