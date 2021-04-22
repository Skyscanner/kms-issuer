# KMS Issuer

[![Build Status](https://travis-ci.org/Skyscanner/kms-issuer.svg?branch=main)](https://travis-ci.org/Skyscanner/kms-issuer)

KMS issuer is a [cert-manager](https://cert-manager.io/) Certificate Request controller that uses [AWS KMS](https://aws.amazon.com/kms/) to sign the certificate request.

## Getting started

In this guide, we assume that you have a [Kubernetes](https://kubernetes.io/) environment with a cert-manager version supporting CertificateRequest issuers, cert-manager v0.11.0 or higher.

For any details on Cert-Manager, check the [official documentation](https://cert-manager.io/docs/usage/).

### Usage

1. Install [cert-manager](https://cert-manager.io/docs/installation/). The operator has been tested with version v0.15.1

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
kubectl apply -f https://raw.githubusercontent.com/Skyscanner/kms-issuer/main/deploy/kubernetes/kms-issuer.yaml
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

## API Reference

### KMSKey

A KMSKey resource is used to create an AWS KMS](https://aws.amazon.com/kms/) asymetric key compatible with the KMS issuer.

| Field                            | Type                                                                                                                     | Description                                                                                                                                                                  |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| apiVersion                       | string                                                                                                                   | `cert-manager.skyscanner.net/v1alpha1`                                                                                                                                       |
| kind                             | string                                                                                                                   | `KMSKey`                                                                                                                                                                     |
| metadata                         | [Kubernetes meta/v1.ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#objectmeta-v1-meta) | Refer to the Kubernetes API documentation for the fields of the `metadata` field.                                                                                            |     |
| spec                             | object                                                                                                                   | Desired state of the KMSKey resource.                                                                                                                                        |
| spec.aliasName                   | the alias name for the kms key. This value must begin with alias/ followed by a name, such as alias/ExampleAlias.        |
| spec.description                 | string                                                                                                                   | Description for the key (optional)                                                                                                                                           |
| spec.customerMasterKeySpec       | string                                                                                                                   | Determines the signing algorithms that the CMK supports. Only RSA_2048 is currently supported. (optional, default=RSA_2048)                                                  |
| spec.policy                      | string                                                                                                                   | The key policy to attach to the CMK (optional)                                                                                                                               |
| spec.tags                        | object                                                                                                                   | A list of tags for the key (optional)                                                                                                                                        |
| spec.deletionPolicy              | string                                                                                                                   | Policy to deletes the alias and key on object deletion. Either `Retain` or `Delete` (optional, default=Retain)                                                               |
| spec.deletionPendingWindowInDays | int                                                                                                                      | Number of days before the KMS key gets deleted. If you include a value, it must be between 7 and 30, inclusive. If you do not include a value, it defaults to 30. (optional) |

### KMSIssuer

A KMSIssuer resource configures a new [Cert-Manager external issuer](https://cert-manager.io/docs/configuration/external).

| Field            | Type                                                                                                                     | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| apiVersion       | string                                                                                                                   | `cert-manager.skyscanner.net/v1alpha1`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| kind             | string                                                                                                                   | `KMSIssuer`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| metadata         | [Kubernetes meta/v1.ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#objectmeta-v1-meta) | Refer to the Kubernetes API documentation for the fields of the `metadata` field.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |     |
| spec             | object                                                                                                                   | Desired state of the KMSIssuer resource.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| spec.keyId       | string                                                                                                                   | The unique identifier for the customer master key                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| spec.commonName  | string                                                                                                                   | The common name to be used on the Certificate.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| spec.duration    | duration                                                                                                                 | Certificate default Duration. (optional, default=26280h aka 3 years)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| spec.renewBefore | duration                                                                                                                 | The amount of time before the certificate’s notAfter time that the issuer will begin to attempt to renew the certificate. If this value is greater than the total duration of the certificate (i.e. notAfter - notBefore), it will be automatically renewed 2/3rds of the way through the certificate’s duration. <br> <br> The `NotBefore` field on the certificate is set to the current time rounded down by the renewal interval. For example, if the certificate is renewed every hour, the `NotBefore` field is set to the beggining of the hour. If the certificate is renewed every day, the `NotBefore` field is set to the beggining of the day. This allows the generation of consistent certificates regardless of when it has been generated during the renewal period, or recreate the same certificate after a backup/restore of your kubernetes cluster. For more details on the computation, check the [time.Truncate](https://golang.org/pkg/time/#Time.Truncate) function. |

## Disable Approval Check

The KMS Issuer will wait for CertificateRequests to have an [approved condition
set](https://cert-manager.io/docs/concepts/certificaterequest/#approval) before
signing. If using an older version of cert-manager (pre v1.3), you can disable
this check by supplying the command line flag `-disable-approved-check` to the
Issuer Deployment.

## Contributing

Kms-Issuer is built using the [Kubebuilder](https://book.kubebuilder.io/) framework. See the [official documentation](https://book.kubebuilder.io/quick-start.html) to get started and check [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## Security

Check [SECURITY.md](SECURITY.md).
