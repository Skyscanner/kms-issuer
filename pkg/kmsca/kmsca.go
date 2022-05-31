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

package kmsca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"time"

	"crypto/sha1" //nolint:gosec // Used for consistent hash
	"math/big"

	"github.com/Skyscanner/kms-issuer/pkg/interfaces"
	"github.com/Skyscanner/kms-issuer/pkg/signer"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	// DefaultCertDuration is the default CA certificate validity duration
	DefaultCertDuration = time.Hour * 24 * 365 * 3 // 3 year
	// DefaultCertRenewalRatio is default ratio of time before the certificate
	// is expected to be renewed
	DefaultCertRenewalRatio = 2.0 / 3
)

// KMSCA KMS Certificate Authority provides the API operation methods for implementation
// a certificate authority on top of AWS KMS.
type KMSCA struct {
	Client interfaces.KMSClient
}

// NewKMSCA creates a new instance of the KMSCA client with a session.
// If additional configuration is needed for the client instance use the optional
// aws.Config parameter to add your extra config.
func NewKMSCA(cfg *aws.Config) *KMSCA {
	return &KMSCA{
		Client: kms.NewFromConfig(*cfg),
	}
}

// CreateKey creates an asymetric KMS key used to sign certificates and a KMS Alias pointing at the key.
// The method only creates the key if the alias hasn't yet been created.
// Returns the KeyID string
func (ca *KMSCA) CreateKey(ctx context.Context, input *CreateKeyInput) (string, error) {
	// Check if the key already exists
	response, err := ca.Client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(input.AliasName),
	})
	if err == nil {
		// return existing key if one already exists
		return aws.ToString(response.KeyMetadata.KeyId), nil
	}

	// if the error isn't a NotFoundException then raise it
	var nsk *kmstypes.NotFoundException
	if !errors.As(err, &nsk) {
		return "", err
	}

	// Create the KMS key
	keyInput := &kms.CreateKeyInput{
		KeyUsage: kmstypes.KeyUsageTypeSignVerify,
		KeySpec:  kmstypes.KeySpec(kmstypes.CustomerMasterKeySpecRsa2048),
	}
	if len(input.CustomerMasterKeySpec) > 0 {
		keyInput.KeySpec = kmstypes.KeySpec(input.CustomerMasterKeySpec)
	}
	if len(input.Description) > 0 {
		keyInput.Description = aws.String(input.Description)
	}
	if len(input.Policy) > 0 {
		keyInput.Policy = aws.String(input.Policy)
	}
	if len(input.Tags) > 0 {
		for k, v := range input.Tags {
			keyInput.Tags = append(keyInput.Tags, kmstypes.Tag{TagKey: aws.String(k), TagValue: aws.String(v)})
		}
	}
	key, err := ca.Client.CreateKey(ctx, keyInput)
	if err != nil {
		return "", err
	}
	// Create the KMS alias
	_, err = ca.Client.CreateAlias(ctx, &kms.CreateAliasInput{
		TargetKeyId: key.KeyMetadata.KeyId,
		AliasName:   aws.String(input.AliasName),
	})
	if err != nil {
		return "", err
	}
	return aws.ToString(key.KeyMetadata.KeyId), nil
}

// DeleteKey delete a KMS key alias and the underlying target KMS Key.
func (ca *KMSCA) DeleteKey(ctx context.Context, input *DeleteKeyInput) error {
	// Check if the key already exists
	response, err := ca.Client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(input.AliasName),
	})
	if err != nil {
		return err
	}
	// Delete the KMS key
	deleteInput := &kms.ScheduleKeyDeletionInput{
		KeyId: response.KeyMetadata.KeyId,
	}
	if input.PendingWindowInDays > 0 {
		deleteInput.PendingWindowInDays = aws.Int32(int32(input.PendingWindowInDays))
	}

	_, err = ca.Client.ScheduleKeyDeletion(ctx, deleteInput)
	if err != nil {
		return err
	}
	// Delete the KMS alias
	_, err = ca.Client.DeleteAlias(ctx, &kms.DeleteAliasInput{
		AliasName: aws.String(input.AliasName),
	})
	if err != nil {
		return err
	}
	return nil
}

// GenerateCertificateAuthorityCertificate returns the Certificate Authority Certificate
func (ca *KMSCA) GenerateCertificateAuthorityCertificate(input *GenerateCertificateAuthorityCertificateInput) *x509.Certificate {
	// Compute the start/end validity.
	// The rounding factor is used to ensure all the certificates issued within the same period are identical.
	notBefore := time.Now().Truncate(input.Rounding)
	notAfter := notBefore.Add(input.Duration)

	// Compute CA certificate
	cert := &x509.Certificate{
		Subject:               input.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	// Compute the serial number
	serialNumberKey := fmt.Sprintf("%s %v", input, cert)
	sha := sha1.Sum([]byte(serialNumberKey)) //nolint:gosec // Used for consistent hash
	cert.SerialNumber = new(big.Int).SetBytes(sha[:])

	return cert
}

// GenerateAndSignCertificateAuthorityCertificate returns the signed Certificate Authority Certificate
func (ca *KMSCA) GenerateAndSignCertificateAuthorityCertificate(ctx context.Context, input *GenerateCertificateAuthorityCertificateInput) (*x509.Certificate, error) {
	cert := ca.GenerateCertificateAuthorityCertificate(input)
	newSigner, err := signer.New(ctx, ca.Client, input.KeyID)
	if err != nil {
		return nil, err
	}
	pub := newSigner.Public()
	if pub == nil {
		return nil, errors.New("could not retrieve the public key associated with the KMS private key")
	}
	signedBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, newSigner)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(signedBytes)
}

// SignCertificate Signs a certificate request using KMS.
func (ca *KMSCA) SignCertificate(ctx context.Context, input *IssueCertificateInput) (*x509.Certificate, error) {
	newSigner, err := signer.New(ctx, ca.Client, input.KeyID)
	if err != nil {
		return nil, err
	}
	signedBytes, err := x509.CreateCertificate(rand.Reader, input.Cert, input.Parent, input.PublicKey, newSigner)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(signedBytes)
}

// CreateKeyInput input for the CreateKey method
type CreateKeyInput struct {
	// AliasName Specifies the alias name for the kms key. This value must begin with alias/ followed by a
	// name, such as alias/ExampleAlias.
	AliasName string
	// Description for the key
	Description string
	// CustomerMasterKeySpec determines the signing algorithms that the CMK supports.
	// Only RSA_2048 is currently supported.
	CustomerMasterKeySpec string
	// The key policy to attach to the CMK
	Policy string
	// Tags is a list of tags for the key
	Tags map[string]string
}

// DeleteKeyInput input for the CreateKey method
type DeleteKeyInput struct {
	// AliasName Specifies the alias name for the kms key. This value must begin with alias/ followed by a
	// name, such as alias/ExampleAlias.
	AliasName string
	// PendingWindowInDays. This value is optional. If you include a value, it must be between 7 and
	// 30, inclusive. If you do not include a value, it defaults to 30.
	PendingWindowInDays int
}

type Key struct {
	// KeyID is the KMS Key Id
	KeyID string
}
type GenerateCertificateAuthorityCertificateInput struct {
	// KeyID is the KMS Key Id
	KeyID string
	// Subject of the CA certificate
	Subject pkix.Name
	// Duration is certificate validity duration
	Duration time.Duration
	// Rounding is used to round down the certificate NotBefore time.
	// For example, by setting the rounding period to 1h, all the certificates generated between the start
	// and in the end of an hour will be identical
	Rounding time.Duration
}

type IssueCertificateInput struct {
	// KeyID is the KMS Key Id
	KeyID string
	// CSR Certificate Request
	Cert *x509.Certificate
	// PublicKey
	PublicKey crypto.PublicKey
	// Parent Signing Certificate
	Parent *x509.Certificate
	// Public
}
