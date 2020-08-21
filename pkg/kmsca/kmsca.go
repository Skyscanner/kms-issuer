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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"

	"github.com/Skyscanner/kms-issuer/pkg/signer"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

// KMSCA KMS Certificate Authority provides the API operation methods for implementation
// a certificate authority on top of AWS KMS.
type KMSCA struct {
	Client kmsiface.KMSAPI
}

// NewKMSCA creates a new instance of the KMSCA client with a session.
// If additional configuration is needed for the client instance use the optional
// aws.Config parameter to add your extra config.
func NewKMSCA(p client.ConfigProvider, cfgs ...*aws.Config) *KMSCA {
	return &KMSCA{
		Client: kms.New(p, cfgs...),
	}
}

// CreateKey creates an asymetric KMS key used to sign certificates and a KMS Alias pointing at the key.
// The method only creates the key if the alias hasn't yet been created.
// Returns the KeyID string
func (ca *KMSCA) CreateKey(input *CreateKeyInput) (string, error) {
	// Check if the key already exists
	response, err := ca.Client.DescribeKey(&kms.DescribeKeyInput{
		KeyId: aws.String(input.AliasName),
	})
	if err == nil {
		// return existing key if one already exists
		return aws.StringValue(response.KeyMetadata.KeyId), nil
	}
	if err.(awserr.Error).Code() != kms.ErrCodeNotFoundException {
		return "", err
	}
	// Create the KMS key
	keyInput := &kms.CreateKeyInput{
		KeyUsage:              aws.String(kms.KeyUsageTypeSignVerify),
		CustomerMasterKeySpec: aws.String(kms.CustomerMasterKeySpecRsa2048),
	}
	if len(input.CustomerMasterKeySpec) > 0 {
		keyInput.CustomerMasterKeySpec = aws.String(input.CustomerMasterKeySpec)
	}
	if len(input.Description) > 0 {
		keyInput.Description = aws.String(input.Description)
	}
	if len(input.Policy) > 0 {
		keyInput.Policy = aws.String(input.Policy)
	}
	if len(input.Tags) > 0 {
		for k, v := range input.Tags {
			keyInput.Tags = append(keyInput.Tags, &kms.Tag{TagKey: aws.String(k), TagValue: aws.String(v)})
		}
	}
	key, err := ca.Client.CreateKey(keyInput)
	if err != nil {
		return "", err
	}
	// Create the KMS alias
	_, err = ca.Client.CreateAlias(&kms.CreateAliasInput{
		TargetKeyId: key.KeyMetadata.KeyId,
		AliasName:   aws.String(input.AliasName),
	})
	if err != nil {
		return "", err
	}
	return aws.StringValue(key.KeyMetadata.KeyId), nil
}

// DeleteKey delete a KMS key alias and the underlying target KMS Key.
func (ca *KMSCA) DeleteKey(input *DeleteKeyInput) error {
	// Check if the key already exists
	response, err := ca.Client.DescribeKey(&kms.DescribeKeyInput{
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
		deleteInput.PendingWindowInDays = aws.Int64(int64(input.PendingWindowInDays))
	}

	_, err = ca.Client.ScheduleKeyDeletion(deleteInput)
	if err != nil {
		return err
	}
	// Delete the KMS alias
	_, err = ca.Client.DeleteAlias(&kms.DeleteAliasInput{
		AliasName: aws.String(input.AliasName),
	})
	if err != nil {
		return err
	}
	return nil
}

// GenerateCertificateAuthorityCertificate returns the signed Certificate Authority Certificate
func (ca *KMSCA) GenerateCertificateAuthorityCertificate(input *GenerateCertificateAuthorityCertificateInput) (*x509.Certificate, error) {
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(input.SerialNumber),
		Subject:               input.Subject,
		NotBefore:             input.NotBefore,
		NotAfter:              input.NotAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	newSigner, err := signer.New(ca.Client, input.KeyID)
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
func (ca *KMSCA) SignCertificate(input *IssueCertificateInput) (*x509.Certificate, error) {
	newSigner, err := signer.New(ca.Client, input.KeyID)
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
	// Serial Number is used to uniquely identify the certificate
	SerialNumber int64
	// Subject of the CA certifiacte
	Subject pkix.Name
	// NotBefore is the time at which the certificate validity starts
	NotBefore time.Time
	// NotAfter is the time at which the certificate validity ends
	NotAfter time.Time
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
