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
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"crypto/sha1" //nolint:gosec // Used for consistent hash
	"math/big"

	"github.com/Skyscanner/kms-issuer/v4/pkg/signer"
)

const (
	// DefaultCertDuration is the default CA certificate validity duration
	DefaultCertDuration = time.Hour * 24 * 365 * 3 // 3 year
	// DefaultCertRenewalRatio is default ratio of time before the certificate
	// is expected to be renewed
	DefaultCertRenewalRatio = 2.0 / 3
)

// A factory that creates a signer given a keyUri and signing algo
// Mainly useful for testing, defaults to signer.NewKMSCrypto
type SignerFactory func(context.Context, string, x509.SignatureAlgorithm) (crypto.Signer, error)

// KMSCA KMS Certificate Authority provides the API operation methods for implementation
// a certificate authority on top of AWS KMS.
type KMSCA struct {
	sync.RWMutex
	signerCache   map[string]crypto.Signer
	signerFactory SignerFactory
}

// NewKMSCA creates a new instance of the KMSCA client with a session
// only supports ambient auth methods.
func NewKMSCA() *KMSCA {
	return NewKMSCAWithFactory(signer.NewKMSCrypto)
}

func NewKMSCAWithFactory(factory SignerFactory) *KMSCA {
	return &KMSCA{
		signerFactory: factory,
		signerCache:   make(map[string]crypto.Signer),
	}
}

// Basically a pull-through cache for kms key metadata
func (ca *KMSCA) getSigner(ctx context.Context, keyUri string) (crypto.Signer, error) {
	ca.Lock()
	defer ca.Unlock()

	_, ok := ca.signerCache[keyUri]
	if !ok {
		kmssigner, err := ca.signerFactory(ctx, keyUri, x509.SHA256WithRSAPSS)
		if err != nil {
			return nil, err
		}
		ca.signerCache[keyUri] = kmssigner
	}

	return ca.signerCache[keyUri], nil
}

// Creates a certificate intended for use as a CA
func (ca *KMSCA) GenerateCertificateAuthorityCertificate(ctx context.Context, input *GenerateCertificateAuthorityCertificateInput) (*x509.Certificate, error) {
	// Get the signer's public key
	kmssigner, err := ca.getSigner(ctx, input.KeyUri)
	if err != nil {
		return nil, err
	}
	pub := kmssigner.Public()
	if pub == nil {
		return nil, errors.New("could not retrieve the public key associated with the KMS private key")
	}

	// Convert the public key to a pem string
	pubkeyByte, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.New("could not marshal the signer's public key")
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubkeyByte,
	}
	pemByte := pem.EncodeToMemory(block)
	pubstring := string(pemByte)

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
		SignatureAlgorithm:    x509.SHA256WithRSAPSS,
	}
	// Compute the serial number
	serialNumberKey := fmt.Sprintf("%s %s %v", input, pubstring, cert)
	sha := sha1.Sum([]byte(serialNumberKey)) //nolint:gosec // Used for consistent hash
	cert.SerialNumber = new(big.Int).SetBytes(sha[:])

	return cert, nil
}

// Self-signs a cert, usually a root CA cert
func (ca *KMSCA) SelfSignCertificate(ctx context.Context, input *SelfSignCertificateInput) (*x509.Certificate, error) {
	kmssigner, err := ca.getSigner(ctx, input.KeyUri)
	if err != nil {
		return nil, err
	}
	pub := kmssigner.Public()
	if pub == nil {
		return nil, errors.New("could not retrieve the public key associated with the KMS private key")
	}
	signedBytes, err := x509.CreateCertificate(rand.Reader, input.Cert, input.Cert, pub, kmssigner)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(signedBytes)
}

// Signs a certificate request with a parent cert held in KMS
func (ca *KMSCA) SignCertificate(ctx context.Context, input *IssueCertificateInput) (*x509.Certificate, error) {
	kmssigner, err := ca.getSigner(ctx, input.KeyUri)
	if err != nil {
		return nil, err
	}
	signedBytes, err := x509.CreateCertificate(rand.Reader, input.Cert, input.Parent, input.PublicKey, kmssigner)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(signedBytes)
}

type GenerateCertificateAuthorityCertificateInput struct {
	// Subject of the CA certificate
	Subject pkix.Name
	// Duration is certificate validity duration
	Duration time.Duration
	// Rounding is used to round down the certificate NotBefore time.
	// For example, by setting the rounding period to 1h, all the certificates generated between the start
	// and in the end of an hour will be identical
	Rounding time.Duration
	// the URI for the signing key in the GCP KMS API
	KeyUri string
}

type SelfSignCertificateInput struct {
	Cert   *x509.Certificate
	KeyUri string
}

type IssueCertificateInput struct {
	// the URI for the key in the GCP KMS API
	KeyUri string
	// CSR Certificate Request
	Cert *x509.Certificate
	// PublicKey
	PublicKey crypto.PublicKey
	// Parent Signing Certificate
	Parent *x509.Certificate
	// Public
}
