// Portions Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file
// at: https://github.com/salrashid123/signer/blob/master/kms/kms.go
// Derivative Copyright 2023 Josh Perry under the same license

package signer

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"sync"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/Skyscanner/kms-issuer/v4/pkg/interfaces"
)

var (
	refreshMutex    = &sync.Mutex{}
	x509Certificate x509.Certificate
	publicKey       crypto.PublicKey
)

type ClientFactory func(context.Context) (interfaces.KMSClient, error)

type KMS struct {
	crypto.Signer // https://golang.org/pkg/crypto/#Signer

	PublicKeyFile string

	KeyUri             string
	SignatureAlgorithm x509.SignatureAlgorithm

	primaryVersionUri string
	// A factory function, mainly useful for testing
	clientFactory ClientFactory
}

// Default client factory uses cloud KMS
func newCloudKmsClient(ctx context.Context) (interfaces.KMSClient, error) {
	return cloudkms.NewKeyManagementClient(ctx)
}

// /
// Given the URI to a GCP KMS CryptoKey, validates and creates a KMS signer
// using the currently primary version of the key.
//
// The signature algorithm must be either x509.SHA256WithRSA or x509.SHA256WithRSAPSS
func NewKMSCrypto(ctx context.Context, keyUri string, algo x509.SignatureAlgorithm) (crypto.Signer, error) {
	return NewKMSCryptoWithFactory(ctx, keyUri, algo, newCloudKmsClient)
}

// Creates a new KMS signer using a given client factory, mainly useful when testing to mock out the kms interface
func NewKMSCryptoWithFactory(ctx context.Context, keyUri string, algo x509.SignatureAlgorithm, factory ClientFactory) (crypto.Signer, error) {
	// Validate inputs
	if algo == x509.UnknownSignatureAlgorithm {
		algo = x509.SHA256WithRSA
	}
	if (algo != x509.SHA256WithRSA) && (algo != x509.SHA256WithRSAPSS) {
		return nil, fmt.Errorf("signatureAlgorithm must be either x509.SHA256WithRSA or x509.SHA256WithRSAPSS")
	}

	if keyUri == "" {
		return nil, fmt.Errorf("KeyUri cannot be empty")
	}

	// Get the current primary key version
	kmsClient, err := factory(ctx)
	if err != nil {
		fmt.Printf("Error getting kms client %v", err)
		return nil, err
	}
	defer kmsClient.Close()

	key, err := kmsClient.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: keyUri})
	if err != nil {
		fmt.Printf("Error getting key %v", err)
		return nil, err
	}

	// Create the KMS instance
	kms := &KMS{
		KeyUri:             keyUri,
		SignatureAlgorithm: algo,
		primaryVersionUri:  key.Primary.Name,
		clientFactory:      factory,
	}

	// Preload the public key
	publicKey, err = kms.getPublicKey(ctx, kmsClient)
	if err != nil {
		fmt.Printf("Error getting kms public key %v", err)
		return nil, err
	}

	// Give the enriched instance to the caller
	return kms, nil
}

func (t KMS) getPublicKey(ctx context.Context, kmsClient interfaces.KMSClient) (crypto.PublicKey, error) {
	dresp, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: t.primaryVersionUri})
	if err != nil {
		fmt.Printf("Error getting GetPublicKey %v", err)
		return nil, err
	}
	pubKeyBlock, _ := pem.Decode([]byte(dresp.Pem))

	pub, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		fmt.Printf("Error parsing PublicKey %v", err)
		return nil, err
	}

	return pub.(*rsa.PublicKey), nil
}

// /
// crypto.Signer.Public impl Gets the public key from the KMS w/memoization
func (t KMS) Public() crypto.PublicKey {
	ctx := context.Background()
	if publicKey == nil {
		kmsClient, err := t.clientFactory(ctx)
		if err != nil {
			fmt.Printf("Error getting kms client %v", err)
			return nil
		}
		defer kmsClient.Close()

		publicKey, err = t.getPublicKey(ctx, kmsClient)
		if err != nil {
			fmt.Printf("Error getting kms public key %v", err)
			return nil
		}
	}

	return publicKey
}

// /
// crypto.Signer.Sign impl signing a digest using the KMS private key
func (t KMS) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("Sign: Digest length doesn't match passed crypto algorithm")
	}

	refreshMutex.Lock()
	defer refreshMutex.Unlock()

	ctx := context.Background()

	kmsClient, err := t.clientFactory(ctx)
	if err != nil {
		fmt.Printf("Error getting kms client %v", err)
		return nil, err
	}
	defer kmsClient.Close()

	pss, ok := opts.(*rsa.PSSOptions)
	if ok {
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash {
			fmt.Println("PSS salt length will automatically get set to rsa.PSSSaltLengthEqualsHash ")
		}
	}
	req := &kmspb.AsymmetricSignRequest{
		Name: t.primaryVersionUri,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		},
	}
	dresp, err := kmsClient.AsymmetricSign(ctx, req)
	if err != nil {
		fmt.Printf("Error signing with kms client %v", err)
		return nil, err
	}
	return dresp.Signature, nil
}
