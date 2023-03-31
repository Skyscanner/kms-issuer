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

package signer

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"

	"github.com/Skyscanner/kms-issuer/v4/pkg/interfaces"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSSigner implements the crypto/Signer interface that can be used for signing operations
// using an AWS KMS key. see https://golang.org/pkg/crypto/#Signer
type KMSSigner struct {
	// client is and instance of the aws kms client
	client interfaces.KMSClient
	// keyID is the KMS Key Id used for signing
	keyID string
	// public key
	publicKey crypto.PublicKey
}

// New returns a KMSSigner instance given and AWS client and a KMS key used for signing.
// TODO: explain what are the pre-requisits for the KMS key.
// TODO: implement PublicKey caching with periodical refresh
func New(ctx context.Context, client interfaces.KMSClient, keyID string) (*KMSSigner, error) {
	response, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(response.PublicKey)
	if err != nil {
		return nil, err
	}
	return &KMSSigner{
		client:    client,
		keyID:     keyID,
		publicKey: key,
	}, nil
}

// Public returns the public key corresponding to the opaque, private key.
func (s *KMSSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the KMS key.
// TODO: currently use SigningAlgorithmSpecRsassaPkcs1V15Sha256. Is that ok?
// TODO: should use the opts provided.
func (s *KMSSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	resp, err := s.client.Sign(context.TODO(), &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}
