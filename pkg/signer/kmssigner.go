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
	"crypto"
	"crypto/x509"
	"io"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

// KMSSigner implements the crypto/Signer interface that can be used for signing operations
// using an AWS KMS key. see https://golang.org/pkg/crypto/#Signer
type KMSSigner struct {
	//client is and instance of the aws kms client
	client kmsiface.KMSAPI
	// keyId is the KMS Key Id used for signing
	keyId string
}

// New returns a KMSSigner instance given and AWS client and a KMS key used for signing.
// TODO: explain what are the pre-requisits for the KMS key.
func New(client kmsiface.KMSAPI, keyId string) *KMSSigner {
	return &KMSSigner{
		client: client,
		keyId:  keyId,
	}
}

// Public returns the public key corresponding to the opaque, private key.
// TODO: Do we really need this method? Error handling is inhexistant. Maybe another function?
func (s *KMSSigner) Public() crypto.PublicKey {
	response, err := s.client.GetPublicKey(&kms.GetPublicKeyInput{
		KeyId: &s.keyId,
	})
	if err != nil {
		return nil
	}
	key, err := x509.ParsePKIXPublicKey(response.PublicKey)
	if err != nil {
		return nil
	}
	return key
}

// Sign signs digest with the KMS key.
// TODO: currently use SigningAlgorithmSpecRsassaPkcs1V15Sha256. Is that ok?
// TODO: should use the opts provided.
func (s *KMSSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	resp, err := s.client.Sign(&kms.SignInput{
		KeyId:            &s.keyId,
		Message:          digest,
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: aws.String(kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256),
	})
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}
