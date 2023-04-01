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

package kmsmock

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/Skyscanner/kms-issuer/pkg/interfaces"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"
)

var (
	publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALqbHeRLCyOdykC5SDLqI49ArYGYG1mq
aH9/GnWjGavZM02fos4lc2w6tCchcUBNtJvGqKwhC5JEnx3RYoSX2ucCAwEAAQ==
-----END PUBLIC KEY-----
`)
	privateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIBPQIBAAJBALqbHeRLCyOdykC5SDLqI49ArYGYG1mqaH9/GnWjGavZM02fos4l
c2w6tCchcUBNtJvGqKwhC5JEnx3RYoSX2ucCAwEAAQJBAKn6O+tFFDt4MtBsNcDz
GDsYDjQbCubNW+yvKbn4PJ0UZoEebwmvH1ouKaUuacJcsiQkKzTHleu4krYGUGO1
mEECIQD0dUhj71vb1rN1pmTOhQOGB9GN1mygcxaIFOWW8znLRwIhAMNqlfLijUs6
rY+h1pJa/3Fh1HTSOCCCCWA0NRFnMANhAiEAwddKGqxPO6goz26s2rHQlHQYr47K
vgPkZu2jDCo7trsCIQC/PSfRsnSkEqCX18GtKPCjfSH10WSsK5YRWAY3KcyLAQIh
AL70wdUu5jMm2ex5cZGkZLRB50yE6rBiHCd5W1WdTFoe
-----END RSA PRIVATE KEY-----
`)
)

// KMSMock Define a simple mock of the KMS client
type KMSMock struct {
	keys  map[string]*kms.CreateKeyInput
	alias map[string]string
}

// Ensure KMSMock implements interface
var _ interfaces.KMSClient = &KMSMock{}

// New creates a new KMSMock instance
func New() *KMSMock {
	return &KMSMock{
		keys:  map[string]*kms.CreateKeyInput{},
		alias: map[string]string{},
	}
}

// CreateKey mocks of the KMS CreateKey method.
// Returns a valid CreateKeyOutput response
func (m *KMSMock) CreateKey(_ context.Context, input *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	uid := uuid.New().String()
	m.keys[uid] = input
	return &kms.CreateKeyOutput{
		KeyMetadata: &kmstypes.KeyMetadata{
			KeyId: aws.String(uid),
		},
	}, nil
}

// CreateAlias mocks of the KMS CreateAlias method.
// Returns a valid CreateAliasOutput response
func (m *KMSMock) CreateAlias(_ context.Context, input *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	m.alias[aws.ToString(input.AliasName)] = aws.ToString(input.TargetKeyId)
	return &kms.CreateAliasOutput{}, nil
}

// DeleteAlias mocks of the KMS DeleteAlias method.
// Returns a valid DeleteAliasOutput response
func (m *KMSMock) DeleteAlias(_ context.Context, input *kms.DeleteAliasInput, _ ...func(*kms.Options)) (*kms.DeleteAliasOutput, error) {
	delete(m.alias, aws.ToString(input.AliasName))
	return &kms.DeleteAliasOutput{}, nil
}

// DescribeKey mocks of the KMS DescribeKey method.
// Returns a valid DescribeKeyOutput response
func (m *KMSMock) DescribeKey(_ context.Context, input *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	keyID := aws.ToString(input.KeyId)
	// fetch key id from alias
	if strings.HasPrefix(keyID, "alias/") {
		keyID = m.alias[keyID]
		if keyID == "" {
			return nil, &kmstypes.NotFoundException{}
		}
	}
	return &kms.DescribeKeyOutput{
		KeyMetadata: &kmstypes.KeyMetadata{
			KeyId: aws.String(keyID),
		},
	}, nil
}

// ListResourceTags mocks of the KMS ListResourceTags method.
func (m *KMSMock) ListResourceTags(_ context.Context, input *kms.ListResourceTagsInput, _ ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	if key, ok := m.keys[aws.ToString(input.KeyId)]; ok {
		return &kms.ListResourceTagsOutput{
			Tags: key.Tags,
		}, nil
	}
	return nil, &kmstypes.NotFoundException{}
}

// ScheduleKeyDeletion mocks of the KMS ScheduleKeyDeletion method.
func (m *KMSMock) ScheduleKeyDeletion(_ context.Context, input *kms.ScheduleKeyDeletionInput, _ ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	if _, ok := m.keys[aws.ToString(input.KeyId)]; ok {
		return &kms.ScheduleKeyDeletionOutput{}, nil
	}
	return nil, &kmstypes.NotFoundException{}
}

// GetPublicKey mocks of the KMS GetPublicKey method.
func (m *KMSMock) GetPublicKey(_ context.Context, input *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if key, ok := m.keys[aws.ToString(input.KeyId)]; ok {
		block, _ := pem.Decode(publicKey)
		return &kms.GetPublicKeyOutput{
			CustomerMasterKeySpec: kmstypes.CustomerMasterKeySpec(key.KeySpec),
			KeySpec:               key.KeySpec,
			KeyUsage:              key.KeyUsage,
			PublicKey:             block.Bytes,
		}, nil
	}
	return nil, &kmstypes.NotFoundException{}
}

// Sign mocks of the KMS Sign method.
func (m *KMSMock) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if _, ok := m.keys[aws.ToString(input.KeyId)]; ok {
		block, _ := pem.Decode(privateKey)
		signer, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
		signature, _ := rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, input.Message)
		return &kms.SignOutput{
			Signature: signature,
		}, nil
	}
	return nil, &kmstypes.NotFoundException{}
}
