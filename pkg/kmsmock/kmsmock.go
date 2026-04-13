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

	"github.com/Skyscanner/kms-issuer/v4/pkg/interfaces"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"
)

var (
	publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwySom9ZEPwxZ0v020XI8
RDi9dzWtnIRzl4P4S2mHiap47CssQPxcxlUdsg+cnh+2XO1krhQlv3ww9E1OjvUa
/E/Otpus/DuDsap7KTwUEDZqK35NlZB/fpNlx9ck4KzoZl9Sc1CUw0MyVX3nm89b
EgP/6EAspj125ZaA7VIdxdA4SsTZCe1ijYVBs79vi1GWFz/U4uHP+e8dugGtxBCu
KED8cgHmj31sxJB2BZuuoOEsUxGR5w2MA2fCur3HPc8kcaXhFqcB76RwEMOCWHMW
8s0/gwFwaj2kncR4Msd6WLXDvemIz46TKCJI3LlSANsHhXfEILidgN9fLoecOQMP
1QIDAQAB
-----END PUBLIC KEY-----
`)
	privateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwySom9ZEPwxZ0v020XI8RDi9dzWtnIRzl4P4S2mHiap47Css
QPxcxlUdsg+cnh+2XO1krhQlv3ww9E1OjvUa/E/Otpus/DuDsap7KTwUEDZqK35N
lZB/fpNlx9ck4KzoZl9Sc1CUw0MyVX3nm89bEgP/6EAspj125ZaA7VIdxdA4SsTZ
Ce1ijYVBs79vi1GWFz/U4uHP+e8dugGtxBCuKED8cgHmj31sxJB2BZuuoOEsUxGR
5w2MA2fCur3HPc8kcaXhFqcB76RwEMOCWHMW8s0/gwFwaj2kncR4Msd6WLXDvemI
z46TKCJI3LlSANsHhXfEILidgN9fLoecOQMP1QIDAQABAoIBAAERkJKbF+N69vNs
6mLAAEdRsZ/IT6bSlbntu0L/7KhNDSpeUQWSjDYcsfpI3E0mXt+7Xczb58CL570w
nJXvZCzbK8IieJrzmK5XK4nJt9oTNazLmQz/+MltghttQ25aAWEPVd73r/tC41L9
wlRp4bnWtpoF+JvSggtBYRV2R6wocl239xvQhrxtOBtcuU5Cz3GR5xpNZSQ2KxuM
WSbZ7y6PP5bkcpFaxA7srVo7UAGYSQsGSDVyg0Js8yATbrDclhrEAXjR92RuA/5o
OYfzoIcgkO1mgdK3ZdBqnh4qzH/c16klv5Vay691JcNqToI8gWQZ1Sd1uMSeq6XB
SWA6xJECgYEA9w05r4Oe55oB5mQhWwN3js/AIw/9RWDorJed66uHoaT1tGCzeBWs
Btxc9QKtaPlNtHf+S8BFThicSodk4B1os+p4ryVmYvL/BoSqZPvhADJ1ND59mcT7
vwReO49J8fLjyjrycohrcYQO2t6m2gZRUbfpQxkSdLdEcO76hqyI6rECgYEAyjYd
U5nyEZpkOE/ed/qUD1qbSLlMQE/tHfwOZalKYizvwDvLSqdT6k6JsJuMLMcxtz1L
PwVlKxHp/8j/QwHEa5fBBDk/O6jKD3M8yg/uHEC1+T6R38h4Bzv0fyeuXyjQI5TE
m/bnOy/+ohqB8a06MNKwBtGxAXczYR9qUsCT+GUCgYEAw6QiiX6HCUups4SZ8ZRG
Sr70ng+cdyOuPnd25NmaeATFWwm1NiSbbXd22cQ8BURgJ8lahSyG9biBlHeyB9Ti
RJAq8DCC61sZYFURBxV8cgaDUFMobexTnEpeQXZQjZzWjSCvPMoRo/x7MxJdOY0F
OtyUicFCH1G+jlyB4sKhTpECgYA8+L41BBlCh4wqkqKhCLR2QLrL3duJFNCJlwP8
UWR1X9lW3HC67ONXpiDMWMqWgeWSu++hbA4KQ5eMId4eJT1Ft/diP6S6Z3Wt3PB6
eP0yFa0JH326vWa7v69EXAGu/c5svCHgaT1l0l30IQwHhFUkfZLIK5g0ue2LHn7f
vuOfJQKBgQCalMj/BczrsYXvwF8n+mSgSJ1Q3Dbz7OGtcPQjsmORXB6cVnPqSwlz
Oc8K7aRu5LzBTvVkXYVMhtOoQrBJwJAr9JpC0kU3QGsP8B/ImDgfqtx50cb2EJmi
Ce+P5wm/tp+Zl38cj6s1xlld+H9IfKrqcpdlQ4fJKzfrPWM7jgpcUw==
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
