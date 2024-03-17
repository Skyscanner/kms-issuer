package signer_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/Skyscanner/kms-issuer/v4/pkg/interfaces"
	"github.com/Skyscanner/kms-issuer/v4/pkg/signer"
	"github.com/googleapis/gax-go/v2"
)

type mockKmsClient struct {
	Key *rsa.PrivateKey
}

func (c *mockKmsClient) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	var ropts rsa.PSSOptions
	ropts.SaltLength = rsa.PSSSaltLengthEqualsHash

	signature, err := rsa.SignPSS(rand.Reader, c.Key, crypto.SHA256, req.Digest.GetSha256(), &ropts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign RSA-PSS %v", err)
	}
	return &kmspb.AsymmetricSignResponse{
		Signature: signature,
	}, nil
}

func (c *mockKmsClient) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error) {
	return &kmspb.CryptoKey{
		Primary: &kmspb.CryptoKeyVersion{
			Name: fmt.Sprintf("%s/cryptoKeyVersion/1", req.Name),
		},
	}, nil
}

func (c *mockKmsClient) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	pubkey := c.Key.Public()
	pubkeyByte, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		panic("couldn't marshal pub key")
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubkeyByte,
	}
	pemByte := pem.EncodeToMemory(block)
	return &kmspb.PublicKey{
		Pem: string(pemByte),
	}, nil
}

func (c *mockKmsClient) Close() error {
	return nil
}

func mockkmsfactoryfactory(key *rsa.PrivateKey) func(context.Context) (interfaces.KMSClient, error) {
	return func(ctx context.Context) (interfaces.KMSClient, error) {
		return &mockKmsClient{
			Key: key,
		}, nil
	}
}

// mockKMSCA retruns a KMSCA client using a KMS mock factory.
func newMockSigner(keyUri string) crypto.Signer {
	// Generate an RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate RSA key")
	}

	s, _ := signer.NewKMSCryptoWithFactory(context.TODO(), keyUri, x509.SHA256WithRSAPSS, mockkmsfactoryfactory(key))
	return s
}
