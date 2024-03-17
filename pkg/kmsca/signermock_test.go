// Portions copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.package tpm
// from https://github.com/salrashid123/signer/blob/master/pem/pem.go
// derivative copyright Josh Perry 2023 under the same license
package kmsca_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
)

type MockSigner struct {
	KeyUri string
	Algo   x509.SignatureAlgorithm
	Key    *rsa.PrivateKey
	mu     sync.Mutex
}

func newMockSigner(ctx context.Context, keyUri string, algo x509.SignatureAlgorithm) (crypto.Signer, error) {
	if algo == x509.UnknownSignatureAlgorithm {
		algo = x509.SHA256WithRSAPSS
	}
	if (algo != x509.SHA256WithRSA) && (algo != x509.SHA256WithRSAPSS) {
		return nil, fmt.Errorf("signatureAlgorithm must be either x509.SHA256WithRSA or x509.SHA256WithRSAPSS")
	}
	if keyUri == "" {
		return nil, fmt.Errorf("KeyUri cannot be empty")
	}

	// Generate an RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key")
	}

	return &MockSigner{
		KeyUri: keyUri,
		Algo:   algo,
		Key:    key,
	}, nil
}

func (t *MockSigner) Public() crypto.PublicKey {
	return t.Key.Public()
}

func (t *MockSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("Sign: Digest length doesn't match passed crypto algorithm")
	}

	pss, ok := opts.(*rsa.PSSOptions)
	if ok {
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash {
			fmt.Println("PSS salt length will automatically get set to rsa.PSSSaltLengthEqualsHash ")
		}
	}

	var signature []byte
	var err error
	// RSA-PSS: https://github.com/golang/go/issues/32425

	if t.Algo == x509.SHA256WithRSAPSS {
		var ropts rsa.PSSOptions
		ropts.SaltLength = rsa.PSSSaltLengthEqualsHash

		signature, err = rsa.SignPSS(rand.Reader, t.Key, opts.HashFunc(), digest, &ropts)
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-PSS %v", err)
		}
	} else {
		signature, err = rsa.SignPKCS1v15(rand.Reader, t.Key, opts.HashFunc(), digest)
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-SignPKCS1v15 %v", err)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-PSS %v", err)
		}
	}
	return signature, nil
}
