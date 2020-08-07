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

package signer_test

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"

	mocks "github.com/Skyscanner/kms-issuer/pkg/kmsmock"
	"github.com/Skyscanner/kms-issuer/pkg/signer"
	"github.com/aws/aws-sdk-go/service/kms"

	"math/big"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Context("Signer", func() {

	Describe("Given a cert and valid KMS key", func() {

		It("should sign the certificate using KMS key", func() {
			cert := &x509.Certificate{
				SerialNumber: big.NewInt(2020),
				Subject: pkix.Name{
					CommonName: "Root CA",
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().AddDate(10, 0, 0),
				IsCA:                  true,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
				BasicConstraintsValid: true,
			}
			By("creating a KMS key")
			client := mocks.New()
			key, err := client.CreateKey(&kms.CreateKeyInput{})
			Expect(err).To(BeNil())

			By("creating a new KMSSigner")
			signer, err := signer.New(client, *key.KeyMetadata.KeyId)
			Expect(signer).NotTo(BeNil())
			Expect(err).To(BeNil())

			By("extracting the public key")
			pub := signer.Public()
			Expect(pub).NotTo(BeNil())

			By("signing the certificate")
			signedBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, signer)
			Expect(err).To(BeNil())
			signed, err := x509.ParseCertificate(signedBytes)
			Expect(err).To(BeNil())

			By("verifying the signature is valid")
			roots := x509.NewCertPool()
			roots.AddCert(signed)
			_, err = signed.Verify(x509.VerifyOptions{
				Roots: roots,
			})
			Expect(err).To(BeNil())
		})
	})

	Describe("Given an invalid KMS key ID", func() {
		It("should fail", func() {
			client := mocks.New()
			By("erroring out")
			signer, err := signer.New(client, "invalid key ID")
			Expect(signer).To(BeNil())
			Expect(err).NotTo(BeNil())
		})
	})
})
