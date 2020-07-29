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

package kmsca_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	"github.com/Skyscanner/kms-issuer/pkg/kmsca"
	mocks "github.com/Skyscanner/kms-issuer/pkg/kmsmock"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/kms"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Context("KMSCA", func() {

	Describe("when calling CreateKey", func() {

		It("should create a new KMS key and a Key Alias", func() {
			client := mockKMSCA()
			KeyID, err := client.CreateKey(&kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
				Tags: map[string]string{
					"Project": "k8s",
					"foo":     "bar",
				},
				Description:           "My test key",
				CustomerMasterKeySpec: "RSA_2048",
				Policy:                "{}",
			})
			Expect(err).To(BeNil())
			Expect(KeyID).NotTo(BeEmpty())
		})

		It("should return existing key if one already exists", func() {
			client := mockKMSCA()
			KeyID, err := client.CreateKey(&kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})
			Expect(err).To(BeNil())
			KeyID2, err := client.CreateKey(&kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})
			Expect(err).To(BeNil())
			Expect(KeyID).To(Equal(KeyID2))
		})
	})
	Describe("when calling DeleteKey", func() {

		It("should delete the KMS key and a Key Alias", func() {
			client := mockKMSCA()
			KeyID, err := client.CreateKey(&kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})
			Expect(err).To(BeNil())
			Expect(KeyID).NotTo(BeEmpty())

			err = client.DeleteKey(&kmsca.DeleteKeyInput{
				AliasName: "alias/test-key",
			})
			Expect(err).To(BeNil())
			_, err = client.Client.DescribeKey(&kms.DescribeKeyInput{
				KeyId: aws.String("alias/test-key"),
			})
			Expect(err.(awserr.Error).Code()).To(Equal(kms.ErrCodeNotFoundException))
		})
	})

	Describe("when calling GenerateCertificateAuthorityCertificate", func() {

		It("should return a valid ca cert", func() {
			By("creating a managed key")
			client := mockKMSCA()
			KeyID, _ := client.CreateKey(&kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})

			By("calling GenerateCertificateAuthorityCertificate")
			signed, err := client.GenerateCertificateAuthorityCertificate(&kmsca.GenerateCertificateAuthorityCertificateInput{
				KeyID: KeyID,
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().AddDate(10, 0, 0),
			})

			Expect(signed).NotTo(BeNil())
			Expect(err).To(BeNil())
		})

	})

	Describe("when calling SignCertificate", func() {

		It("should return a signed certificate", func() {
			By("creating a managed key")
			client := mockKMSCA()
			keyID, _ := client.CreateKey(&kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})

			By("calling GenerateCertificateAuthorityCertificate")
			parent, _ := client.GenerateCertificateAuthorityCertificate(&kmsca.GenerateCertificateAuthorityCertificateInput{
				KeyID: keyID,
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().AddDate(10, 0, 0),
			})

			By("creating a certificate")
			cert := &x509.Certificate{
				SerialNumber: big.NewInt(1658),
				Subject: pkix.Name{
					Organization:  []string{"Company, INC."},
					Country:       []string{"US"},
					Province:      []string{""},
					Locality:      []string{"San Francisco"},
					StreetAddress: []string{"Golden Gate Bridge"},
					PostalCode:    []string{"94016"},
				},
				IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
				NotBefore:    time.Now(),
				NotAfter:     time.Now().AddDate(10, 0, 0),
				SubjectKeyId: []byte{1, 2, 3, 4, 6},
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				KeyUsage:     x509.KeyUsageDigitalSignature,
			}
			certPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)

			By("signing the certificate")

			signed, err := client.SignCertificate(&kmsca.IssueCertificateInput{
				KeyID:     keyID,
				Cert:      cert,
				Parent:    parent,
				PublicKey: certPrivKey.Public(),
			})
			Expect(err).To(BeNil())
			Expect(signed).NotTo(BeNil())

			By("verifying the signature is valid")
			roots := x509.NewCertPool()
			roots.AddCert(parent)
			_, err = signed.Verify(x509.VerifyOptions{
				Roots: roots,
			})
			Expect(err).To(BeNil())
		})

	})
})

// mockKMSCA retruns a KMSCA client with a mock of KMS backend.
func mockKMSCA() *kmsca.KMSCA {
	return &kmsca.KMSCA{
		Client: mocks.New(),
	}
}
