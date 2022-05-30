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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	"github.com/Skyscanner/kms-issuer/pkg/kmsca"
	mocks "github.com/Skyscanner/kms-issuer/pkg/kmsmock"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Context("KMSCA", func() {

	Describe("when calling CreateKey", func() {

		It("should create a new KMS key and a Key Alias", func() {
			client := mockKMSCA()
			KeyID, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{
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
			KeyID, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})
			Expect(err).To(BeNil())
			KeyID2, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})
			Expect(err).To(BeNil())
			Expect(KeyID).To(Equal(KeyID2))
		})
	})
	Describe("when calling DeleteKey", func() {

		It("should delete the KMS key and a Key Alias", func() {
			client := mockKMSCA()
			KeyID, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})
			Expect(err).To(BeNil())
			Expect(KeyID).NotTo(BeEmpty())

			err = client.DeleteKey(context.TODO(), &kmsca.DeleteKeyInput{
				AliasName: "alias/test-key",
			})
			Expect(err).To(BeNil())
			_, err = client.Client.DescribeKey(context.TODO(), &kms.DescribeKeyInput{
				KeyId: aws.String("alias/test-key"),
			})
			Expect(err).To(BeAssignableToTypeOf(&kmstypes.NotFoundException{}))
		})
	})

	Describe("when calling GenerateCertificateAuthorityCertificate", func() {

		It("should return a certificate with default values", func() {
			By("creating a managed key")
			client := mockKMSCA()

			By("calling GenerateCertificateAuthorityCertificate")
			input := &kmsca.GenerateCertificateAuthorityCertificateInput{
				KeyID: "Test ",
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				Duration: time.Hour,
			}
			cert := client.GenerateCertificateAuthorityCertificate(input)
			Expect(cert.SerialNumber).NotTo(BeNil())
			Expect(cert.Subject).To(Equal(input.Subject))
			Expect(cert.NotAfter.Sub(cert.NotBefore)).To(Equal(input.Duration))
			Expect(cert.IsCA).To(BeTrue())
			Expect(cert.ExtKeyUsage).To(Equal([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}))
			Expect(cert.KeyUsage).To(Equal(x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign))
			Expect(cert.BasicConstraintsValid).To(BeTrue())
		})

		It("should generate consistent certificates when using the Rounding factor", func() {
			By("creating a managed key")
			client := mockKMSCA()

			By("calling GenerateCertificateAuthorityCertificate")
			input := &kmsca.GenerateCertificateAuthorityCertificateInput{
				KeyID: "Test ",
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				Duration: time.Hour,
				Rounding: time.Hour * 24 * 365,
			}
			first := client.GenerateCertificateAuthorityCertificate(input)
			second := client.GenerateCertificateAuthorityCertificate(input)
			Expect(first).To(Equal(second))
		})
	})

	Describe("when calling GenerateAndSignCertificateAuthorityCertificate", func() {

		It("should return a valid ca cert", func() {
			By("creating a managed key")
			client := mockKMSCA()
			KeyID, _ := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})

			By("calling GenerateAndSignCertificateAuthorityCertificate")
			signed, err := client.GenerateAndSignCertificateAuthorityCertificate(
				context.TODO(),
				&kmsca.GenerateCertificateAuthorityCertificateInput{
					KeyID: KeyID,
					Subject: pkix.Name{
						CommonName: "Test CA",
					},
					Duration: time.Hour,
				},
			)
			Expect(signed).NotTo(BeNil())
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

	Describe("when calling SignCertificate", func() {

		It("should return a signed certificate", func() {
			By("creating a managed key")
			client := mockKMSCA()
			keyID, _ := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})

			By("calling GenerateAndSignCertificateAuthorityCertificate")
			parent, _ := client.GenerateAndSignCertificateAuthorityCertificate(
				context.TODO(),
				&kmsca.GenerateCertificateAuthorityCertificateInput{
					KeyID: keyID,
					Subject: pkix.Name{
						CommonName: "Test CA",
					},
					Duration: time.Hour,
				},
			)

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

			signed, err := client.SignCertificate(
				context.TODO(),
				&kmsca.IssueCertificateInput{
					KeyID:     keyID,
					Cert:      cert,
					Parent:    parent,
					PublicKey: certPrivKey.Public(),
				},
			)
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
