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

	"github.com/Skyscanner/kms-issuer/v4/pkg/kmsca"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Context("KMSCA", func() {

	Describe("when calling GenerateCertificateAuthorityCertificate", func() {

		It("should return a certificate with default values", func() {
			client := mockKMSCA()

			By("calling GenerateCertificateAuthorityCertificate")
			input := &kmsca.GenerateCertificateAuthorityCertificateInput{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				Duration: time.Hour,
				KeyUri:   "abcd12345",
			}
			cert, err := client.GenerateCertificateAuthorityCertificate(context.TODO(), input)
			Expect(err).To(BeNil())
			Expect(cert.SerialNumber).NotTo(BeNil())
			Expect(cert.Subject).To(Equal(input.Subject))
			Expect(cert.NotAfter.Sub(cert.NotBefore)).To(Equal(input.Duration))
			Expect(cert.IsCA).To(BeTrue())
			Expect(cert.ExtKeyUsage).To(Equal([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}))
			Expect(cert.KeyUsage).To(Equal(x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign))
			Expect(cert.BasicConstraintsValid).To(BeTrue())
		})

		It("should generate consistent certificates when using the Rounding factor", func() {
			client := mockKMSCA()

			By("calling GenerateCertificateAuthorityCertificate")
			input := &kmsca.GenerateCertificateAuthorityCertificateInput{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				Duration: time.Hour,
				Rounding: time.Hour * 24 * 365,
				KeyUri:   "abcd12345",
			}
			first, err := client.GenerateCertificateAuthorityCertificate(context.TODO(), input)
			Expect(err).To(BeNil())
			second, err := client.GenerateCertificateAuthorityCertificate(context.TODO(), input)
			Expect(err).To(BeNil())
			Expect(first).To(Equal(second))
		})
	})

	Describe("when calling SelfSignCertificate", func() {

		It("should return a valid ca cert", func() {
			client := mockKMSCA()
			keyUri := "abcd12345"
			cacert, err := client.GenerateCertificateAuthorityCertificate(
				context.TODO(),
				&kmsca.GenerateCertificateAuthorityCertificateInput{
					Subject: pkix.Name{
						CommonName: "Test CA",
					},
					Duration: time.Hour,
					KeyUri:   keyUri,
				},
			)
			Expect(err).To(BeNil())

			By("calling SelfSignCertificate")
			signed, err := client.SelfSignCertificate(
				context.TODO(),
				&kmsca.SelfSignCertificateInput{
					Cert:   cacert,
					KeyUri: keyUri,
				},
			)
			Expect(err).To(BeNil())
			Expect(signed).NotTo(BeNil())

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
			client := mockKMSCA()
			keyUri := "abcd12345"
			cacert, err := client.GenerateCertificateAuthorityCertificate(
				context.TODO(),
				&kmsca.GenerateCertificateAuthorityCertificateInput{
					Subject: pkix.Name{
						CommonName: "Test CA",
					},
					Duration: time.Hour,
					KeyUri:   keyUri,
				},
			)
			Expect(err).To(BeNil())

			By("calling SelfSignCertificate")
			parent, err := client.SelfSignCertificate(
				context.TODO(),
				&kmsca.SelfSignCertificateInput{
					Cert:   cacert,
					KeyUri: keyUri,
				},
			)
			Expect(err).To(BeNil())

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
				IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
				NotBefore:          time.Now(),
				NotAfter:           time.Now().AddDate(10, 0, 0),
				SubjectKeyId:       []byte{1, 2, 3, 4, 6},
				ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				KeyUsage:           x509.KeyUsageDigitalSignature,
				SignatureAlgorithm: x509.SHA256WithRSAPSS,
			}
			certPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)

			By("signing the certificate")

			signed, err := client.SignCertificate(
				context.TODO(),
				&kmsca.IssueCertificateInput{
					KeyUri:    keyUri,
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

// mockKMSCA retruns a KMSCA client using a KMS mock factory.
func mockKMSCA() *kmsca.KMSCA {
	return kmsca.NewKMSCAWithFactory(newMockSigner)
}
