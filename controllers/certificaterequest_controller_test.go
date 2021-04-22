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

package controllers

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	kmsiapi "github.com/Skyscanner/kms-issuer/api/v1alpha1"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

	"github.com/Skyscanner/kms-issuer/pkg/kmsca"
	"github.com/jetstack/cert-manager/test/e2e/util"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Context("CertificateRequestReconciler", func() {
	Describe("when a new CertificateRequest is created", func() {
		It("should sign the certificate request", func() {
			By("Creating a KMSIssuer")
			keyID, err := ca.CreateKey(&kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})
			Expect(err).To(BeNil())
			issuerKey := client.ObjectKey{
				Name:      "test-kms-issuer",
				Namespace: "default",
			}
			issuer := &kmsiapi.KMSIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      issuerKey.Name,
					Namespace: issuerKey.Namespace,
				},
				Spec: kmsiapi.KMSIssuerSpec{
					KeyID:      keyID,
					CommonName: "RootCA",
					Duration:   &metav1.Duration{},
				},
			}
			Expect(k8sClient.Create(context.Background(), issuer)).Should(Succeed(), "failed to create test KMSIssuer resource")
			Eventually(
				func() bool {
					issuer := &kmsiapi.KMSIssuer{}
					Expect(k8sClient.Get(context.Background(), issuerKey, issuer)).Should(Succeed(), "failed to get KMSIssuer resource")
					return len(issuer.Status.Certificate) > 0
				},
				time.Second*1, time.Millisecond*100,
			).Should(BeTrue(), "Certificate should be set")

			By("Creating a Certificate Request to be signed by the KMS Issuer")
			crKey := client.ObjectKey{
				Name:      "test-kms-issuer",
				Namespace: "default",
			}
			exampleDNSNames := []string{"dnsName1.co", "dnsName2.ninja"}
			exampleIPAddresses := []net.IP{
				[]byte{8, 8, 8, 8},
				[]byte{1, 1, 1, 1},
			}
			exampleURIs := []string{"spiffe://foo.foo.example.net", "spiffe://foo.bar.example.net"}
			cr, _, err := util.NewCertManagerBasicCertificateRequest( //nolint:staticcheck // TODO: fixed when refactored
				crKey.Name, issuerKey.Name, "KMSIssuer",
				&metav1.Duration{
					Duration: time.Hour * 24 * 90,
				},
				exampleDNSNames, exampleIPAddresses, exampleURIs, x509.RSA,
			)
			cr.ObjectMeta.Namespace = crKey.Namespace
			cr.Spec.IssuerRef.Group = kmsiapi.GroupVersion.Group
			Expect(err).To(BeNil())
			Expect(k8sClient.Create(context.Background(), cr)).Should(Succeed(), "failed to create test CertificateRequest resource")

			By("Checking the certificate is signed by the KMS issuer")
			Eventually(
				func() bool {
					cr := &cmapi.CertificateRequest{}
					Expect(k8sClient.Get(context.Background(), crKey, cr)).Should(Succeed(), "failed to get CertificateRequest resource")
					return len(cr.Status.Certificate) > 0
				},
				time.Second*1, time.Millisecond*100,
			).Should(BeTrue(), "status.Certificate field should be set")
		})
	})
})
