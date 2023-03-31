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

package certmanager

import (
	"context"
	"time"

	kmsiapi "github.com/Skyscanner/kms-issuer/v4/apis/certmanager/v1alpha1"

	"github.com/Skyscanner/kms-issuer/v4/pkg/kmsca"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func WaitIssuerReady(key client.ObjectKey) *kmsiapi.KMSIssuer {
	issuer := &kmsiapi.KMSIssuer{}
	Eventually(
		func() bool {
			Expect(k8sClient.Get(context.Background(), key, issuer)).Should(Succeed(), "failed to get KMSIssuer resource")
			return issuer.Status.IsReady()
		},
		time.Second*1, time.Millisecond*100,
	).Should(BeTrue(), "issuer should be ready")
	return issuer
}

var _ = Context("KMSIssuer", func() {

	Describe("when a new resources is created", func() {
		It("should sign the intermediate certificate", func() {
			By("Creating a KMS Key")
			keyID, err := ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})
			Expect(err).To(BeNil())

			By("Creating a KMSIssuer object with an empty KeyId")
			key := client.ObjectKey{
				Name:      "key",
				Namespace: "default",
			}
			issuer := &kmsiapi.KMSIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: kmsiapi.KMSIssuerSpec{
					KeyID:      keyID,
					CommonName: "RootCA",
				},
			}
			Expect(k8sClient.Create(context.Background(), issuer)).Should(Succeed(), "failed to create test KMSIssuer resource")

			By("Waiting for the Issuer certificate to be issued")
			issuer = WaitIssuerReady(key)

			By("Getting the Public Cert")
			Expect(len(issuer.Status.Certificate)).NotTo(BeNil())

			cert, err := ParseCertificate(issuer.Status.Certificate)
			Expect(err).To(BeNil())
			Expect(cert.NotAfter.Sub(cert.NotBefore)).To(Equal(defaultCertDuration))
		})

		It("should renew the certificate ", func() {
			By("Creating a KMS Key")
			keyID, err := ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{
				AliasName: "alias/test-key",
			})
			Expect(err).To(BeNil())

			By("Creating a KMSIssuer object with an empty KeyId")
			key := client.ObjectKey{
				Name:      "key-to-renew",
				Namespace: "default",
			}
			issuer := &kmsiapi.KMSIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: kmsiapi.KMSIssuerSpec{
					KeyID:      keyID,
					CommonName: "RootCA",
					Duration: &metav1.Duration{
						Duration: time.Second,
					},
				},
			}
			Expect(k8sClient.Create(context.Background(), issuer)).Should(Succeed(), "failed to create test KMSIssuer resource")

			By("Waiting for the Issuer certificate to be issued")
			issuer = WaitIssuerReady(key)
			cert, err := ParseCertificate(issuer.Status.Certificate)
			serialNumber := cert.SerialNumber
			Expect(err).To(BeNil())
			Expect(serialNumber).NotTo(BeNil())

			By("Waiting for the Issuer certificate to be renew")
			Eventually(
				func() bool {
					Expect(k8sClient.Get(context.Background(), key, issuer)).Should(Succeed(), "failed to get KMSIssuer resource")
					cert, _ := ParseCertificate(issuer.Status.Certificate)
					return cert.SerialNumber != serialNumber
				},
				time.Second*2, time.Millisecond*100,
			).Should(BeTrue(), "issuer should be renewed")
		})
	})
})
