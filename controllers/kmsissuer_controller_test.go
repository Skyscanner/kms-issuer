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
	"time"

	kmsiapi "github.com/Skyscanner/kms-issuer/api/v1alpha1"

	"github.com/Skyscanner/kms-issuer/pkg/kmsca"
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
			keyID, err := ca.CreateKey(&kmsca.CreateKeyInput{
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
					KeyID:        keyID,
					CommonName:   "RootCA",
					SerialNumber: int64(1234),
					NotBefore:    metav1.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
					NotAfter:     metav1.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
				},
			}
			Expect(k8sClient.Create(context.Background(), issuer)).Should(Succeed(), "failed to create test KMSIssuer resource")

			By("Waiting for the Issuer certificate to be issued")
			issuer = WaitIssuerReady(key)

			By("Getting the Public Cert")
			Expect(len(issuer.Status.Certificate)).NotTo(BeNil())

		})
	})
})
