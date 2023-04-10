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
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func WaitForKMSKeyReady(key client.ObjectKey) *kmsiapi.KMSKey {
	kmsKey := &kmsiapi.KMSKey{}
	Eventually(
		func() bool {
			Expect(k8sClient.Get(context.Background(), key, kmsKey)).Should(Succeed(), "failed to get KMSKey resource")
			return kmsKey.Status.IsReady()
		},
		time.Second*1, time.Millisecond*100,
	).Should(BeTrue(), "kmsKey should be ready")
	return kmsKey
}

func WaitForKMSKeyDeleted(key client.ObjectKey) {
	kmsKey := &kmsiapi.KMSKey{}
	Eventually(
		func() bool {
			err := k8sClient.Get(context.Background(), key, kmsKey)
			return err != nil
		},
		time.Second*1, time.Millisecond*100,
	).Should(BeTrue(), "kmsKey not deleted")
}

var _ = Context("KMSKey", func() {

	Describe("when a new resources is created", func() {
		It("should create a kms key", func() {
			By("Creating a KMSKey object")
			key := client.ObjectKey{
				Name:      "key",
				Namespace: "default",
			}
			kmsKey := &kmsiapi.KMSKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: kmsiapi.KMSKeySpec{
					AliasName:             "alias/kms-issuer-test-key",
					Description:           "test key for the kms issuer",
					CustomerMasterKeySpec: "RSA_2048",
					Policy:                "",
					Tags: map[string]string{
						"Project": "kms-issuer",
					},
					DeletionPolicy: "Retain",
				},
			}
			Expect(k8sClient.Create(context.Background(), kmsKey)).Should(Succeed(), "failed to create test KMSKey resource")

			By("Waiting for the kms key to be issued")
			kmsKey = WaitForKMSKeyReady(key)

			By("Checking the finalizer has been set")
			Expect(NeedToAddFinalizer(kmsKey)).To(BeFalse())
			By("Checking the Status.KeyId has been set")
			Expect(kmsKey.Status.KeyID).NotTo(BeEmpty())
		})
	})

	Describe("when a new resources is deleted", func() {
		It("should delete the kms key and alias", func() {
			By("Creating a KMSKey object")
			key := client.ObjectKey{
				Name:      "key-to-delete",
				Namespace: "default",
			}
			kmsKey := &kmsiapi.KMSKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: kmsiapi.KMSKeySpec{
					AliasName:      "alias/kms-issuer-test-key",
					DeletionPolicy: "Delete",
				},
			}
			Expect(k8sClient.Create(context.Background(), kmsKey)).Should(Succeed(), "failed to create test KMSKey resource")

			By("Waiting for the kms key to be issued")
			kmsKey = WaitForKMSKeyReady(key)

			By("deleting the object")
			Expect(k8sClient.Delete(context.Background(), kmsKey)).Should(Succeed(), "failed to delete test KMSKey resource")
			WaitForKMSKeyDeleted(key)
			By("Checking the key and alias has been removed")
			_, err := ca.Client.DescribeKey(context.TODO(), &kms.DescribeKeyInput{
				KeyId: aws.String(kmsKey.Spec.AliasName),
			})
			Expect(err).To(BeAssignableToTypeOf(&kmstypes.NotFoundException{}))
		})
	})
})
