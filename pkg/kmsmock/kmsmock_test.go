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

package kmsmock_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"

	"crypto/sha256"

	mocks "github.com/Skyscanner/kms-issuer/pkg/kmsmock"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Context("KMSMock", func() {

	Describe("KMSMock", func() {

		It("should create and delete a key with tags", func() {
			By("Creating a new key")
			client := mocks.New()
			input := &kms.CreateKeyInput{
				Tags: []*kms.Tag{
					{
						TagKey:   aws.String("foo"),
						TagValue: aws.String("bar"),
					},
				},
			}
			key, err := client.CreateKey(input)
			Expect(err).To(BeNil())
			Expect(aws.StringValue(key.KeyMetadata.KeyId)).NotTo(BeEmpty())

			By("Check the Tags")
			tags, err := client.ListResourceTags(&kms.ListResourceTagsInput{
				KeyId: key.KeyMetadata.KeyId,
			})
			Expect(err).To(BeNil())
			Expect(tags.Tags).To(Equal(input.Tags))

			By("Deleting the key")
			_, err = client.ScheduleKeyDeletion(&kms.ScheduleKeyDeletionInput{
				KeyId: key.KeyMetadata.KeyId,
			})
			Expect(err).To(BeNil())
		})

		It("should support kms alias", func() {
			By("Creating a new key")
			client := mocks.New()
			input := &kms.CreateKeyInput{
				Tags: []*kms.Tag{
					{
						TagKey:   aws.String("foo"),
						TagValue: aws.String("bar"),
					},
				},
			}
			key, err := client.CreateKey(input)
			Expect(err).To(BeNil())
			Expect(aws.StringValue(key.KeyMetadata.KeyId)).NotTo(BeEmpty())

			By("Create an alias")
			_, err = client.CreateAlias(&kms.CreateAliasInput{
				TargetKeyId: key.KeyMetadata.KeyId,
				AliasName:   aws.String("alias/my-key"),
			})
			Expect(err).To(BeNil())

			By("Describing the key")
			output, err := client.DescribeKey(&kms.DescribeKeyInput{
				KeyId: aws.String("alias/my-key"),
			})
			Expect(err).To(BeNil())
			Expect(aws.StringValue(output.KeyMetadata.KeyId)).To(Equal(aws.StringValue(key.KeyMetadata.KeyId)))

			_, err = client.DeleteAlias(&kms.DeleteAliasInput{
				AliasName: aws.String("alias/my-key"),
			})
			Expect(err).To(BeNil())
		})

		It("should sign a payload", func() {
			By("Creating a new key")
			client := mocks.New()
			key, err := client.CreateKey(&kms.CreateKeyInput{})
			Expect(err).To(BeNil())
			Expect(aws.StringValue(key.KeyMetadata.KeyId)).NotTo(BeEmpty())

			By("Getting the public key")
			public, err := client.GetPublicKey(&kms.GetPublicKeyInput{
				KeyId: key.KeyMetadata.KeyId,
			})
			Expect(err).To(BeNil())
			publicKey, err := x509.ParsePKIXPublicKey(public.PublicKey)
			Expect(err).To(BeNil())

			By("Signging a payload")
			message := []byte("message to be signed")
			hashed := sha256.Sum256(message)
			signed, err := client.Sign(&kms.SignInput{
				KeyId:   key.KeyMetadata.KeyId,
				Message: hashed[:],
			})
			Expect(err).To(BeNil())

			By("Verifying the signature")
			err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signed.Signature)
			Expect(err).To(BeNil())
		})
	})

})
