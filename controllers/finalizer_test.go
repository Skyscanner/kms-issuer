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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Finalizers", func() {

	Context("Finalizers", func() {

		Describe("Finalizers", func() {
			It("should correctly handle finalizers", func() {
				obj := &metav1.ObjectMeta{}
				Expect(NeedToAddFinalizer(obj)).To(BeTrue())
				Expect(IsBeingDeleted(obj)).To(BeFalse())

				AddFinalizer(obj)
				Expect(len(obj.GetFinalizers())).To(Equal(1))
				Expect(NeedToAddFinalizer(obj)).To(BeFalse())

				RemoveFinalizer(obj)
				Expect(len(obj.GetFinalizers())).To(Equal(0))
				Expect(NeedToAddFinalizer(obj)).To(BeTrue())
			})

			It("should correctly handle finalizers when the object is being deleted", func() {
				obj := &metav1.ObjectMeta{
					DeletionTimestamp: &metav1.Time{
						Time: time.Now(),
					},
				}
				Expect(NeedToAddFinalizer(obj)).To(BeFalse())
				Expect(IsBeingDeleted(obj)).To(BeTrue())
			})
		})
	})
})
