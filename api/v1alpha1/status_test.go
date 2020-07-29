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

package v1alpha1

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// These tests are written in BDD-style using Ginkgo framework. Refer to
// http://onsi.github.io/ginkgo to learn more.

var _ = Describe("Status", func() {

	BeforeEach(func() {
		// Add any setup steps that needs to be executed before each test
	})

	AfterEach(func() {
		// Add any teardown steps that needs to be executed after each test
	})

	Context("Status", func() {

		Describe("SetCondition", func() {
			It("should add a new conditions", func() {
				status := &Status{}
				oups := NewCondition(ConditionReady, ConditionFalse, KMSIssuerReasonFailed, "oups")
				status.SetCondition(&oups)
				Expect(status.Conditions[0]).To(Equal(oups))
				Expect(len(status.Conditions)).To(Equal(1))
			})

			It("should replace a pre-existing conditions", func() {
				status := &Status{}
				empty := NewCondition(ConditionReady, ConditionTrue, KMSIssuerReasonIssued, "")
				status.SetCondition(&empty)
				oups := NewCondition(ConditionReady, ConditionFalse, KMSIssuerReasonFailed, "oups")
				status.SetCondition(&oups)
				Expect(status.Conditions[0]).To(Equal(oups))
				Expect(len(status.Conditions)).To(Equal(1))
			})

			It("should not update the condition if it already exists and has the same status and reason.", func() {
				status := &Status{}
				because := NewCondition(ConditionReady, ConditionFalse, KMSIssuerReasonFailed, "because")
				status.SetCondition(&because)
				otherMsg := NewCondition(ConditionReady, ConditionFalse, KMSIssuerReasonFailed, "othermsg")
				status.SetCondition(&otherMsg)
				Expect(status.Conditions[0]).To(Equal(because))
				Expect(len(status.Conditions)).To(Equal(1))
			})
		})
		Describe("GetCondition", func() {
			It("should return a condition by type", func() {
				status := &Status{}
				empty := NewCondition(ConditionReady, ConditionTrue, KMSIssuerReasonIssued, "")
				status.SetCondition(&empty)
				Expect(*status.GetCondition(ConditionReady)).To(Equal(empty))
			})
		})
		Describe("IsReady", func() {
			It("should return true when the Ready Condition is true", func() {
				status := &Status{}
				empty := NewCondition(ConditionReady, ConditionTrue, KMSIssuerReasonIssued, "")
				status.SetCondition(&empty)
				Expect(status.IsReady()).To(BeTrue())
			})

			It("should return false with the Ready Condition is false", func() {
				status := &Status{}
				empty := NewCondition(ConditionReady, ConditionFalse, KMSIssuerReasonIssued, "")
				status.SetCondition(&empty)
				Expect(status.IsReady()).To(BeFalse())
			})
			It("should return false with the Ready Condition is not set", func() {
				status := &Status{}
				Expect(status.IsReady()).To(BeFalse())
			})
		})
	})
})
