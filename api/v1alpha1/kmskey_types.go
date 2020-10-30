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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

)

// Condition reasons
const (
	KMSKeyReasonPending = "Pending"
	KMSKeyReasonFailed  = "Failed"
	KMSKeyReasonIssued  = "Issued"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialised.

// KMSKeySpec defines the desired state of KMSKey
type KMSKeySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// AliasName Specifies the alias name for the kms key. This value must begin with alias/ followed by a
	// name, such as alias/ExampleAlias.
	AliasName string `json:"aliasName"`
	// Description for the key
	Description string `json:"description,omitempty"`
	// CustomerMasterKeySpec determines the signing algorithms that the CMK supports.
	// Only RSA_2048 is currently supported.
	CustomerMasterKeySpec string `json:"customerMasterKeySpec,omitempty"`
	// The key policy to attach to the CMK
	Policy string `json:"policy,omitempty"`
	// Tags is a list of tags for the key
	Tags map[string]string `json:"tags,omitempty"`
	// DeletionPolicy to deletes the alias and key on object deletion.
	// +kubebuilder:validation:Enum=Retain;Delete
	DeletionPolicy string `json:"deletionPolicy,omitempty"`
	// This value is optional. If you include a value, it must be between 7 and
	// 30, inclusive. If you do not include a value, it defaults to 30.
	PendingWindowInDays int `json:"PendingWindowInDays" validate:"required,min=7,max=30"`
}

// KMSKeyStatus defines the observed state of KMSKey
type KMSKeyStatus struct {
	Status `json:",inline"`
	// KeyID is the unique identifier for the customer master key (CMK)
	KeyID string `json:"keyId,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// KMSKey is the Schema for the kmskeys API
type KMSKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KMSKeySpec   `json:"spec,omitempty"`
	Status KMSKeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KMSKeyList contains a list of KMSKey
type KMSKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KMSKey `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KMSKey{}, &KMSKeyList{})
}
