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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialised.

// Condition reasons
const (
	KMSIssuerReasonPending = "Pending"
	KMSIssuerReasonFailed  = "Failed"
	KMSIssuerReasonIssued  = "Issued"
)

// KMSIssuerSpec defines the desired state of KMSIssuer
type KMSIssuerSpec struct {

	// KeyID is the unique identifier for the customer master key (CMK)
	// deletion. When unspecified, a RSA 2048 key is created and managed by
	// the operator.
	// +optional
	KeyID string `json:"keyId,omitempty"`

	// CommonName is a common name to be used on the Certificate.
	// The CommonName should have a length of 64 characters or fewer to avoid
	// generating invalid CSRs.
	// This value is ignored by TLS clients when any subject alt name is set.
	// This is x509 behaviour: https://tools.ietf.org/html/rfc6125#section-6.4.4
	CommonName string `json:"commonName,omitempty"`

	// The earliest time and date on which the certificate is valid.
	NotBefore metav1.Time `json:"notBefore,omitempty"`

	// The time and date past which the certificate is no longer valid.
	NotAfter metav1.Time `json:"notAfter,omitempty"`

	// SerialNumber used to uniquely identify the certificate.
	SerialNumber int64 `json:"serialNumber,omitempty"`
}

// KMSIssuerStatus defines the observed state of KMSIssuer
type KMSIssuerStatus struct {
	Status `json:",inline"`
	// Byte slice containing a PEM encoded signed certificate of the CA
	// +optional
	Certificate []byte `json:"certificate,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// KMSIssuer is the Schema for the kmsissuers API
type KMSIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KMSIssuerSpec   `json:"spec,omitempty"`
	Status KMSIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KMSIssuerList contains a list of KMSIssuer
type KMSIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KMSIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KMSIssuer{}, &KMSIssuerList{})
}
