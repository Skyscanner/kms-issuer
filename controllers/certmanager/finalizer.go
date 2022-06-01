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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubectl/pkg/util/slice"
)

const (
	// FinalizerName is the name of the kuberneter finalizer being added to the KMSIssuer resources.
	FinalizerName = "kms-issuer.finalizers.cert-manager.skyscanner.net"
)

// NeedToAddFinalizer checks if need to add finalizer to object
func NeedToAddFinalizer(obj metav1.Object) bool {
	return obj.GetDeletionTimestamp() == nil && !slice.ContainsString(obj.GetFinalizers(), FinalizerName, nil)
}

// AddFinalizer adds the finalizer to the object
func AddFinalizer(obj metav1.Object) {
	obj.SetFinalizers(
		append(obj.GetFinalizers(), FinalizerName),
	)
}

// RemoveFinalizer removes the specified finalizer
func RemoveFinalizer(obj metav1.Object) {
	obj.SetFinalizers(
		removeString(obj.GetFinalizers(), FinalizerName),
	)
}

// IsBeingDeleted returns true if a deletion timestamp is set.
func IsBeingDeleted(obj metav1.Object) bool {
	return !obj.GetDeletionTimestamp().IsZero()
}
