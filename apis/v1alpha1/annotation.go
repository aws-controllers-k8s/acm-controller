// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package v1alpha1

import "fmt"

var (
	// ExportedSerialAnnotation is the annotation key used to store the serial
	// of the certificate last exported to a Certificate's spec.exportTo
	// Secret. When the issued serial differs from this value, the
	// acm-controller exports the certificate again.
	//
	// This annotation is only applied by the acm-controller. Removing it
	// forces the certificate to be exported again on the next reconcile.
	ExportedSerialAnnotation = fmt.Sprintf("%s/exported-serial", GroupVersion.Group)
)
