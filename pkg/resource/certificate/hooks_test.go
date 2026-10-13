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

package certificate

import (
	"testing"

	ackv1alpha1 "github.com/aws-controllers-k8s/runtime/apis/core/v1alpha1"
	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"

	svcapitypes "github.com/aws-controllers-k8s/acm-controller/apis/v1alpha1"
)

func strPtr(s string) *string { return &s }

func newCertificate(
	exportTo bool,
	status *string,
	serial *string,
	annotations map[string]string,
) *resource {
	ko := &svcapitypes.Certificate{}
	if exportTo {
		ko.Spec.ExportTo = &ackv1alpha1.SecretKeyReference{Key: "tls.crt"}
	}
	ko.Status.Status = status
	ko.Status.Serial = serial
	ko.SetAnnotations(annotations)
	return &resource{ko: ko}
}

func TestCompareExportedSerial(t *testing.T) {
	issued := strPtr("ISSUED")
	exportedSerial := func(s string) map[string]string {
		return map[string]string{svcapitypes.ExportedSerialAnnotation: s}
	}
	cases := []struct {
		name        string
		exportTo    bool
		status      *string
		serial      *string
		annotations map[string]string
		wantDelta   bool
	}{
		{"no exportTo", false, issued, strPtr("01"), nil, false},
		{"not yet issued", true, strPtr("PENDING_VALIDATION"), nil, nil, false},
		{"issued without serial", true, issued, nil, nil, false},
		{"first issuance", true, issued, strPtr("01"), nil, true},
		{"already exported", true, issued, strPtr("01"), exportedSerial("01"), false},
		{"renewed", true, issued, strPtr("02"), exportedSerial("01"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The runtime hands the delta a desired copy carrying the
			// observed status, so a and b share status and annotations.
			b := newCertificate(tc.exportTo, tc.status, tc.serial, tc.annotations)
			a := &resource{ko: b.ko.DeepCopy()}
			delta := ackcompare.NewDelta()
			compareExportedSerial(delta, a, b)
			if got := delta.DifferentAt("Spec.Status.Serial"); got != tc.wantDelta {
				t.Fatalf("DifferentAt(Spec.Status.Serial) = %v, want %v", got, tc.wantDelta)
			}
		})
	}
}

func TestSetExportedSerial(t *testing.T) {
	ko := &svcapitypes.Certificate{}
	ko.SetAnnotations(map[string]string{"keep": "me"})
	setExportedSerial(ko, "02")
	got := ko.GetAnnotations()
	if got[svcapitypes.ExportedSerialAnnotation] != "02" || got["keep"] != "me" {
		t.Fatalf("unexpected annotations: %v", got)
	}

	ko = &svcapitypes.Certificate{}
	setExportedSerial(ko, "01")
	if ko.GetAnnotations()[svcapitypes.ExportedSerialAnnotation] != "01" {
		t.Fatalf("unexpected annotations: %v", ko.GetAnnotations())
	}
}
