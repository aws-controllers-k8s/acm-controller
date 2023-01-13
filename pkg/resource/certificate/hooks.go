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
	"errors"
	"fmt"
	"time"
)

const (
	// See note on
	// https://docs.aws.amazon.com/acm/latest/APIReference/API_RequestCertificate.html
	// about DescribeCertificate not being ready to call for several seconds
	// after a successful RequestCertificate API call...
	waitSecondsAfterCreate = 5 * time.Second

	// DNS validation only works for up to 5 chained CNAME records
	limitDomainValidationOptionsPublic = 5
)

var (
	errTooManyDomainValidationOptions = errors.New(
		"Too many domain validation errors",
	)

	domainValidationOptionsExceededMsg = fmt.Sprintf(
		"Certificate cannot have more than %d domain validation options "+
			"when requesting a public certificate",
		limitDomainValidationOptionsPublic,
	)
)

// validatePublicValidationOptions checks that when requesting a public
// certificate, we do not exceed the number of additional CNAME records that
// DNS verification can handle.
func validatePublicValidationOptions(
	r *resource,
) error {
	// If the certificateAuthorityARN field is empty, that means this is a
	// request for a public certificate. If so, because we require DNS
	// verification for public certificates (due to email verification not be
	// automateable), we need to limit the number of chained CNAME records in
	// the DomainValidationOptions field to 5, since DNS verification only
	// works on up to 5 subdomains.
	if r.ko.Spec.CertificateAuthorityARN != nil {
		numDVOptions := len(r.ko.Spec.DomainValidationOptions)
		if numDVOptions > limitDomainValidationOptionsPublic {
			return errTooManyDomainValidationOptions
		}
	}
	return nil
}

func waitAfterSuccessfulCreate() {
	time.Sleep(waitSecondsAfterCreate)
}
