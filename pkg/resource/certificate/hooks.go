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
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	ackv1alpha1 "github.com/aws-controllers-k8s/runtime/apis/core/v1alpha1"
	ackerr "github.com/aws-controllers-k8s/runtime/pkg/errors"
	ackrtlog "github.com/aws-controllers-k8s/runtime/pkg/runtime/log"
	svcsdk "github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/smithy-go"
	pkcs8 "github.com/youmark/pkcs8"
	k8scorev1 "k8s.io/api/core/v1"

	"github.com/aws-controllers-k8s/acm-controller/pkg/tags"
)

const (
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

// maybeImportCertificate imports a certificate into ACM if Spec.Certificate is set.
func (rm *resourceManager) maybeImportCertificate(ctx context.Context, r *resource) (*resource, bool, error) {
	certSpec := r.ko.Spec
	if certSpec.Certificate != nil {
		if certSpec.DomainName != nil || len(certSpec.DomainValidationOptions) > 0 || certSpec.KeyAlgorithm != nil ||
			len(certSpec.SubjectAlternativeNames) > 0 || certSpec.Options != nil {
			return nil, false, ackerr.NewTerminalError(errors.New("cannot set fields used for requesting a certificate when importing a certificate"))
		}
		input, err := rm.newImportCertificateInput(ctx, r)
		if err != nil {
			return nil, false, err
		}
		if len(input.PrivateKey) == 0 {
			return nil, false, ackerr.NewTerminalError(errors.New("privateKey is required when importing a certificate"))
		}
		created, err := rm.importCertificate(ctx, r, input)
		if err != nil {
			return nil, false, err
		}
		return created, true, nil
	}
	if certSpec.DomainName != nil && (certSpec.Certificate != nil || certSpec.PrivateKey != nil || certSpec.CertificateChain != nil) {
		return nil, false, ackerr.NewTerminalError(errors.New("cannot set fields used for importing a certificate when requesting a certificate"))
	}
	return nil, false, nil
}

var (
	syncTags = tags.SyncTags
	listTags = tags.ListTags
)

// importCertificate imports a certificate into ACM.
func (rm *resourceManager) importCertificate(
	ctx context.Context,
	desired *resource,
	input *svcsdk.ImportCertificateInput,
) (created *resource, err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.importCertificate")
	defer func(err error) { exit(err) }(err)

	resp, respErr := rm.sdkapi.ImportCertificate(ctx, input)
	rm.metrics.RecordAPICall("CREATE", "ImportCertificate", respErr)
	if respErr != nil {
		return nil, respErr
	}
	// Merge in the information we read from the API call above to the copy of
	// the original Kubernetes object we passed to the function
	ko := desired.ko.DeepCopy()
	created = &resource{ko}
	rm.setResourceFromImportCertificateOutput(created, resp)
	rm.setStatusDefaults(ko)
	return created, nil
}

// importCertificateInput exists as a workaround for a limitation in code-generator.
// code-generator does not resolve secret key references for custom []byte fields like PrivateKey and Certificate.
type importCertificateInput struct {
	Certificate      *ackv1alpha1.SecretKeyReference
	CertificateChain *ackv1alpha1.SecretKeyReference
	PrivateKey       *ackv1alpha1.SecretKeyReference
	*svcsdk.ImportCertificateInput
}

func validateExportCertificateOptions(
	r *resource,
) error {
	if r.ko.Spec.ExportTo != nil {
		if r.ko.Spec.ExportTo.Name == "" {
			return ackerr.NewTerminalError(errors.New("exportTo requires a name field that refers to a Secret"))
		}
		if r.ko.Spec.ExportPassphrase == nil {
			return ackerr.NewTerminalError(errors.New("exporting a certificate requires the ExportPassphrase field"))
		}
	}
	return nil
}

func (rm *resourceManager) maybeExportCertificate(
	ctx context.Context,
	r *resource,
) error {
	if r.ko.Spec.ExportTo == nil || r.ko.Spec.ExportPassphrase == nil {
		return nil
	}

	// Get the passphrase from the secret reference
	passphrase, err := rm.rr.SecretValueFromReference(ctx, r.ko.Spec.ExportPassphrase)
	if err != nil || passphrase == "" {
		return ackerr.NewTerminalError(errors.New("could not resolve exportPassphrase secret reference"))
	}

	secretReference := new(k8scorev1.SecretReference)
	secretReference.Name = r.ko.Spec.ExportTo.Name
	if r.ko.Spec.ExportTo.Namespace != "" {
		secretReference.Namespace = r.ko.Spec.ExportTo.Namespace
	} else {
		secretReference.Namespace = r.ko.Namespace
	}

	input := &svcsdk.ExportCertificateInput{}
	if r.ko.Status.ACKResourceMetadata != nil && r.ko.Status.ACKResourceMetadata.ARN != nil {
		input.CertificateArn = (*string)(r.ko.Status.ACKResourceMetadata.ARN)
	}
	input.Passphrase = []byte(passphrase)

	resp, err := rm.sdkapi.ExportCertificate(ctx, input)
	rm.metrics.RecordAPICall("READ_ONE", "ExportCertificate", err)
	if err != nil {
		var awsErr smithy.APIError
		if errors.As(err, &awsErr) && awsErr.ErrorCode() == "ResourceNotFoundException" {
			return ackerr.NotFound
		}
		return err
	}

	certificateChain := *resp.Certificate
	if resp.CertificateChain != nil && *resp.CertificateChain != "" {
		certificateChain = certificateChain + *resp.CertificateChain
	}
	if err := rm.rr.WriteToSecret(ctx, certificateChain, secretReference.Namespace, secretReference.Name, "tls.crt"); err != nil {
		return err
	}

	decryptedKey, err := DecryptPrivateKey([]byte(*resp.PrivateKey), []byte(passphrase))
	if err != nil {
		return err
	}

	if err := rm.rr.WriteToSecret(ctx, string(decryptedKey), secretReference.Namespace, secretReference.Name, "tls.key"); err != nil {
		return err
	}

	// No need to update secret annotations since we're now tracking IssuedAt changes
	// in the template logic using the Certificate object's Status field
	return nil
}

func DecryptPrivateKey(encryptedPEM, passphrase []byte) ([]byte, error) {
	pemBlock, _ := pem.Decode(encryptedPEM)
	if pemBlock == nil {
		return nil, errors.New("failed to decode PEM block: no PEM data found")
	}
	privateKey, err := pkcs8.ParsePKCS8PrivateKey(pemBlock.Bytes, passphrase)
	if err != nil {
		return nil, errors.New("failed to decrypt PEM block")
	}

	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey.(*rsa.PrivateKey))
	if err != nil {
		return nil, errors.New("failed to marshal PEM block")
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	})
	return pemBytes, err
}
