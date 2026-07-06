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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws-controllers-k8s/acm-controller/pkg/tags"
	ackv1alpha1 "github.com/aws-controllers-k8s/runtime/apis/core/v1alpha1"
	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackerr "github.com/aws-controllers-k8s/runtime/pkg/errors"
	ackrequeue "github.com/aws-controllers-k8s/runtime/pkg/requeue"
	ackrtlog "github.com/aws-controllers-k8s/runtime/pkg/runtime/log"
	svcsdk "github.com/aws/aws-sdk-go-v2/service/acm"
	pkcs8 "github.com/youmark/pkcs8"

	svcapitypes "github.com/aws-controllers-k8s/acm-controller/apis/v1alpha1"
)

const (
	// DNS validation only works for up to 5 chained CNAME records
	limitDomainValidationOptionsPublic = 5
	// tlsCertificateSecretDataKey is the secret data key for the certificate when
	// importing from a Kubernetes TLS Secret via importFrom.
	tlsCertificateSecretDataKey = "tls.crt"
	// tlsPrivateKeySecretDataKey is the secret data key for the private key when
	// importing from a Kubernetes TLS Secret via importFrom.
	tlsPrivateKeySecretDataKey = "tls.key"
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

// importSecretRefs holds the resolved secret references for certificate import.
type importSecretRefs struct {
	Certificate      *ackv1alpha1.SecretKeyReference
	PrivateKey       *ackv1alpha1.SecretKeyReference
	CertificateChain *ackv1alpha1.SecretKeyReference
}

func isImportCertificateSpec(certSpec svcapitypes.CertificateSpec) bool {
	return certSpec.Certificate != nil || certSpec.ImportFrom != nil
}

func importSecretRefsFromSpec(certSpec svcapitypes.CertificateSpec) (*importSecretRefs, error) {
	if certSpec.ImportFrom != nil {
		certRef := ackv1alpha1.SecretKeyReference{
			SecretReference: certSpec.ImportFrom.SecretReference,
			Key:             tlsCertificateSecretDataKey,
		}
		keyRef := ackv1alpha1.SecretKeyReference{
			SecretReference: certSpec.ImportFrom.SecretReference,
			Key:             tlsPrivateKeySecretDataKey,
		}
		return &importSecretRefs{
			Certificate: &certRef,
			PrivateKey:  &keyRef,
		}, nil
	}
	return &importSecretRefs{
		Certificate:      certSpec.Certificate,
		PrivateKey:       certSpec.PrivateKey,
		CertificateChain: certSpec.CertificateChain,
	}, nil
}

func (rm *resourceManager) secretValueFromReference(
	ctx context.Context,
	ref *ackv1alpha1.SecretKeyReference,
) (string, error) {
	if ref == nil {
		return "", nil
	}
	value, err := rm.rr.SecretValueFromReference(ctx, ref)
	if err != nil {
		return "", ackrequeue.Needed(err)
	}
	return value, nil
}

func validateImportFromExclusivity(certSpec svcapitypes.CertificateSpec) error {
	if certSpec.ImportFrom == nil {
		return nil
	}
	// Tags are excluded because the controller injects default tags via
	// EnsureTags before create. Request fields populated from ACM are cleared
	// before this validation when importFrom manages an existing certificate.
	if certSpec.Certificate != nil || certSpec.PrivateKey != nil || certSpec.CertificateChain != nil ||
		certSpec.ExportTo != nil ||
		certSpec.CertificateAuthorityARN != nil || certSpec.CertificateAuthorityRef != nil ||
		certSpec.DomainName != nil || len(certSpec.DomainValidationOptions) > 0 ||
		certSpec.KeyAlgorithm != nil || certSpec.Options != nil ||
		len(certSpec.SubjectAlternativeNames) > 0 {
		return ackerr.NewTerminalError(errors.New("importFrom cannot be set with certificate request, export, or opaque secret import fields"))
	}
	return nil
}

func clearImportFromObservedSpecFields(certSpec *svcapitypes.CertificateSpec) {
	certSpec.DomainValidationOptions = nil
	certSpec.KeyAlgorithm = nil
	certSpec.SubjectAlternativeNames = nil
	certSpec.Options = nil
	certSpec.DomainName = nil
}

// splitCertificateAndChain splits PEM data that may contain a leaf certificate
// followed by intermediate certificates (as stored in a Kubernetes TLS Secret's
// tls.crt key) into separate certificate and chain byte slices for ACM import.
func splitCertificateAndChain(pemData []byte) (certificate []byte, chain []byte, err error) {
	var certBlocks [][]byte
	remaining := pemData
	for {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certBlocks = append(certBlocks, pem.EncodeToMemory(block))
	}
	if len(certBlocks) == 0 {
		return nil, nil, errors.New("no certificate found in PEM data")
	}
	certificate = certBlocks[0]
	if len(certBlocks) > 1 {
		chain = bytes.Join(certBlocks[1:], nil)
	}
	return certificate, chain, nil
}

// finalizeImportCertificateInput applies ImportCertificate request constraints that
// are not expressed in the CRD schema. ACM does not permit tags when re-importing
// a certificate at an existing ARN.
func finalizeImportCertificateInput(input *svcsdk.ImportCertificateInput) {
	if input.CertificateArn != nil && *input.CertificateArn != "" {
		input.Tags = nil
	}
}

// ImportTlsCertificate imports a certificate into ACM if Spec.Certificate or
// Spec.ImportFrom is set.
func (rm *resourceManager) ImportTlsCertificate(ctx context.Context, r *resource) (*resource, bool, error) {
	certSpec := r.ko.Spec
	if isImportCertificateSpec(certSpec) {
		// When re-importing a certificate that was previously created (has an
		// ARN), clear request-only fields that were populated by late
		// initialization / DescribeCertificate. These are informational for
		// imported certs and will be re-populated after the new import succeeds.
		if r.ko.Status.ACKResourceMetadata != nil && r.ko.Status.ACKResourceMetadata.ARN != nil {
			clearImportFromObservedSpecFields(&certSpec)
		}
		if err := validateImportFromExclusivity(certSpec); err != nil {
			return nil, false, err
		}
		if certSpec.ImportFrom == nil && (certSpec.DomainName != nil || len(certSpec.DomainValidationOptions) > 0 || certSpec.KeyAlgorithm != nil ||
			len(certSpec.SubjectAlternativeNames) > 0 || certSpec.Options != nil) {
			return nil, false, ackerr.NewTerminalError(errors.New("cannot set fields used for requesting a certificate when importing a certificate"))
		}
		input, err := rm.newImportCertificateInput(ctx, r)
		if err != nil {
			return nil, false, err
		}
		setImportCertificateARN(input, r)
		finalizeImportCertificateInput(input)
		if len(input.PrivateKey) == 0 {
			return nil, false, ackerr.NewTerminalError(errors.New("privateKey is required when importing a certificate"))
		}
		created, err := rm.importCertificate(ctx, r, input)
		if err != nil {
			return nil, false, err
		}
		return created, true, nil
	}
	if certSpec.DomainName != nil && (certSpec.Certificate != nil || certSpec.PrivateKey != nil || certSpec.CertificateChain != nil || certSpec.ImportFrom != nil) {
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

func isImportFromManagedCertificate(r *resource) bool {
	if r == nil || r.ko == nil || r.ko.Spec.ImportFrom == nil {
		return false
	}
	if r.ko.Status.ACKResourceMetadata == nil || r.ko.Status.ACKResourceMetadata.ARN == nil {
		return false
	}
	return r.ko.Status.Type != nil &&
		*r.ko.Status.Type == string(svcapitypes.CertificateType_IMPORTED)
}

func parseLeafCertificate(pemData []byte) (*x509.Certificate, error) {
	certPEM, _, err := splitCertificateAndChain(pemData)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (rm *resourceManager) importFromSecretLeafCertificate(
	ctx context.Context,
	certSpec svcapitypes.CertificateSpec,
) (*x509.Certificate, error) {
	refs, err := importSecretRefsFromSpec(certSpec)
	if err != nil {
		return nil, err
	}
	if refs.Certificate == nil {
		return nil, errors.New("importFrom secret reference is missing")
	}

	pemData, err := rm.secretValueFromReference(ctx, refs.Certificate)
	if err != nil {
		return nil, err
	}
	if pemData == "" {
		return nil, errors.New("importFrom TLS secret certificate is empty")
	}
	return parseLeafCertificate([]byte(pemData))
}

// certificatesMatch compares the complete DER-encoded leaf certificates.
func certificatesMatch(a, b *x509.Certificate) bool {
	return a != nil && b != nil && bytes.Equal(a.Raw, b.Raw)
}

func (rm *resourceManager) getACMLeafCertificate(
	ctx context.Context,
	r *resource,
) (*x509.Certificate, error) {
	if r == nil || r.ko == nil ||
		r.ko.Status.ACKResourceMetadata == nil ||
		r.ko.Status.ACKResourceMetadata.ARN == nil {
		return nil, errors.New("cannot get ACM certificate without an ARN")
	}
	arn := string(*r.ko.Status.ACKResourceMetadata.ARN)
	output, err := rm.sdkapi.GetCertificate(ctx, &svcsdk.GetCertificateInput{
		CertificateArn: &arn,
	})
	rm.metrics.RecordAPICall("READ_ONE", "GetCertificate", err)
	if err != nil {
		return nil, err
	}
	if output.Certificate == nil {
		return nil, errors.New("ACM GetCertificate response did not contain a certificate")
	}
	return parseLeafCertificate([]byte(*output.Certificate))
}

func setImportCertificateARN(input *svcsdk.ImportCertificateInput, r *resource) {
	if input == nil || r == nil || r.ko == nil {
		return
	}
	if input.CertificateArn != nil && *input.CertificateArn != "" {
		return
	}
	if r.ko.Spec.CertificateARN != nil && *r.ko.Spec.CertificateARN != "" {
		input.CertificateArn = r.ko.Spec.CertificateARN
		return
	}
	if r.ko.Status.ACKResourceMetadata != nil && r.ko.Status.ACKResourceMetadata.ARN != nil {
		arn := string(*r.ko.Status.ACKResourceMetadata.ARN)
		input.CertificateArn = &arn
	}
}

// syncImportFromSecretIfNeeded performs at most one re-import per read. The
// next scheduled reconciliation observes ACM again, avoiding recursive sdkFind
// calls while ACM propagates the replacement certificate.
func (rm *resourceManager) syncImportFromSecretIfNeeded(
	ctx context.Context,
	r *resource,
) (*resource, error) {
	return rm.syncImportFromSecretWithImporter(
		ctx,
		r,
		rm.getACMLeafCertificate,
		rm.ImportTlsCertificate,
	)
}

type getACMLeafCertificateFunc func(
	context.Context,
	*resource,
) (*x509.Certificate, error)

type importTLSCertificateFunc func(
	context.Context,
	*resource,
) (*resource, bool, error)

func (rm *resourceManager) syncImportFromSecretWithImporter(
	ctx context.Context,
	r *resource,
	getACMCertificate getACMLeafCertificateFunc,
	importCertificate importTLSCertificateFunc,
) (*resource, error) {
	if !isImportFromManagedCertificate(r) {
		return r, nil
	}

	leafCert, err := rm.importFromSecretLeafCertificate(ctx, r.ko.Spec)
	if err != nil {
		return nil, err
	}
	acmCert, err := getACMCertificate(ctx, r)
	if err != nil {
		return nil, err
	}
	if certificatesMatch(leafCert, acmCert) {
		return r, nil
	}

	rlog := ackrtlog.FromContext(ctx)
	rlog.Info(
		"TLS secret certificate does not match ACM certificate, re-importing",
	)
	_, _, err = importCertificate(ctx, r)
	if err != nil {
		return nil, err
	}
	return nil, ackrequeue.NeededAfter(
		errors.New("waiting for ACM to observe the re-imported certificate"),
		5*time.Second,
	)
}

// importCertificateInput exists as a workaround for a limitation in code-generator.
// code-generator does not resolve secret key references for custom []byte fields like PrivateKey and Certificate.
type importCertificateInput struct {
	Certificate      *ackv1alpha1.SecretKeyReference
	CertificateChain *ackv1alpha1.SecretKeyReference
	PrivateKey       *ackv1alpha1.SecretKeyReference
	*svcsdk.ImportCertificateInput
}

// generateRandomString generates a cryptographically secure random string of a given length
// using a specified character set.
func generateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}

	result := make([]byte, length)
	charsetLen := len(charset)
	for i := 0; i < length; i++ {
		result[i] = charset[int(b[i])%charsetLen]
	}

	return string(result), nil
}

func (rm *resourceManager) exportCertificate(
	ctx context.Context,
	r *resource,
) error {
	if r.ko.Spec.ExportTo == nil {
		return nil
	}

	input := &svcsdk.ExportCertificateInput{}
	if r.ko.Status.ACKResourceMetadata != nil && r.ko.Status.ACKResourceMetadata.ARN != nil {
		input.CertificateArn = (*string)(r.ko.Status.ACKResourceMetadata.ARN)
	}

	passphraseLength := 8 // Desired length of the passphrase
	passphrase, err := generateRandomString(passphraseLength)
	if err != nil {
		return err
	}
	input.Passphrase = []byte(passphrase)

	resp, err := rm.sdkapi.ExportCertificate(ctx, input)
	rm.metrics.RecordAPICall("READ_ONE", "ExportCertificate", err)
	if err != nil {
		return err
	}

	certificateChain := *resp.Certificate
	if resp.CertificateChain != nil && *resp.CertificateChain != "" {
		certificateChain = certificateChain + *resp.CertificateChain
	}

	if r.ko.Spec.ExportTo.Namespace != "" {
		if err := rm.rr.WriteToSecret(ctx, certificateChain, r.ko.Spec.ExportTo.Namespace, r.ko.Spec.ExportTo.Name, r.ko.Spec.ExportTo.Key); err != nil {
			return err
		}
	} else {
		if err := rm.rr.WriteToSecret(ctx, certificateChain, r.ko.Namespace, r.ko.Spec.ExportTo.Name, r.ko.Spec.ExportTo.Key); err != nil {
			return err
		}
	}

	decryptedKey, err := DecryptPrivateKey([]byte(*resp.PrivateKey), []byte(passphrase), *r.ko.Spec.KeyAlgorithm)
	if err != nil {
		return err
	}

	if r.ko.Spec.ExportTo.Namespace != "" {
		if err := rm.rr.WriteToSecret(ctx, string(decryptedKey), r.ko.Spec.ExportTo.Namespace, r.ko.Spec.ExportTo.Name, "tls.key"); err != nil {
			return err
		}
	} else {
		if err := rm.rr.WriteToSecret(ctx, string(decryptedKey), r.ko.Namespace, r.ko.Spec.ExportTo.Name, "tls.key"); err != nil {
			return err
		}
	}

	// No need to update secret annotations since we're now tracking IssuedAt changes
	// in the template logic using the Certificate object's Status field
	return nil
}

func DecryptPrivateKey(encryptedPEM, passphrase []byte, keyAlgorithm string) ([]byte, error) {
	pemBlock, _ := pem.Decode(encryptedPEM)
	if pemBlock == nil {
		return nil, errors.New("failed to decode PEM block: no PEM data found")
	}
	privateKey, err := pkcs8.ParsePKCS8PrivateKey(pemBlock.Bytes, passphrase)
	if err != nil {
		return nil, errors.New("failed to decrypt PEM block")
	}

	// NOTE: Algorithms supported for an ACM certificate request include: RSA_2048, EC_prime256v1, EC_secp384r1
	if strings.Contains(keyAlgorithm, "RSA") {
		derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey.(*rsa.PrivateKey))
		if err != nil {
			return nil, errors.New("failed to marshal PEM block")
		}

		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		})
		return pemBytes, err
	} else {
		derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, errors.New("failed to marshal PEM block")
		}

		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		})
		return pemBytes, err
	}
}

// normalizeKeyAlgorithm normalizes a KeyAlgorithm value by replacing all dash
// characters with underscore characters. This ensures consistency between the
// user-specified format (e.g., RSA_2048) and the AWS API response format
// (e.g., RSA-2048).
func normalizeKeyAlgorithm(algorithm string) string {
	return strings.ReplaceAll(algorithm, "-", "_")
}

func compareKeyAlgorithm(
	delta *ackcompare.Delta,
	a *resource,
	b *resource,
) {
	if a.ko.Spec.KeyAlgorithm != nil && b.ko.Spec.KeyAlgorithm != nil {
		normalizedA := normalizeKeyAlgorithm(*a.ko.Spec.KeyAlgorithm)
		normalizedB := normalizeKeyAlgorithm(*b.ko.Spec.KeyAlgorithm)
		if normalizedA != normalizedB {
			delta.Add("Spec.KeyAlgorithm", a.ko.Spec.KeyAlgorithm, b.ko.Spec.KeyAlgorithm)
		}
	}
}

func compareDomainName(
	delta *ackcompare.Delta,
	a *resource,
	b *resource,
) {
	// DomainName is populated by ACM for importFrom certificates and is not
	// part of the user's desired state.
	if a.ko.Spec.ImportFrom != nil || b.ko.Spec.ImportFrom != nil {
		return
	}
	if ackcompare.HasNilDifference(a.ko.Spec.DomainName, b.ko.Spec.DomainName) {
		delta.Add("Spec.DomainName", a.ko.Spec.DomainName, b.ko.Spec.DomainName)
	} else if a.ko.Spec.DomainName != nil && b.ko.Spec.DomainName != nil {
		if *a.ko.Spec.DomainName != *b.ko.Spec.DomainName {
			delta.Add("Spec.DomainName", a.ko.Spec.DomainName, b.ko.Spec.DomainName)
		}
	}
}

func compareCertificateIssuedAt(
	delta *ackcompare.Delta,
	a *resource,
	b *resource,
) {
	if a.ko.Spec.ExportTo != nil {
		// NOTE: first time the certificate is issued
		if a.ko.Status.IssuedAt == nil && b.ko.Status.Status != nil && *b.ko.Status.Status == "ISSUED" {
			// NOTE: ack runtime ONLY goes into update if delta key starts with "Spec"
			// https://github.com/aws-controllers-k8s/runtime/blob/main/pkg/runtime/reconciler.go#L894-L903
			delta.Add("Spec.Status.IssuedAt", a.ko.Status.IssuedAt, b.ko.Status.IssuedAt)
		}
		// NOTE: when the certificate is renewed
		if a.ko.Status.Serial != nil && b.ko.Status.Serial != nil && *a.ko.Status.Serial != *b.ko.Status.Serial {
			// NOTE: ack runtime ONLY goes into update if delta key starts with "Spec"
			// https://github.com/aws-controllers-k8s/runtime/blob/main/pkg/runtime/reconciler.go#L894-L903
			delta.Add("Spec.Status.Serial", a.ko.Status.Serial, b.ko.Status.Serial)
		}
	}
}
