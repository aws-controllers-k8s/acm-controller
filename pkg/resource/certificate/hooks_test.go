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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	svcapitypes "github.com/aws-controllers-k8s/acm-controller/apis/v1alpha1"
	ackv1alpha1 "github.com/aws-controllers-k8s/runtime/apis/core/v1alpha1"
	ackrequeue "github.com/aws-controllers-k8s/runtime/pkg/requeue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type fakeReconciler struct {
	secretValues map[string]string
}

func (f *fakeReconciler) Reconcile(
	context.Context,
	reconcile.Request,
) (reconcile.Result, error) {
	return reconcile.Result{}, nil
}

func (f *fakeReconciler) SecretValueFromReference(
	_ context.Context,
	ref *ackv1alpha1.SecretKeyReference,
) (string, error) {
	return f.secretValues[ref.Key], nil
}

func (f *fakeReconciler) WriteToSecret(
	context.Context,
	string,
	string,
	string,
	string,
) error {
	return nil
}

func testCertificatePEM(t *testing.T, serial int64) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "services.k8s.aws"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestImportSecretRefsFromSpec(t *testing.T) {
	ref := &ackv1alpha1.SecretReference{}
	ref.Name = "tls-secret"

	refs, err := importSecretRefsFromSpec(
		svcapitypes.CertificateSpec{ImportFrom: ref},
	)
	if err != nil {
		t.Fatal(err)
	}
	if refs.Certificate.Key != tlsCertificateSecretDataKey {
		t.Fatalf("certificate key = %q", refs.Certificate.Key)
	}
	if refs.PrivateKey.Key != tlsPrivateKeySecretDataKey {
		t.Fatalf("private key = %q", refs.PrivateKey.Key)
	}
	if refs.Certificate.Name != "tls-secret" ||
		refs.PrivateKey.Name != "tls-secret" {
		t.Fatal("secret name was not preserved")
	}
}

func TestValidateImportFromExclusivity(t *testing.T) {
	importFrom := &ackv1alpha1.SecretReference{}
	importFrom.Name = "tls-secret"
	domainName := "example.com"
	certificate := &ackv1alpha1.SecretKeyReference{Key: "certificate"}

	tests := []struct {
		name    string
		spec    svcapitypes.CertificateSpec
		wantErr bool
	}{
		{
			name: "importFrom only",
			spec: svcapitypes.CertificateSpec{ImportFrom: importFrom},
		},
		{
			name: "domain name conflict",
			spec: svcapitypes.CertificateSpec{
				ImportFrom: importFrom,
				DomainName: &domainName,
			},
			wantErr: true,
		},
		{
			name: "opaque certificate conflict",
			spec: svcapitypes.CertificateSpec{
				ImportFrom:  importFrom,
				Certificate: certificate,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateImportFromExclusivity(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClearImportFromObservedSpecFields(t *testing.T) {
	domainName := "example.com"
	keyAlgorithm := "RSA_2048"
	subjectAlternativeName := "www.example.com"
	certificate := &ackv1alpha1.SecretKeyReference{Key: "certificate"}
	spec := svcapitypes.CertificateSpec{
		Certificate:             certificate,
		DomainName:              &domainName,
		DomainValidationOptions: []*svcapitypes.DomainValidationOption{{}},
		KeyAlgorithm:            &keyAlgorithm,
		Options:                 &svcapitypes.CertificateOptions{},
		SubjectAlternativeNames: []*string{&subjectAlternativeName},
	}

	clearImportFromObservedSpecFields(&spec)

	if spec.DomainName != nil ||
		spec.DomainValidationOptions != nil ||
		spec.KeyAlgorithm != nil ||
		spec.Options != nil ||
		spec.SubjectAlternativeNames != nil {
		t.Fatal("observed request fields were not cleared")
	}
	if spec.Certificate != certificate {
		t.Fatal("opaque import fields must not be cleared")
	}
}

func TestSplitCertificateAndChain(t *testing.T) {
	leaf := testCertificatePEM(t, 1)
	intermediate := testCertificatePEM(t, 2)

	certificate, chain, err := splitCertificateAndChain(
		append(append([]byte{}, leaf...), intermediate...),
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(certificate) != string(leaf) {
		t.Fatal("leaf certificate was not preserved")
	}
	if string(chain) != string(intermediate) {
		t.Fatal("certificate chain was not preserved")
	}
}

func TestSyncImportFromSecretIfNeededAlreadySynced(t *testing.T) {
	certificatePEM := testCertificatePEM(t, 42)
	acmCertificate, err := parseLeafCertificate(certificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	importFrom := &ackv1alpha1.SecretReference{}
	importFrom.Name = "tls-secret"
	arn := ackv1alpha1.AWSResourceName("arn:aws:acm:region:account:certificate/id")
	certificateType := string(svcapitypes.CertificateType_IMPORTED)
	r := &resource{ko: &svcapitypes.Certificate{
		Spec: svcapitypes.CertificateSpec{ImportFrom: importFrom},
		Status: svcapitypes.CertificateStatus{
			ACKResourceMetadata: &ackv1alpha1.ResourceMetadata{ARN: &arn},
			Type:                &certificateType,
		},
	}}
	rm := &resourceManager{rr: &fakeReconciler{
		secretValues: map[string]string{
			tlsCertificateSecretDataKey: string(certificatePEM),
		},
	}}

	importCalls := 0
	got, err := rm.syncImportFromSecretWithImporter(
		context.Background(),
		r,
		func(context.Context, *resource) (*x509.Certificate, error) {
			return acmCertificate, nil
		},
		func(context.Context, *resource) (*resource, bool, error) {
			importCalls++
			return r, true, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != r {
		t.Fatal("already-synced resource should be returned unchanged")
	}
	if importCalls != 0 {
		t.Fatalf("import calls = %d, want 0", importCalls)
	}
}

func TestSyncImportFromSecretIfNeededReimportsOnceAndRequeues(t *testing.T) {
	certificatePEM := testCertificatePEM(t, 42)
	acmCertificatePEM := testCertificatePEM(t, 42)
	acmCertificate, err := parseLeafCertificate(acmCertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	secretCertificate, err := parseLeafCertificate(certificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if secretCertificate.SerialNumber.Cmp(acmCertificate.SerialNumber) != 0 {
		t.Fatal("test certificates must share a serial number")
	}
	if certificatesMatch(secretCertificate, acmCertificate) {
		t.Fatal("test certificates must have different DER encodings")
	}
	importFrom := &ackv1alpha1.SecretReference{}
	importFrom.Name = "tls-secret"
	arn := ackv1alpha1.AWSResourceName("arn:aws:acm:region:account:certificate/id")
	certificateType := string(svcapitypes.CertificateType_IMPORTED)
	r := &resource{ko: &svcapitypes.Certificate{
		Spec: svcapitypes.CertificateSpec{ImportFrom: importFrom},
		Status: svcapitypes.CertificateStatus{
			ACKResourceMetadata: &ackv1alpha1.ResourceMetadata{ARN: &arn},
			Type:                &certificateType,
		},
	}}
	rm := &resourceManager{rr: &fakeReconciler{
		secretValues: map[string]string{
			tlsCertificateSecretDataKey: string(certificatePEM),
		},
	}}
	importCalls := 0

	got, err := rm.syncImportFromSecretWithImporter(
		context.Background(),
		r,
		func(context.Context, *resource) (*x509.Certificate, error) {
			return acmCertificate, nil
		},
		func(
			context.Context,
			*resource,
		) (*resource, bool, error) {
			importCalls++
			return r, true, nil
		},
	)

	if got != nil {
		t.Fatal("stale observed resource must not be returned after re-import")
	}
	if importCalls != 1 {
		t.Fatalf("import calls = %d, want 1", importCalls)
	}
	var requeueErr *ackrequeue.RequeueNeededAfter
	if !errors.As(err, &requeueErr) {
		t.Fatalf("error = %T, want RequeueNeededAfter", err)
	}
}
