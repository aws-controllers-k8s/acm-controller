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

package acme_external_account_binding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	ackv1alpha1 "github.com/aws-controllers-k8s/runtime/apis/core/v1alpha1"
	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackerr "github.com/aws-controllers-k8s/runtime/pkg/errors"
	acktypes "github.com/aws-controllers-k8s/runtime/pkg/types"

	svcapitypes "github.com/aws-controllers-k8s/acm-controller/apis/v1alpha1"
)

func strPtr(s string) *string { return &s }

func eabResource() *resource {
	arn := ackv1alpha1.AWSResourceName(
		"arn:aws:acm:us-west-2:123456789012:acme-endpoint/e1/acme-external-account-binding/b1")
	ko := &svcapitypes.AcmeExternalAccountBinding{}
	ko.Status.ACKResourceMetadata = &ackv1alpha1.ResourceMetadata{ARN: &arn}
	ko.Spec.Tags = []*svcapitypes.Tag{{Key: strPtr("k"), Value: strPtr("v")}}
	return &resource{ko: ko}
}

// The service has no update operation for an external account binding, so the only
// reconcilable field is the tag set. Anything else must be a TERMINAL error: a plain
// error would be retried for ever, and returning nil would leave the resource reporting
// Synced while its spec and the service disagreed.
//
// The tag-sync path itself is exercised by the e2e test (test_update_tags); it cannot be
// stubbed from here because tags.SyncResourceTags takes package-private interfaces.
func TestCustomUpdateRejectsNonTagChanges(t *testing.T) {
	for _, field := range []string{"Spec.RoleARN", "Spec.AcmeEndpointARN", "Spec.Expiration"} {
		t.Run(field, func(t *testing.T) {
			delta := ackcompare.NewDelta()
			delta.Add(field, nil, nil)

			rm := &resourceManager{}
			out, err := rm.customUpdateAcmeExternalAccountBinding(
				context.Background(), eabResource(), eabResource(), delta)

			if err == nil {
				t.Fatalf("changing %s must fail: the service cannot apply it", field)
			}
			if out != nil {
				t.Error("no resource should be returned when the update is rejected")
			}
			var terminal *ackerr.TerminalError
			if !errors.As(err, &terminal) {
				t.Errorf("the error must be a TerminalError so the resource stops retrying, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), "only tags") {
				t.Errorf("the message should say what IS updatable, got %q", err.Error())
			}
		})
	}
}

// A delta with no differences at all must be a no-op that returns the desired resource,
// not an error: the runtime calls sdkUpdate whenever it sees any delta, including ones
// confined to fields this resource ignores.
func TestCustomUpdateWithNoDifferencesIsANoOp(t *testing.T) {
	desired := eabResource()
	rm := &resourceManager{}
	out, err := rm.customUpdateAcmeExternalAccountBinding(
		context.Background(), desired, eabResource(), ackcompare.NewDelta())
	if err != nil {
		t.Fatalf("an empty delta must not error, got %v", err)
	}
	if out != desired {
		t.Error("an empty delta should return the desired resource unchanged")
	}
}

// fakeReconciler stubs only the two Reconciler methods these hooks use. The interface is embedded
// so the type satisfies acktypes.Reconciler; anything else panics if called, which is the intent —
// a test that reaches an unexpected method should fail loudly.
type fakeReconciler struct {
	acktypes.Reconciler
	secretValue string
	secretErr   error
	writes      []string
	writeErr    error
}

func (f *fakeReconciler) SecretValueFromReference(_ context.Context, _ *ackv1alpha1.SecretKeyReference) (string, error) {
	return f.secretValue, f.secretErr
}

func (f *fakeReconciler) WriteToSecret(_ context.Context, value, namespace, name, key string) error {
	f.writes = append(f.writes, fmt.Sprintf("%s/%s[%s]", namespace, name, key))
	return f.writeErr
}

func eabWithOutput(namespace, secretNamespace string) *svcapitypes.AcmeExternalAccountBinding {
	eab := &svcapitypes.AcmeExternalAccountBinding{}
	eab.Namespace = namespace
	eab.Spec.CredentialsOutput = &ackv1alpha1.SecretKeyReference{Key: "macKey"}
	eab.Spec.CredentialsOutput.Name = "eab-creds"
	eab.Spec.CredentialsOutput.Namespace = secretNamespace
	return eab
}

// A Secret that cannot be READ is not the same as a Secret that is ABSENT. Treating every error as
// "absent" made the read path re-fetch the credential from AWS and re-patch the Secret on every
// reconcile — for ever, while still reporting the resource Synced. Raised in review on #115.
func TestNeedsCredentialsOnlyStoresWhenTheSecretIsAbsent(t *testing.T) {
	for _, tc := range []struct {
		name      string
		value     string
		keyID     string
		err       error
		wantNeeds bool
		wantErr   bool
	}{
		{name: "absent secret or key", err: ackerr.SecretNotFound, wantNeeds: true},
		{name: "present but empty", value: "", wantNeeds: true},
		// Populated Secret AND a recorded keyID: nothing to do. Both halves matter — a
		// populated Secret with no status.keyID still needs the store, which is what makes
		// the self-heal work for a binding created before credentialsOutput was added.
		{name: "present and populated, keyID recorded", value: "abc", keyID: "kid", wantNeeds: false},
		{name: "present and populated, keyID missing", value: "abc", wantNeeds: true},
		// The two cases the reviewer named. Neither means "absent", so neither may trigger a
		// re-fetch; both must surface instead.
		{name: "non-Opaque secret", err: ackerr.SecretTypeNotSupported, wantErr: true},
		{name: "cross-namespace refused", err: ackerr.NewTerminalError(errors.New("nope")), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rm := &resourceManager{rr: &fakeReconciler{secretValue: tc.value, secretErr: tc.err}}
			eab := eabWithOutput("app", "")
			if tc.keyID != "" {
				eab.Status.KeyID = &tc.keyID
			}
			needs, err := rm.needsCredentials(context.Background(), eab)
			if tc.wantErr {
				if err == nil {
					t.Fatal("an unreadable Secret must surface an error, not be treated as absent")
				}
				if needs {
					t.Fatal("an unreadable Secret must not trigger a credential re-fetch from AWS")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if needs != tc.wantNeeds {
				t.Fatalf("needsCredentials = %v, want %v", needs, tc.wantNeeds)
			}
		})
	}
}

// A write is not a read. rr.WriteToSecret takes a raw namespace and validates nothing, so before
// this guard a credentialsOutput naming another namespace would have placed the MAC key there even
// with --enable-cross-namespace=false — a write primitive across a boundary the operator had
// explicitly closed. The guard uses the runtime's own validator, so the write obeys exactly the
// policy SecretValueFromReference applies to reads. Raised in review on #115.
//
// sdkapi is deliberately left nil. The validation runs before the credentials are fetched, so this
// test passes without an AWS client — and if that ordering is ever reversed, it panics rather than
// quietly burning a GetAcmeExternalAccountBindingCredentials call on a path that cannot succeed.
func TestStoreCredentialsRefusesCrossNamespaceWriteUnlessEnabled(t *testing.T) {
	arn := ackv1alpha1.AWSResourceName(
		"arn:aws:acm:us-east-1:111122223333:acme-endpoint/e/acme-external-account-binding/b")

	t.Run("refused when the operator has not enabled it", func(t *testing.T) {
		rr := &fakeReconciler{}
		rm := &resourceManager{rr: rr} // cfg zero value: EnableCrossNamespace is false
		eab := eabWithOutput("app", "other-namespace")
		eab.Status.ACKResourceMetadata = &ackv1alpha1.ResourceMetadata{ARN: &arn}

		err := rm.storeEABCredentials(context.Background(), eab)
		if err == nil {
			t.Fatal("a cross-namespace credentials target must be refused when the flag is off")
		}
		var terminal *ackerr.TerminalError
		if !errors.As(err, &terminal) {
			t.Fatalf("the refusal must be terminal, not retried for ever: %T %v", err, err)
		}
		if len(rr.writes) != 0 {
			t.Fatalf("nothing may be written to a Secret in a refused namespace, got %v", rr.writes)
		}
		if !strings.Contains(err.Error(), "other-namespace") {
			t.Fatalf("the error must name the namespace so a user can act on it: %v", err)
		}
	})

	t.Run("same namespace is always allowed", func(t *testing.T) {
		// An empty credentialsOutput.namespace means the resource's own namespace, which the
		// validator resolves rather than refusing. Proven by reaching the AWS call: with a nil
		// sdkapi that panics, so a recovered panic here is the evidence that validation passed.
		rm := &resourceManager{rr: &fakeReconciler{}}
		eab := eabWithOutput("app", "")
		eab.Status.ACKResourceMetadata = &ackv1alpha1.ResourceMetadata{ARN: &arn}

		defer func() {
			if recover() == nil {
				t.Fatal("expected to reach the credentials fetch, which means validation allowed the write")
			}
		}()
		_ = rm.storeEABCredentials(context.Background(), eab)
	})
}

// rr.WriteToSecret validates neither the target Secret's namespace nor its TYPE, while the read path
// accepts only Opaque. The MAC key could therefore be written into, say, a kubernetes.io/tls Secret
// and the very next read would refuse to read it back: a live credential left in a Secret this
// controller will not touch again, and a resource Terminal for a reason that describes the symptom
// rather than the target. Raised in review on #115 and reproduced against a cluster before this
// guard existed — the MAC key landed in a kubernetes.io/tls Secret alongside tls.crt, and the
// binding reported Synced=True while it did.
//
// sdkapi is deliberately left nil, as in the cross-namespace test above: the refusal must happen
// BEFORE the credentials are fetched, so this test passes with no AWS client at all — and if that
// ordering is ever reversed, it panics rather than quietly burning a credentials call on a path that
// cannot succeed.
func TestStoreCredentialsRefusesANonOpaqueSecret(t *testing.T) {
	arn := ackv1alpha1.AWSResourceName(
		"arn:aws:acm:us-east-1:111122223333:acme-endpoint/e/acme-external-account-binding/b")

	t.Run("a non-Opaque target is refused, terminally, with nothing written", func(t *testing.T) {
		rr := &fakeReconciler{secretErr: ackerr.SecretTypeNotSupported}
		rm := &resourceManager{rr: rr}
		eab := eabWithOutput("app", "")
		eab.Status.ACKResourceMetadata = &ackv1alpha1.ResourceMetadata{ARN: &arn}

		err := rm.storeEABCredentials(context.Background(), eab)
		if err == nil {
			t.Fatal("a Secret the read path cannot read must be refused before the credential is written")
		}
		var terminal *ackerr.TerminalError
		if !errors.As(err, &terminal) {
			t.Fatalf("the refusal must be terminal: no retry changes a Secret's type: %T %v", err, err)
		}
		if len(rr.writes) != 0 {
			t.Fatalf("no credential may be written to a Secret that cannot be read back, got %v", rr.writes)
		}
		if !strings.Contains(err.Error(), "eab-creds") {
			t.Fatalf("the error must name the Secret so a user can act on it: %v", err)
		}
		if eab.Status.KeyID != nil {
			t.Fatalf("status.keyID must not be recorded when nothing was stored, got %v", *eab.Status.KeyID)
		}
	})

	t.Run("an absent key is NOT refused — it is the ordinary state before the first write", func(t *testing.T) {
		// ackerr.SecretNotFound is what the read path returns for a Secret that exists without
		// the key yet, which is exactly the situation every first write starts from. Refusing it
		// would make the resource terminal instead of storing the credential. Proven by reaching
		// the AWS call: sdkapi is nil, so a recovered panic is the evidence that we proceeded.
		rm := &resourceManager{rr: &fakeReconciler{secretErr: ackerr.SecretNotFound}}
		eab := eabWithOutput("app", "")
		eab.Status.ACKResourceMetadata = &ackv1alpha1.ResourceMetadata{ARN: &arn}

		defer func() {
			if recover() == nil {
				t.Fatal("an absent key must not be treated as a bad Secret type; expected to reach the credentials fetch")
			}
		}()
		_ = rm.storeEABCredentials(context.Background(), eab)
	})
}
