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

	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackerr "github.com/aws-controllers-k8s/runtime/pkg/errors"
	ackrequeue "github.com/aws-controllers-k8s/runtime/pkg/requeue"
	ackrt "github.com/aws-controllers-k8s/runtime/pkg/runtime"

	svcapitypes "github.com/aws-controllers-k8s/acm-controller/apis/v1alpha1"
	svcsdk "github.com/aws/aws-sdk-go-v2/service/acm"

	"github.com/aws-controllers-k8s/acm-controller/pkg/tags"
)

// syncTags and listTags manage resource tags via the standardized ACM
// TagResource/UntagResource/ListTagsForResource operations. They are wired
// into the generated sdkFind flow via a hook template and into sdkUpdate via
// customUpdateAcmeExternalAccountBinding below.
var (
	syncTags = tags.SyncResourceTags
	listTags = tags.ListResourceTags
)

// storeEABCredentials fetches the external account binding's credentials and records
// them: the key identifier into status, and the secret MAC key into the Secret named by
// spec.credentialsOutput.
//
// It is called from BOTH create and read. Create is where it normally happens, but the
// credentials fetch and the Secret write can each fail after the binding already exists
// in ACM (a missing Secret, a denied GetAcmeExternalAccountBindingCredentials, a
// throttle). Doing it only on create would leave such a resource reporting Synced with an
// empty Secret and no keyID, with nothing to retry it — so read repairs it, guarded on
// status.keyID so the steady state costs no extra API call.
//
// Any failure here is returned as a REQUEUE, never as an AWS error: the ACK runtime marks
// a resource unmanaged when Create returns an AWS API error (reconciler.go,
// setResourceUnmanaged), which would drop the finalizer while the binding still exists in
// ACM — deleting the CR would then never delete the binding, leaving a live credential
// nobody tracks.
func (rm *resourceManager) storeEABCredentials(
	ctx context.Context,
	ko *svcapitypes.AcmeExternalAccountBinding,
) error {
	if ko.Status.ACKResourceMetadata == nil || ko.Status.ACKResourceMetadata.ARN == nil {
		// Nothing to fetch credentials for yet.
		return nil
	}
	arn := (*string)(ko.Status.ACKResourceMetadata.ARN)
	// Everything that can be decided WITHOUT calling AWS is decided first. Fetching a MAC key
	// and then refusing to write it would burn a credential fetch on a path that cannot succeed,
	// and the refusal is terminal, so the fetch would never have been useful.
	var namespace, name, macKeyKey string
	if ko.Spec.CredentialsOutput != nil {
		if ko.Spec.CredentialsOutput.Name == "" {
			// The schema requires only `key`, so an incomplete reference reaches us here.
			// Terminal rather than a requeue: no amount of retrying fixes a missing name.
			return ackerr.NewTerminalError(
				errors.New("spec.credentialsOutput.name is required in order to write the external account binding credentials"),
			)
		}
		// The namespace is validated with the runtime's own helper, so a write obeys exactly the
		// policy a read does. rr.WriteToSecret takes a raw namespace and performs no validation of
		// its own, which meant a credentialsOutput naming another namespace would have the MAC key
		// written there even with --enable-cross-namespace=false. Reported in review.
		name = ko.Spec.CredentialsOutput.Name
		var err error
		namespace, _, err = ackrt.ValidateCrossNamespaceReferenceString(
			rm.cfg.EnableCrossNamespace,
			ko.Namespace,
			ko.Spec.CredentialsOutput.Namespace,
			name,
		)
		if err != nil {
			// Terminal: the operator has not enabled cross-namespace references, and no amount
			// of retrying changes that. The user must move the Secret or the operator must
			// enable the flag.
			return ackerr.NewTerminalError(err)
		}
		// The target Secret's TYPE is validated here for the same reason its namespace is:
		// rr.WriteToSecret checks neither, while the read path accepts only Opaque. Writing the
		// MAC key into, say, a kubernetes.io/tls Secret therefore SUCCEEDED, and the next read
		// then refused to read it back — leaving a live credential in a Secret this controller
		// will not touch again and the resource Terminal, pointing at the symptom rather than
		// the cause. Reported in review and reproduced against a cluster before this guard
		// existed: the MAC key landed in a kubernetes.io/tls Secret alongside tls.crt.
		//
		// SecretValueFromReference is used purely as the validator, so a write accepts exactly
		// what a read accepts and the two cannot drift apart again. Only the type error is
		// terminal here: ackerr.SecretNotFound is the ordinary state before the first write
		// (the Secret exists but the key does not yet), and a cross-namespace refusal has
		// already been handled above with a message of its own.
		if _, err := rm.rr.SecretValueFromReference(ctx, ko.Spec.CredentialsOutput); errors.Is(
			err, ackerr.SecretTypeNotSupported,
		) {
			return ackerr.NewTerminalError(fmt.Errorf(
				"Secret %s/%s cannot hold the external account binding credentials: %w",
				namespace, name, err,
			))
		}
		macKeyKey = ko.Spec.CredentialsOutput.Key
	}

	resp, err := rm.sdkapi.GetAcmeExternalAccountBindingCredentials(
		ctx, &svcsdk.GetAcmeExternalAccountBindingCredentialsInput{
			AcmeExternalAccountBindingArn: arn,
		})
	rm.metrics.RecordAPICall("READ_ONE", "GetAcmeExternalAccountBindingCredentials", err)
	if err != nil {
		return ackrequeue.NeededAfter(
			// %s, not %w: wrapping would let the runtime see an AWS error and mark the
			// resource unmanaged, dropping the finalizer.
			fmt.Errorf("external account binding created, but its credentials could not be read: %s", err),
			ackrequeue.DefaultRequeueAfterDuration,
		)
	}
	// A binding is only usable with both halves.
	if resp.KeyId == nil || resp.MacKey == nil {
		return ackrequeue.NeededAfter(
			errors.New("GetAcmeExternalAccountBindingCredentials did not return both keyId and macKey"),
			ackrequeue.DefaultRequeueAfterDuration,
		)
	}

	// NOTE: status.keyID is deliberately assigned at the END of this function, after the
	// Secret writes. The ACK runtime patches status even when a reconcile returns an error
	// (reconciler.go, HandleReconcileError -> patchResourceStatus), so assigning it before
	// a write that fails would persist it, and needsCredentials would then see a populated
	// keyID and never retry — leaving the resource Synced with an empty Secret for ever.
	if ko.Spec.CredentialsOutput == nil {
		ko.Status.KeyID = resp.KeyId
		return nil
	}

	// WriteToSecret patches an existing Secret; it does not create one. That is the same
	// contract as Certificate.exportTo.
	if err := rm.rr.WriteToSecret(ctx, *resp.MacKey, namespace, name, macKeyKey); err != nil {
		return ackrequeue.NeededAfter(
			fmt.Errorf("writing the external account binding MAC key to Secret %s/%s: %s", namespace, name, err),
			ackrequeue.DefaultRequeueAfterDuration,
		)
	}
	// The key identifier is also written to the Secret for convenience, under a fixed
	// key — unless the caller chose that key for the MAC key, which must win: the MAC key
	// is the credential, and overwriting it would leave the Secret holding a value that
	// cannot authenticate. status.keyID carries it either way.
	if macKeyKey != "keyId" {
		if err := rm.rr.WriteToSecret(ctx, *resp.KeyId, namespace, name, "keyId"); err != nil {
			return ackrequeue.NeededAfter(
				fmt.Errorf("writing the external account binding key identifier to Secret %s/%s: %s", namespace, name, err),
				ackrequeue.DefaultRequeueAfterDuration,
			)
		}
	}
	// Only now: the credentials are where the user asked for them.
	ko.Status.KeyID = resp.KeyId
	return nil
}

// needsCredentials reports whether the credentials still have to be fetched and stored.
//
// It checks the SECRET, not just status.keyID. Guarding on status alone was not enough: a
// user who adds spec.credentialsOutput to an existing binding, or who deletes or empties
// the Secret, would otherwise never have it (re)populated, because keyID is already set.
// A read of a Secret this controller was pointed at is cheap and involves no AWS call.
func (rm *resourceManager) needsCredentials(
	ctx context.Context,
	ko *svcapitypes.AcmeExternalAccountBinding,
) (bool, error) {
	if ko.Spec.CredentialsOutput == nil {
		// Nothing to store; status.keyID is the only output.
		return ko.Status.KeyID == nil, nil
	}
	val, err := rm.rr.SecretValueFromReference(ctx, ko.Spec.CredentialsOutput)
	switch {
	case errors.Is(err, ackerr.SecretNotFound):
		// The Secret, or the key within it, is absent. This is the self-heal case: the
		// credential was never written, or something removed it.
		return true, nil
	case err != nil:
		// Anything else means we cannot tell whether the credential is stored:
		// ackerr.SecretTypeNotSupported for a non-Opaque Secret, or a terminal error for a
		// cross-namespace reference the operator has not enabled. Treating those as "not
		// stored" would re-fetch from AWS and re-patch on every reconcile, forever, while
		// still reporting the resource Synced. Surface the error instead.
		return false, err
	case val == "":
		// Present but empty: the key exists with no value, so it still needs writing.
		return true, nil
	}
	return ko.Status.KeyID == nil, nil
}

// customUpdateAcmeExternalAccountBinding backs the resource's sdkUpdate. The
// external account binding has no service-side update operation, so the only
// field that can be reconciled after creation is the resource's tag set, which
// is managed through the standardized TagResource/UntagResource API. Any change
// to another field is rejected as a terminal error.
func (rm *resourceManager) customUpdateAcmeExternalAccountBinding(
	ctx context.Context,
	desired *resource,
	latest *resource,
	delta *ackcompare.Delta,
) (*resource, error) {
	if delta.DifferentAt("Spec.Tags") {
		if desired.ko.Status.ACKResourceMetadata == nil || desired.ko.Status.ACKResourceMetadata.ARN == nil {
			return nil, ackerr.NotFound
		}
		if err := syncTags(
			ctx, rm.sdkapi, rm.metrics,
			string(*desired.ko.Status.ACKResourceMetadata.ARN),
			desired.ko.Spec.Tags, latest.ko.Spec.Tags,
		); err != nil {
			return nil, err
		}
	}
	if !delta.DifferentExcept("Spec.Tags") {
		return desired, nil
	}
	return nil, ackerr.NewTerminalError(
		errors.New("only tags can be updated for an external account binding"),
	)
}
