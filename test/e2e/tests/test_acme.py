# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
#	 http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

"""Integration tests for the ACM ACME resources
"""

import time
import os
import pytest

from typing import Dict, Tuple
from kubernetes import client
from acktest.k8s import resource as k8s
from acktest.resources import random_suffix_name
from acktest import tags
from e2e import service_marker, CRD_GROUP, CRD_VERSION, load_resource
from e2e.replacement_values import REPLACEMENT_VALUES
from e2e.bootstrap_resources import get_bootstrap_resources

ACME_ENDPOINT_PLURAL = 'acmeendpoints'
ACME_DOMAIN_VALIDATION_PLURAL = 'acmedomainvalidations'
ACME_EAB_PLURAL = 'acmeexternalaccountbindings'

# AcmeEndpoint goes CREATING -> ACTIVE, requeue is 30s
CREATE_ENDPOINT_WAIT_SECONDS = 35
# Domain validation goes VALIDATING -> VALID/INVALID, can take 60s+
CREATE_DOMAIN_VALIDATION_WAIT_SECONDS = 65
# EAB creation also fetches credentials and writes the Secret
CREATE_EAB_WAIT_SECONDS = 65
# Time to allow an update (tag sync / field patch) to reconcile
UPDATE_WAIT_SECONDS = 35
# A credential repair happens on the resource's next read, so allow for more than one requeue
REPAIR_WAIT_SECONDS = 120
# ACM ACME only lets internal AWS accounts validate .people.aws.dev subdomains
DOMAIN_VALIDATION_PARENT_DOMAIN = 'people.aws.dev'


def _aws_resource_tags(acm_client, resource_arn: str) -> Dict[str, str]:
    """Returns the AWS-side tags for a resource ARN as a {key: value} dict,
    using the standardized ListTagsForResource API (the source of truth)."""
    resp = acm_client.list_tags_for_resource(ResourceArn=resource_arn)
    return {t["Key"]: t.get("Value") for t in resp.get("Tags", [])}


@pytest.fixture
def acme_endpoint(request) -> Tuple[k8s.CustomResourceReference, Dict]:
    endpoint_name = random_suffix_name("acme-endpoint", 20)

    replacements = REPLACEMENT_VALUES.copy()
    replacements['ACME_ENDPOINT_NAME'] = endpoint_name

    resource_data = load_resource(
        "acme_endpoint",
        additional_replacements=replacements,
    )

    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, ACME_ENDPOINT_PLURAL,
        endpoint_name, namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    time.sleep(CREATE_ENDPOINT_WAIT_SECONDS)

    yield (ref, cr)

    try:
        _, deleted = k8s.delete_custom_resource(ref, 3, 10)
        assert deleted
    except:
        pass


@service_marker
class TestAcmeEndpoint:
    def test_create_delete(self, acme_endpoint, acm_client):
        (ref, cr) = acme_endpoint

        # Poll for the resource to become synced (the endpoint is ACTIVE
        # once the synced condition is True) to avoid timing inconsistencies.
        assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=3)

        # Re-read to get updated status
        cr = k8s.get_resource(ref)
        assert cr is not None

        # Verify the endpoint reached ACTIVE status
        assert cr["status"].get("status") == "ACTIVE", \
            f"Expected ACTIVE, got {cr['status'].get('status')}"

        # Verify endpointURL is populated
        endpoint_url = cr["status"].get("endpointURL")
        assert endpoint_url is not None, "endpointURL should be set"
        assert "acm-acme" in endpoint_url, \
            f"endpointURL should contain 'acm-acme', got: {endpoint_url}"

        # Verify ARN is set
        arn = cr["status"]["ackResourceMetadata"]["arn"]
        assert arn is not None
        assert "acme-endpoint" in arn

        # Verify against AWS (the source of truth) that the endpoint the
        # controller reports actually matches what ACM has.
        aws = acm_client.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        assert aws["Status"] == cr["status"]["status"], \
            f"AWS status {aws['Status']} != CR status {cr['status']['status']}"
        assert aws["EndpointUrl"] == endpoint_url, \
            f"AWS endpointURL {aws['EndpointUrl']} != CR {endpoint_url}"
        assert aws["Contact"] == cr["spec"]["contact"]

        # Verify the create-time tag actually landed on the AWS resource.
        aws_tags = _aws_resource_tags(acm_client, arn)
        assert aws_tags is not None
        tags.assert_equal_without_ack_tags(
            expected={"environment": "dev"}, actual=aws_tags,
        )

    def test_update(self, acme_endpoint, acm_client):
        (ref, cr) = acme_endpoint
        cr = k8s.get_resource(ref)
        arn = cr["status"]["ackResourceMetadata"]["arn"]

        # Update a non-tag mutable field (contact) to exercise the
        # UpdateAcmeEndpoint path, and simultaneously rewrite the tag set
        # (remove "environment", add "team") to exercise tag sync
        # (TagResource + UntagResource).
        updates = {
            "spec": {
                "contact": "REQUIRED",
                "certificateAuthority": {
                    "publicCertificateAuthority": {
                        "allowedKeyAlgorithms": ["RSA_2048", "EC_prime256v1"],
                    },
                },
                "tags": [{"key": "team", "value": "platform"}],
            }
        }
        k8s.patch_custom_resource(ref, updates)
        time.sleep(UPDATE_WAIT_SECONDS)

        # The update should reconcile fully and return to a synced state.
        assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=3)

        # Verify against AWS that both the field update and the tag sync
        # reached ACM.
        aws = acm_client.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        assert aws["Contact"] == "REQUIRED", \
            f"expected AWS contact REQUIRED, got {aws['Contact']}"

        aws_algorithms = aws.get("CertificateAuthority", {}) \
            .get("PublicCertificateAuthority", {}).get("AllowedKeyAlgorithms")
        assert aws_algorithms == ["RSA_2048", "EC_prime256v1"], \
            f"expected updated allowedKeyAlgorithms on AWS, got {aws_algorithms}"

        aws_tags = _aws_resource_tags(acm_client, arn)
        # The user-managed tag set was rewritten: "team" added, "environment"
        # removed. assert_equal_without_ack_tags ignores ACK's own
        # services.k8s.aws/* tags and asserts the user tag set matches exactly
        # (mirrors the tag assertions in test_certificate.py).
        tags.assert_equal_without_ack_tags(
            expected={"team": "platform"}, actual=aws_tags,
        )


@pytest.fixture
def acme_domain_validation(request, acme_endpoint) -> Tuple[k8s.CustomResourceReference, Dict]:
    """Creates an AcmeEndpoint and then a DomainValidation for it."""
    (endpoint_ref, endpoint_cr) = acme_endpoint

    # Re-read endpoint to get ARN
    endpoint_cr = k8s.get_resource(endpoint_ref)
    endpoint_arn = endpoint_cr["status"]["ackResourceMetadata"]["arn"]

    validation_name = random_suffix_name("acme-dv", 20)
    domain_name = f"{validation_name}.{DOMAIN_VALIDATION_PARENT_DOMAIN}"

    replacements = REPLACEMENT_VALUES.copy()
    replacements['ACME_DOMAIN_VALIDATION_NAME'] = validation_name
    replacements['ACME_ENDPOINT_ARN'] = endpoint_arn
    replacements['DOMAIN_NAME'] = domain_name

    resource_data = load_resource(
        "acme_domain_validation",
        additional_replacements=replacements,
    )

    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, ACME_DOMAIN_VALIDATION_PLURAL,
        validation_name, namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    time.sleep(CREATE_DOMAIN_VALIDATION_WAIT_SECONDS)

    yield (ref, cr)

    try:
        _, deleted = k8s.delete_custom_resource(ref, 3, 10)
        assert deleted
    except:
        pass


def _wait_for_settled_dv_status(ref, timeout_seconds: int = 90) -> str:
    """Polls a domain validation until its status settles (VALID or INVALID).

    We poll status.status rather than waiting on ACK.ResourceSynced: only VALID
    is configured as synced, because an INVALID validation is an unhealthy
    (but recoverable) domain that the runtime keeps re-checking every 30s, so it
    reports Synced=False even though the controller reconciled correctly.
    """
    deadline = time.time() + timeout_seconds
    status = None
    while time.time() < deadline:
        cr = k8s.get_resource(ref)
        status = (cr or {}).get("status", {}).get("status")
        if status in ("VALID", "INVALID"):
            return status
        time.sleep(5)
    pytest.fail(f"domain validation never settled; last status={status}")


@service_marker
class TestAcmeDomainValidation:
    def test_create_delete(self, acme_domain_validation, acm_client):
        (ref, cr) = acme_domain_validation

        # Poll until the validation settles. The domain has no DNS records, so
        # it lands INVALID.
        status = _wait_for_settled_dv_status(ref)

        # Re-read to get updated status
        cr = k8s.get_resource(ref)
        assert cr is not None

        # Verify ARN is set
        arn = cr["status"]["ackResourceMetadata"]["arn"]
        assert arn is not None

        # Verify against AWS (the source of truth) that the domain validation
        # exists, its status agrees, and the create-time tag landed.
        aws = acm_client.describe_acme_domain_validation(
            AcmeDomainValidationArn=arn,
        )["AcmeDomainValidation"]
        assert aws["Status"] == status, \
            f"AWS status {aws['Status']} != CR status {status}"
        aws_tags = _aws_resource_tags(acm_client, arn)
        assert aws_tags is not None
        tags.assert_equal_without_ack_tags(
            expected={"environment": "dev"}, actual=aws_tags,
        )

    def test_update(self, acme_domain_validation, acm_client):
        (ref, cr) = acme_domain_validation
        cr = k8s.get_resource(ref)
        arn = cr["status"]["ackResourceMetadata"]["arn"]

        # Update the mutable prevalidationOptions (disable wildcards) to
        # exercise UpdateAcmeDomainValidation, and rewrite the tag set
        # (remove "environment", add "team") to exercise tag sync.
        updates = {
            "spec": {
                "prevalidationOptions": {
                    "dnsPrevalidation": {
                        "domainScope": {
                            "exactDomain": "ENABLED",
                            "subdomains": "ENABLED",
                            "wildcards": "DISABLED",
                        },
                    },
                },
                "tags": [{"key": "team", "value": "platform"}],
            }
        }
        k8s.patch_custom_resource(ref, updates)
        time.sleep(UPDATE_WAIT_SECONDS)

        # The update should reconcile fully and the validation should settle
        # again (INVALID). Note ACK.ResourceSynced is only True for VALID, so we
        # poll the status instead of the condition.
        _wait_for_settled_dv_status(ref)

        # Verify against AWS. The describe response reports the effective
        # prevalidation state in PrevalidationDetails.
        aws = acm_client.describe_acme_domain_validation(
            AcmeDomainValidationArn=arn,
        )["AcmeDomainValidation"]
        scope = aws.get("PrevalidationDetails", {}) \
            .get("DnsPrevalidation", {}).get("DomainScope", {})
        assert scope.get("Wildcards") == "DISABLED", \
            f"expected wildcards DISABLED on AWS, got {scope}"

        aws_tags = _aws_resource_tags(acm_client, arn)
        tags.assert_equal_without_ack_tags(
            expected={"team": "platform"}, actual=aws_tags,
        )


def _eab_role_arn() -> str:
    """Returns the EAB issuance role ARN from the bootstrapped resources,
    falling back to the ACME_ROLE_ARN environment variable for local runs."""
    env_arn = os.environ.get("ACME_ROLE_ARN")
    if env_arn:
        return env_arn
    return get_bootstrap_resources().EABRole.arn


@pytest.fixture
def acme_endpoint_with_eab(request, acme_endpoint) -> Tuple[k8s.CustomResourceReference, Dict, str]:
    """Creates an AcmeEndpoint and then an EAB for it."""
    (endpoint_ref, endpoint_cr) = acme_endpoint

    # Re-read endpoint to get ARN
    endpoint_cr = k8s.get_resource(endpoint_ref)
    endpoint_arn = endpoint_cr["status"]["ackResourceMetadata"]["arn"]

    eab_name = random_suffix_name("acme-eab", 20)
    secret_name = eab_name + "-credentials"

    # The controller populates an existing Secret with the EAB credentials; it
    # does not create one. Users are expected to create the Secret first (same
    # pattern as the Certificate exportTo field).
    v1 = client.CoreV1Api(k8s._get_k8s_api_client())
    secret_body = client.V1Secret(
        metadata=client.V1ObjectMeta(name=secret_name, namespace="default"),
        type="Opaque",
    )
    v1.create_namespaced_secret("default", secret_body)

    replacements = REPLACEMENT_VALUES.copy()
    replacements['ACME_EAB_NAME'] = eab_name
    replacements['ACME_EAB_SECRET_NAME'] = secret_name
    replacements['ACME_ENDPOINT_ARN'] = endpoint_arn
    replacements['ROLE_ARN'] = _eab_role_arn()

    resource_data = load_resource(
        "acme_external_account_binding",
        additional_replacements=replacements,
    )

    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, ACME_EAB_PLURAL,
        eab_name, namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    time.sleep(CREATE_EAB_WAIT_SECONDS)

    yield (ref, cr, endpoint_arn)

    # The delete assertion must be able to fail the suite. A binding that will not delete leaves a
    # usable EAB credential live in ACM, which is precisely what a test should catch; a bare
    # `except: pass` here swallowed the assertion and reported success. Raised in review on #115.
    #
    # The Secret cleanup runs in `finally`, so a failed CR delete does not also leak the Secret.
    try:
        _, deleted = k8s.delete_custom_resource(ref, 3, 10)
        assert deleted, (
            f"external account binding {eab_name} was not deleted; an EAB credential may still be "
            "live in ACM"
        )
    finally:
        try:
            v1.delete_namespaced_secret(secret_name, "default")
        except Exception as e:
            # Already absent is fine. Anything else is a real failure and must not be hidden.
            if getattr(e, "status", None) != 404:
                raise


@service_marker
class TestAcmeExternalAccountBinding:
    def test_create_delete_and_credentials_secret(self, acme_endpoint_with_eab, acm_client):
        (ref, cr, endpoint_arn) = acme_endpoint_with_eab

        assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=3)

        # Re-read to get updated status
        cr = k8s.get_resource(ref)
        assert cr is not None

        # Verify ARN is set
        arn = cr["status"]["ackResourceMetadata"]["arn"]
        assert arn is not None
        assert "acme-external-account-binding" in arn

        # Verify the key identifier is surfaced in status for ACME clients
        key_id_status = cr["status"].get("keyID")
        assert key_id_status is not None, "status.keyID should be set"
        assert len(key_id_status) > 0, "status.keyID should not be empty"

        # Verify the actual K8s Secret was populated with the credentials.
        # The sensitive macKey is written under the user-specified key, and the
        # keyId is written under a fixed "keyId" key.
        secret_name = cr["spec"]["credentialsOutput"]["name"]
        secret_namespace = cr["spec"]["credentialsOutput"].get("namespace", "default")
        mac_key_field = cr["spec"]["credentialsOutput"]["key"]

        v1 = client.CoreV1Api(k8s._get_k8s_api_client())
        secret = v1.read_namespaced_secret(secret_name, secret_namespace)
        assert secret is not None, f"Secret {secret_name} should exist"
        assert "keyId" in secret.data, "Secret should contain keyId"
        assert mac_key_field in secret.data, f"Secret should contain macKey under '{mac_key_field}'"
        assert len(secret.data["keyId"]) > 0
        assert len(secret.data[mac_key_field]) > 0

        # Verify against AWS (the source of truth) that the EAB exists and the
        # create-time tag landed.
        aws = acm_client.describe_acme_external_account_binding(
            AcmeExternalAccountBindingArn=arn,
        )["ExternalAccountBinding"]
        assert aws["AcmeExternalAccountBindingArn"] == arn
        aws_tags = _aws_resource_tags(acm_client, arn)
        tags.assert_equal_without_ack_tags(
            expected={"environment": "dev"}, actual=aws_tags,
        )

    def test_credentials_are_repaired_when_the_secret_is_emptied(self, acme_endpoint_with_eab):
        """Removing the stored credentials must heal: the controller re-writes both keys.

        The read path deliberately checks the Secret rather than trusting status.keyID so that a
        binding whose credentials never reached the Secret — or whose Secret was emptied later —
        recovers without user action. Nothing exercised the SUCCESSFUL repair until now, only the
        classification of a Secret that cannot be read; a reviewer had to verify this by hand on
        #115, which is the argument for the test.

        There is no API call here on purpose: the credential in ACM never changed, so the whole
        assertion is about what the controller puts back into Kubernetes.
        """
        (ref, cr, _endpoint_arn) = acme_endpoint_with_eab

        assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=3)

        cr = k8s.get_resource(ref)
        secret_name = cr["spec"]["credentialsOutput"]["name"]
        secret_namespace = cr["spec"]["credentialsOutput"].get("namespace", "default")
        mac_key_field = cr["spec"]["credentialsOutput"]["key"]

        v1 = client.CoreV1Api(k8s._get_k8s_api_client())
        before = v1.read_namespaced_secret(secret_name, secret_namespace)
        assert mac_key_field in (before.data or {}), "the credentials must be stored before we remove them"

        # Remove both credential keys, leaving the Secret itself in place: the controller patches
        # an existing Secret and does not create one, so deleting it would test a different path
        # (which test_delete_after_secret_removed already covers).
        v1.patch_namespaced_secret(
            secret_name, secret_namespace,
            {"data": {mac_key_field: None, "keyId": None}},
        )
        emptied = v1.read_namespaced_secret(secret_name, secret_namespace).data or {}
        assert mac_key_field not in emptied, "the credential must actually be gone for this to prove anything"

        healed = {}
        deadline = time.time() + REPAIR_WAIT_SECONDS
        while time.time() < deadline:
            time.sleep(10)
            data = v1.read_namespaced_secret(secret_name, secret_namespace).data or {}
            if mac_key_field in data and "keyId" in data:
                healed = data
                break

        assert mac_key_field in healed, (
            f"the controller did not restore the MAC key to {secret_namespace}/{secret_name} "
            f"within {REPAIR_WAIT_SECONDS}s; the credential repair on the read path did not run"
        )
        assert "keyId" in healed, "the key identifier must be restored alongside the MAC key"
        assert len(healed[mac_key_field]) > 0
        assert len(healed["keyId"]) > 0

        # The resource must remain healthy throughout: a repair is normal operation, not an error.
        assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=3)

    def test_no_credentials_output_still_reports_key_id(self, acme_endpoint):
        """An EAB without credentialsOutput must still surface status.keyID.

        The key identifier is not sensitive and an ACME client needs it to register an
        account, so it belongs in status whether or not a Secret was requested. This is
        also the only path that exercises storeEABCredentials with no Secret write.
        """
        (endpoint_ref, _) = acme_endpoint
        endpoint_arn = k8s.get_resource(endpoint_ref)["status"]["ackResourceMetadata"]["arn"]
        role_arn = _eab_role_arn()

        eab_name = random_suffix_name("acme-eab-nosecret", 32)
        body = {
            "apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
            "kind": "AcmeExternalAccountBinding",
            "metadata": {"name": eab_name},
            "spec": {"acmeEndpointARN": endpoint_arn, "roleARN": role_arn},
        }
        ref = k8s.CustomResourceReference(
            CRD_GROUP, CRD_VERSION, ACME_EAB_PLURAL, eab_name, namespace="default",
        )
        k8s.create_custom_resource(ref, body)
        time.sleep(CREATE_EAB_WAIT_SECONDS)

        assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=3)
        cr = k8s.get_resource(ref)
        assert cr["status"].get("keyID"), "status.keyID must be set even with no credentialsOutput"

        _, deleted = k8s.delete_custom_resource(ref, wait_periods=6, period_length=10)
        assert deleted

    def test_delete_after_secret_removed(self, acme_endpoint, acm_client):
        """Deleting the credentials Secret before the CR must not block deletion.

        The runtime's delete path calls ReadOne first and abandons the delete on any error
        other than NotFound, so a credential repair attempted during deletion would leave
        the CR in Terminating for ever and the binding live in ACM. This is the ordering a
        namespace deletion or a GitOps prune produces, because the Secret has no finalizer.
        """
        (endpoint_ref, _) = acme_endpoint
        endpoint_arn = k8s.get_resource(endpoint_ref)["status"]["ackResourceMetadata"]["arn"]
        role_arn = _eab_role_arn()

        secret_name = random_suffix_name("acme-eab-secret", 32)
        eab_name = random_suffix_name("acme-eab-del", 32)
        # The api client must come from the test harness. A bare client.CoreV1Api() has no
        # kubeconfig and silently targets localhost:80, which is how this failed in CI.
        k8s_client = client.CoreV1Api(k8s._get_k8s_api_client())
        k8s_client.create_namespaced_secret(
            namespace="default",
            body=client.V1Secret(metadata=client.V1ObjectMeta(name=secret_name), type="Opaque"),
        )

        body = {
            "apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
            "kind": "AcmeExternalAccountBinding",
            "metadata": {"name": eab_name},
            "spec": {
                "acmeEndpointARN": endpoint_arn,
                "roleARN": role_arn,
                "credentialsOutput": {"namespace": "default", "name": secret_name, "key": "macKey"},
            },
        }
        ref = k8s.CustomResourceReference(
            CRD_GROUP, CRD_VERSION, ACME_EAB_PLURAL, eab_name, namespace="default",
        )
        k8s.create_custom_resource(ref, body)
        time.sleep(CREATE_EAB_WAIT_SECONDS)
        assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=3)
        eab_arn = k8s.get_resource(ref)["status"]["ackResourceMetadata"]["arn"]

        # The Secret goes FIRST, as it would in a namespace deletion.
        k8s_client.delete_namespaced_secret(name=secret_name, namespace="default")

        _, deleted = k8s.delete_custom_resource(ref, wait_periods=9, period_length=10)
        assert deleted, "the CR must delete even though its credentials Secret is gone"

        # And the binding must be gone from ACM, not merely from Kubernetes.
        with pytest.raises(acm_client.exceptions.ResourceNotFoundException):
            acm_client.describe_acme_external_account_binding(
                AcmeExternalAccountBindingArn=eab_arn,
            )

    def test_update_tags(self, acme_endpoint_with_eab, acm_client):
        (ref, cr, endpoint_arn) = acme_endpoint_with_eab
        cr = k8s.get_resource(ref)
        arn = cr["status"]["ackResourceMetadata"]["arn"]

        # The EAB has no service-side update operation; its sdkUpdate is a
        # custom method that reconciles only tags via TagResource/UntagResource.
        # Rewrite the tag set (remove "environment", add "team") and verify the
        # change reaches AWS.
        k8s.patch_custom_resource(
            ref, {"spec": {"tags": [{"key": "team", "value": "platform"}]}},
        )
        time.sleep(UPDATE_WAIT_SECONDS)

        # The update should reconcile fully and return to a synced state.
        assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=3)

        aws_tags = _aws_resource_tags(acm_client, arn)
        tags.assert_equal_without_ack_tags(
            expected={"team": "platform"}, actual=aws_tags,
        )
