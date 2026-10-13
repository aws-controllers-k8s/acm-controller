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

"""Integration tests for the ACM API Certificate resource
"""

import time
import base64
import boto3
import pytest

from typing import Dict, Tuple
from kubernetes import client
from acktest.k8s import resource as k8s, condition
from acktest.resources import random_suffix_name
from e2e import service_marker, CRD_GROUP, CRD_VERSION, load_resource
from e2e.replacement_values import REPLACEMENT_VALUES
from e2e import certificate
from e2e.x509 import create_x509_certificate
from e2e.bootstrap_resources import get_bootstrap_resources
from acktest import tags

RESOURCE_PLURAL = 'certificates'

# NOTE(jaypipes): requeue_on_success_seconds = 60 for certificates, and in the
# tests we check for Status.Status, which will only appear after a successful
# Describe
CREATE_WAIT_AFTER_SECONDS = 65
FAILED_WAIT_AFTER_SECONDS = 60
DELETE_WAIT_AFTER_SECONDS = 30

# Time we wait for the certificate to get to ACK.ResourceSynced=True
MAX_WAIT_FOR_SYNCED_MINUTES = 1

EXPORTED_SERIAL_ANNOTATION = "acm.services.k8s.aws/exported-serial"
MAX_WAIT_FOR_EXPORT_SECONDS = 60*5
MAX_WAIT_FOR_RENEWAL_SECONDS = 60*10
WAIT_INTERVAL_SECONDS = 10


@pytest.fixture
def certificate_public(request) -> Tuple[k8s.CustomResourceReference, Dict]:
    certificate_name = random_suffix_name("certificate", 20)
    domain_name = "example.com"

    replacements = REPLACEMENT_VALUES.copy()
    replacements['CERTIFICATE_NAME'] = certificate_name
    replacements['DOMAIN_NAME'] = domain_name

    resource_data = load_resource(
        request.param,
        additional_replacements=replacements,
    )

    # Create the k8s resource
    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, RESOURCE_PLURAL,
        certificate_name, namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    time.sleep(CREATE_WAIT_AFTER_SECONDS)

    yield (ref, cr)

    # Try to delete, if doesn't already exist
    try:
        _, deleted = k8s.delete_custom_resource(ref, 3, 10)
        assert deleted
        certificate.wait_until_deleted(cr["status"]["ackResourceMetadata"]["arn"])
    except:
        pass


@pytest.fixture
def certificate_import() -> Tuple[k8s.CustomResourceReference, Dict]:
    certificate_name = random_suffix_name("certificate-imported", 30)
    body = client.V1Secret()
    private_key, cert = create_x509_certificate('ACK', 'services.k8s.aws', 'acm.services.k8s.aws')
    body.data = {
        'tls.key': base64.b64encode(private_key).decode('utf-8'),
        'tls.crt': base64.b64encode(cert).decode('utf-8')
    }
    body.metadata = {'name': certificate_name}
    body.type = 'Opaque'
    api_client = k8s_client()
    client.CoreV1Api(api_client).create_namespaced_secret('default', api_client.sanitize_for_serialization(body))

    replacements = REPLACEMENT_VALUES.copy()
    replacements['CERTIFICATE_NAME'] = certificate_name

    resource_data = load_resource(
        'certificate_imported',
        additional_replacements=replacements,
    )

    # Create the k8s resource
    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, RESOURCE_PLURAL,
        certificate_name, namespace='default',
    )
    k8s.create_custom_resource(ref, resource_data)
    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    time.sleep(CREATE_WAIT_AFTER_SECONDS)

    yield ref, cr

    try:
        _, deleted = k8s.delete_custom_resource(ref, 3, 10)
        assert deleted
        certificate.wait_until_deleted(cr['status']['ackResourceMetadata']['arn'])
        k8s.delete_secret('default', certificate_name)
    except:
        pass


@pytest.fixture
def certificate_private_export() -> Tuple[k8s.CustomResourceReference, Dict]:
    certificate_name = random_suffix_name("certificate-export", 30)
    body = client.V1Secret()
    body.data = {'tls.crt': '', 'tls.key': ''}
    body.metadata = {'name': certificate_name}
    body.type = 'kubernetes.io/tls'
    api_client = k8s_client()
    client.CoreV1Api(api_client).create_namespaced_secret('default', api_client.sanitize_for_serialization(body))

    replacements = REPLACEMENT_VALUES.copy()
    replacements['CERTIFICATE_NAME'] = certificate_name
    replacements['DOMAIN_NAME'] = certificate_name + '.ack-e2e.example.com'
    replacements['CERTIFICATE_AUTHORITY_ARN'] = get_bootstrap_resources().PrivateCA.arn

    resource_data = load_resource(
        'certificate_private_export',
        additional_replacements=replacements,
    )

    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, RESOURCE_PLURAL,
        certificate_name, namespace='default',
    )
    try:
        k8s.create_custom_resource(ref, resource_data)
        cr = k8s.wait_resource_consumed_by_controller(ref)
    except:
        k8s.delete_secret('default', certificate_name)
        raise

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    yield ref, cr

    try:
        _, deleted = k8s.delete_custom_resource(ref, 3, 10)
        assert deleted
        certificate.wait_until_deleted(cr['status']['ackResourceMetadata']['arn'])
    except:
        pass
    try:
        k8s.delete_secret('default', certificate_name)
    except:
        pass


@service_marker
@pytest.mark.canary
class TestCertificate:
    @pytest.mark.parametrize('certificate_public', ['certificate_public'], indirect=True)
    def test_crud_public(
            self,
            certificate_public,
    ):
        (ref, cr) = certificate_public
        assert "status" in cr
        assert "ackResourceMetadata" in cr["status"]
        assert "arn" in cr["status"]["ackResourceMetadata"]
        certificate_arn = cr["status"]["ackResourceMetadata"]["arn"]

        assert 'status' in cr['status']
        # NOTE(jaypipes): The certificate request will quickly transition from
        # PENDING_VALIDATION to FAILED, so this just checks to make sure we're
        # in one of those states...
        assert cr['status']['status'] in ['PENDING_VALIDATION', 'FAILED']

        # Wait for the resource to get synced
        assert k8s.wait_on_condition(
            ref,
            "ACK.ResourceSynced",
            "True",
            wait_periods=MAX_WAIT_FOR_SYNCED_MINUTES,
        )

        # NOTE(jaypipes): The domain name is example.com, which will cause the
        # certificate to transition to a FAILED status due to additional
        # verification being needed.
        certificate.wait_until(
            certificate_arn,
            certificate.status_matches("FAILED"),
        )

        time.sleep(FAILED_WAIT_AFTER_SECONDS)

        # The corresponding CR should be updated to a FAILED status as well
        # because we have requeue_on_success_seconds = 60...
        cr = k8s.get_resource(ref)
        assert "status" in cr
        assert 'status' in cr['status']
        assert cr['status']['status'] == 'FAILED'

        expected_tags = [
            {
                "key": "environment",
                "value": "dev"
            },
        ]
        observed_tags = certificate.get_tags(certificate_arn)
        tags_dict = tags.to_dict(
            expected_tags,
            key_member_name="key",
            value_member_name="value"
        )
        tags.assert_equal_without_ack_tags(
            expected=tags_dict,
            actual=observed_tags,
        )

        new_tags = [
            {
                "key": "environment",
                "value": "dev2"
            },
            {
                "key": "key-a",
                "value": "value-a"
            },
            {
                "key": "key-b",
                "value": "value-b"
            },
        ]
        # Update tags
        updates = {
            "spec": {
                "tags": new_tags
            },
        }
        k8s.patch_custom_resource(ref, updates)
        time.sleep(10)

        observed_tags = certificate.get_tags(certificate_arn)
        tags_dict = tags.to_dict(
            new_tags,
            key_member_name="key",
            value_member_name="value"
        )
        tags.assert_equal_without_ack_tags(
            expected=tags_dict,
            actual=observed_tags,
        )

        # Test domainName field is immutable and is rejected by API server
        updates = {
            "spec": {
                "domainName": "new.domain.example.com"
            }
        }
        with pytest.raises(k8s.ApiException) as e:
            k8s.patch_custom_resource(ref, updates)
        assert "Value is immutable once set" in str(e.value.body)

        k8s.delete_custom_resource(ref)
        time.sleep(DELETE_WAIT_AFTER_SECONDS)
        certificate.wait_until_deleted(certificate_arn)

    @pytest.mark.parametrize('certificate_public', ['certificate_public_invalid'], indirect=True)
    def test_invalid(
            self,
            certificate_public,
    ):
        (ref, cr) = certificate_public
        assert 'status' in cr

        cond = k8s.get_resource_condition(ref, condition.CONDITION_TYPE_TERMINAL)
        assert cond is not None
        assert cond == {
            'message': 'Too many domain validation errors',
            'status': 'True',
            'type': condition.CONDITION_TYPE_TERMINAL,
        }

    @pytest.mark.parametrize('certificate_public', ['certificate_with_key_algorithm'], indirect=True)
    def test_key_algorithm_normalization(
            self,
            certificate_public,
    ):
        """Test that KeyAlgorithm with underscores is preserved after sync.

        This test verifies that when a user specifies keyAlgorithm as RSA_2048
        (with underscores), the controller normalizes the AWS API response
        (which uses dashes like RSA-2048) back to underscores, preventing
        infinite reconciliation loops.
        """
        (ref, cr) = certificate_public
        assert "status" in cr
        assert "ackResourceMetadata" in cr["status"]
        assert "arn" in cr["status"]["ackResourceMetadata"]
        certificate_arn = cr["status"]["ackResourceMetadata"]["arn"]

        # Wait for the resource to get synced
        assert k8s.wait_on_condition(
            ref,
            "ACK.ResourceSynced",
            "True",
            wait_periods=MAX_WAIT_FOR_SYNCED_MINUTES,
        )

        # Verify the keyAlgorithm field maintains underscore format after sync
        cr = k8s.get_resource(ref)
        assert "spec" in cr
        assert "keyAlgorithm" in cr["spec"]
        # The keyAlgorithm should remain RSA_2048 (with underscores), not RSA-2048
        assert cr["spec"]["keyAlgorithm"] == "RSA_2048", \
            f"Expected keyAlgorithm to be 'RSA_2048' but got '{cr['spec']['keyAlgorithm']}'"

        k8s.delete_custom_resource(ref)
        time.sleep(DELETE_WAIT_AFTER_SECONDS)
        certificate.wait_until_deleted(certificate_arn)

    def test_import_certificate(
            self,
            certificate_import,
    ):
        (ref, cr) = certificate_import
        assert k8s.wait_on_condition(
            ref,
            condition.CONDITION_TYPE_RESOURCE_SYNCED,
            "True",
            wait_periods=MAX_WAIT_FOR_SYNCED_MINUTES,
        )
        assert k8s.get_resource_condition(ref, condition.CONDITION_TYPE_TERMINAL) is None

        assert 'status' in cr
        status = cr['status']
        assert 'ackResourceMetadata' in status
        assert 'arn' in status['ackResourceMetadata']
        certificate_arn = status['ackResourceMetadata']['arn']
        assert status['type_'] == 'IMPORTED'
        assert status['status'] == 'ISSUED'
        assert status['subject'] == 'O=ACK,CN=services.k8s.aws'

        assert certificate.get(certificate_arn) is not None

        updates = {
            'spec': {
                'options': {
                    'certificateTransparencyLoggingPreference': 'ENABLED'
                }
            },
        }
        k8s.patch_custom_resource(ref, updates)
        time.sleep(10)
        assert k8s.wait_on_condition(
            ref,
            condition.CONDITION_TYPE_TERMINAL,
            'True',
            wait_periods=MAX_WAIT_FOR_SYNCED_MINUTES,
        )

        updates = {
            'spec': {
                'options': {
                    'certificateTransparencyLoggingPreference': 'DISABLED'
                }
            },
        }
        k8s.patch_custom_resource(ref, updates)
        time.sleep(10)
        assert k8s.get_resource_condition(ref, condition.CONDITION_TYPE_TERMINAL) is None

        k8s.delete_custom_resource(ref)
        time.sleep(DELETE_WAIT_AFTER_SECONDS)
        certificate.wait_until_deleted(certificate_arn)

    def test_reimport_after_external_delete(
            self,
            certificate_import,
    ):
        (ref, cr) = certificate_import
        assert k8s.wait_on_condition(
            ref,
            condition.CONDITION_TYPE_RESOURCE_SYNCED,
            "True",
            wait_periods=MAX_WAIT_FOR_SYNCED_MINUTES,
        )

        cr = k8s.get_resource(ref)
        assert 'status' in cr
        status = cr['status']
        assert 'ackResourceMetadata' in status
        assert 'arn' in status['ackResourceMetadata']
        original_arn = status['ackResourceMetadata']['arn']
        assert status['type_'] == 'IMPORTED'

        # Verify late-initialized fields are present in spec (these caused
        # the bug when re-importing)
        spec = cr['spec']
        assert spec.get('keyAlgorithm') is not None or \
            spec.get('subjectAlternativeNames') is not None, \
            "Expected late-initialized fields to be present in spec"

        # Delete the certificate directly from AWS to simulate console deletion
        certificate.delete(original_arn)
        certificate.wait_until_deleted(original_arn)

        # Wait for the controller to detect the deletion and re-import.
        # The controller's requeue_on_success_seconds is 60, so we wait for
        # it to reconcile and re-create the certificate.
        time.sleep(CREATE_WAIT_AFTER_SECONDS)

        # Wait for re-import to complete and resource to sync
        assert k8s.wait_on_condition(
            ref,
            condition.CONDITION_TYPE_RESOURCE_SYNCED,
            "True",
            wait_periods=MAX_WAIT_FOR_SYNCED_MINUTES * 3,
        )

        # Verify the certificate was re-imported with a new ARN
        cr = k8s.get_resource(ref)
        new_arn = cr['status']['ackResourceMetadata']['arn']
        assert new_arn != original_arn, \
            "Expected a new ARN after re-import"
        assert cr['status']['type_'] == 'IMPORTED'

        cr = k8s.get_resource(ref)
        spec = cr['spec']
        assert spec.get('keyAlgorithm') is not None or \
            spec.get('subjectAlternativeNames') is not None, \
            "Expected late-initialized fields to be present in spec"

        # Verify late-initialized values match the new certificate in AWS
        aws_cert = certificate.get(new_arn)
        assert aws_cert is not None
        assert spec['keyAlgorithm'] == aws_cert['KeyAlgorithm']
        assert spec['subjectAlternativeNames'] == aws_cert['SubjectAlternativeNames']

        # Cleanup
        k8s.delete_custom_resource(ref)
        time.sleep(DELETE_WAIT_AFTER_SECONDS)
        certificate.wait_until_deleted(new_arn)

    def test_export_private_certificate(
            self,
            certificate_private_export,
    ):
        (ref, _) = certificate_private_export

        cr = wait_until_exported(ref, MAX_WAIT_FOR_EXPORT_SECONDS)
        certificate_arn = cr['status']['ackResourceMetadata']['arn']
        issued_serial = cr['status']['serial']
        assert cr['metadata']['annotations'][EXPORTED_SERIAL_ANNOTATION] == issued_serial
        assert k8s.wait_on_condition(
            ref,
            condition.CONDITION_TYPE_RESOURCE_SYNCED,
            "True",
            wait_periods=MAX_WAIT_FOR_SYNCED_MINUTES,
        )

        exported_crt, exported_key = get_exported_secret(ref.name)
        assert '-----BEGIN CERTIFICATE-----' in exported_crt
        assert 'PRIVATE KEY-----' in exported_key

        boto3.client('acm').renew_certificate(CertificateArn=certificate_arn)
        cr = wait_until_exported(ref, MAX_WAIT_FOR_RENEWAL_SECONDS, previous_serial=issued_serial)
        renewed_serial = cr['status']['serial']
        assert renewed_serial != issued_serial
        assert cr['metadata']['annotations'][EXPORTED_SERIAL_ANNOTATION] == renewed_serial

        renewed_crt, renewed_key = get_exported_secret(ref.name)
        assert renewed_crt != exported_crt
        assert 'PRIVATE KEY-----' in renewed_key


def wait_until_exported(ref, timeout_seconds, previous_serial=None):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        cr = k8s.get_resource(ref)
        serial = cr.get('status', {}).get('serial')
        exported = cr['metadata'].get('annotations', {}).get(EXPORTED_SERIAL_ANNOTATION)
        if serial and serial != previous_serial and exported == serial:
            return cr
        time.sleep(WAIT_INTERVAL_SECONDS)
    pytest.fail(f"certificate {ref.name} was not exported before timeout")


def get_exported_secret(name):
    secret = client.CoreV1Api(k8s_client()).read_namespaced_secret(name, 'default')
    return (
        base64.b64decode(secret.data['tls.crt']).decode('utf-8'),
        base64.b64decode(secret.data['tls.key']).decode('utf-8'),
    )

def k8s_client():
    return k8s._get_k8s_api_client()
