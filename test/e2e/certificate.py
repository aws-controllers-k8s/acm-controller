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

"""Utilities for working with Certificate resources"""

import datetime
import time
import typing

import boto3
import pytest

DEFAULT_WAIT_UNTIL_TIMEOUT_SECONDS = 60*30
DEFAULT_WAIT_UNTIL_INTERVAL_SECONDS = 15
DEFAULT_WAIT_UNTIL_DELETED_TIMEOUT_SECONDS = 60*10
DEFAULT_WAIT_UNTIL_DELETED_INTERVAL_SECONDS = 15

CertificateMatchFunc = typing.NewType(
    'CertificateMatchFunc',
    typing.Callable[[dict], bool],
)

class StatusMatcher:
    def __init__(self, status):
        self.match_on = status

    def __call__(self, record: dict) -> bool:
        return ('Status' in record
                and record['Status'] == self.match_on)


def status_matches(status: str) -> CertificateMatchFunc:
    return StatusMatcher(status)


def wait_until(
        certificate_arn: str,
        match_fn: CertificateMatchFunc,
        timeout_seconds: int = DEFAULT_WAIT_UNTIL_TIMEOUT_SECONDS,
        interval_seconds: int = DEFAULT_WAIT_UNTIL_INTERVAL_SECONDS,
    ) -> None:
    """Waits until a Certificate with a supplied ARN is returned from the ACM
    API and the matching functor returns True.

    Usage:
        from e2e.certificate import wait_until, status_matches

        wait_until(
            certificate_arn,
            status_matches("ISSUED"),
        )

    Raises:
        pytest.fail upon timeout
    """
    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=timeout_seconds)

    while not match_fn(get(certificate_arn)):
        if datetime.datetime.now() >= timeout:
            pytest.fail("failed to match Certificate before timeout")
        time.sleep(interval_seconds)


def wait_until_deleted(
        certificate_arn: str,
        timeout_seconds: int = DEFAULT_WAIT_UNTIL_DELETED_TIMEOUT_SECONDS,
        interval_seconds: int = DEFAULT_WAIT_UNTIL_DELETED_INTERVAL_SECONDS,
    ) -> None:
    """Waits until a Certificate with a supplied ID is no longer returned from
    the ACM API.

    Usage:
        from e2e.db_instance import wait_until_deleted

        wait_until_deleted(instance_id)

    Raises:
        pytest.fail upon timeout or if the Certificate goes to any other status
        other than 'deleting'
    """
    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=timeout_seconds)

    while True:
        if datetime.datetime.now() >= timeout:
            pytest.fail(
                "Timed out waiting for Certificate to be "
                "deleted in ACM API"
            )
        time.sleep(interval_seconds)

        latest = get(certificate_arn)
        if latest is None:
            break


def get(certificate_arn):
    """Returns a dict containing the Certificate record from the ACM API.

    If no such Certificate exists, returns None.
    """
    c = boto3.client('acm')
    try:
        resp = c.describe_certificate(CertificateArn=certificate_arn)
        return resp['Certificate']
    except c.exceptions.ResourceNotFoundException:
        return None


def get_tags(certificate_arn):
    """Returns a dict containing the Certificate's tag records from the ACM
    API.

    If no such Certificate exists, returns None.
    """
    c = boto3.client('acm')
    try:
        resp = c.list_tags_for_certificate(
            CertificateArn=certificate_arn,
        )
        return resp['Tags']
    except c.exceptions.ResourceNotFoundException:
        return None
