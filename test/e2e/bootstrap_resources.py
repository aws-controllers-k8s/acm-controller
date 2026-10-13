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

"""Declares the structure of the bootstrapped resources and provides a loader
for them.
"""

import json
from dataclasses import dataclass, field

import boto3

from acktest import resources
from acktest.bootstrapping import Bootstrappable, Resources
from acktest.bootstrapping.acmpca import PrivateCertificateAuthority
from e2e import bootstrap_directory

# The IAM role associated with an external account binding. The ACME service
# assumes this role to issue certificates on behalf of ACME clients, so its
# trust policy must grant acm-acme.amazonaws.com sts:AssumeRole,
# sts:TagSession, and sts:SetSourceIdentity, and it needs certificate
# issuance permissions.
EAB_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "acm-acme.amazonaws.com"},
            "Action": [
                "sts:AssumeRole",
                "sts:TagSession",
                "sts:SetSourceIdentity",
            ],
        }
    ],
}

EAB_ISSUANCE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "acm:RequestCertificate",
                "acm:DescribeCertificate",
                "acm:GetCertificate",
            ],
            "Resource": "*",
        }
    ],
}


@dataclass
class EABIssuanceRole(Bootstrappable):
    # Inputs
    name_prefix: str

    # Outputs
    name: str = field(init=False)
    arn: str = field(default="", init=False)

    def __post_init__(self):
        self.name = resources.random_suffix_name(self.name_prefix, 63)

    @property
    def iam_client(self):
        return boto3.client("iam", region_name=self.region)

    def bootstrap(self):
        """Creates the EAB issuance role with the ACME service trust policy."""
        super().bootstrap()
        role = self.iam_client.create_role(
            RoleName=self.name,
            AssumeRolePolicyDocument=json.dumps(EAB_TRUST_POLICY),
            Description="ACK ACM e2e test role for ACME external account bindings",
        )
        self.arn = role["Role"]["Arn"]
        self.iam_client.put_role_policy(
            RoleName=self.name,
            PolicyName="acme-issuance",
            PolicyDocument=json.dumps(EAB_ISSUANCE_POLICY),
        )

    def cleanup(self):
        """Deletes the EAB issuance role.

        Tolerant of partial state: bootstrap can fail between create_role and
        put_role_policy, and cleanup must not then raise and mask the original failure.
        """
        try:
            self.iam_client.delete_role_policy(RoleName=self.name, PolicyName="acme-issuance")
        except self.iam_client.exceptions.NoSuchEntityException:
            pass
        try:
            self.iam_client.delete_role(RoleName=self.name)
        except self.iam_client.exceptions.NoSuchEntityException:
            pass
        super().cleanup()


@dataclass
class BootstrapResources(Resources):
    EABRole: EABIssuanceRole = field(default=None)
    PrivateCA: PrivateCertificateAuthority = field(default=None)

_bootstrap_resources = None

def get_bootstrap_resources(bootstrap_file_name: str = "bootstrap.pkl") -> BootstrapResources:
    global _bootstrap_resources
    if _bootstrap_resources is None:
        _bootstrap_resources = BootstrapResources.deserialize(bootstrap_directory, bootstrap_file_name=bootstrap_file_name)
    return _bootstrap_resources
