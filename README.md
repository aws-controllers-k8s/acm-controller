# ACK service controller for AWS Certificate Manager

This repository contains source code for the AWS Controllers for Kubernetes
(ACK) service controller for ACM.

Please [log issues][ack-issues] and feedback on the main AWS Controllers for
Kubernetes Github project.

[ack-issues]: https://github.com/aws/aws-controllers-k8s/issues

## Getting Started

### Pricing
The ACK service controller for AWS Certificate Manager is free of charge. If you issue an exportable public certificate with AWS Certificate Manager, there is a charge at certificate issuance and again when the certificate renews. Learn more about [AWS Certificate Manager Pricing](https://aws.amazon.com/certificate-manager/pricing/).

[samples]: https://github.com/aws-controllers-k8s/acmpca-controller/tree/main/samples

### Kubernetes Secrets
The ACK service controller for AWS Certificate Manager uses Kubernetes TLS Secrets to store the certificate chain and decrypted private key of the exported ACM certificate. Users are expected to create Secrets before creating Certificate resources. As these resources are created, the Secrets' `tls.crt` will be injected with the base64-encoded certificate and `tls.key` will be injected with the base64-encoded private key associated with the certificate. Users are responsible for deleting Secrets.

In addition, after a certificate is successfully renewed by ACM, the ACK service controller for AWS Certificate Manager will automatically export the renewed certificate again so that the Kubernetes TLS Secret `exportTo` contains the certificate data and private key data of the renewed certificate.

#### Export Certificate
To export an ACM certificate to a Kubernetes TLS Secret, users must specify the namespace and the name of the Secret using the `exportTo` field of the Certificate resource, as shown below.

##### Exporting an exportable ACM public certificate
```
apiVersion: v1
kind: Secret
type: kubernetes.io/tls
metadata:
  name: exported-cert-secret
  namespace: demo-app
data:
  tls.crt: ""
  tls.key: ""
---
apiVersion: acm.services.k8s.aws/v1alpha1
kind: Certificate
metadata:
  name: exportable-public-cert
  namespace: demo-app
spec:
  domainName: my.domain.com
  options:
    certificateTransparencyLoggingPreference: ENABLED
  exportTo:
    namespace: demo-app
    name: exported-cert-secret
    key: tls.crt
...
```

##### Exporting an ACM private certificate
```
apiVersion: v1
kind: Secret
type: kubernetes.io/tls
metadata:
  name: exported-cert-secret
  namespace: demo-app-2
data:
  tls.crt: ""
  tls.key: ""
---
apiVersion: acm.services.k8s.aws/v1alpha1
kind: Certificate
metadata:
  name: exportable-private-cert
  namespace: demo-app-2
spec:
  domainName: my.domain.com
  certificateAuthorityARN: arn:aws:acm-pca:{$REGION}:{$AWS_ACCOUNT}:certificate-authority/12345678-1234-1234-1234-123456789012
  keyAlgorithm: EC_secp384r1
  exportTo:
    namespace: demo-app-2
    name: exported-cert-secret
    key: tls.crt
```

## Contributing

We welcome community contributions and pull requests.

See our [contribution guide](/CONTRIBUTING.md) for more information on how to
report issues, set up a development environment, and submit code.

We adhere to the [Amazon Open Source Code of Conduct][coc].

You can also learn more about our [Governance](/GOVERNANCE.md) structure.

[coc]: https://aws.github.io/code-of-conduct

## License

This project is [licensed](/LICENSE) under the Apache-2.0 License.
