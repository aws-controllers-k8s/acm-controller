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
The ACK service controller for AWS Certificate Manager uses Kubernetes TLS Secrets to store the certificate chain and decrypted private key of [exportable public certificates](https://docs.aws.amazon.com/acm/latest/userguide/acm-exportable-certificates.html). Users are expected to create Secrets before creating Certificate resources. As these resources are created, the Secrets' `tls.crt` will be injected with the base64-encoded certificate and `tls.key` will be injected with the base64-encoded private key associated with the certificate. Users are responsible for deleting Secrets.

In addition, after a certificate is successfully renewed by ACM, the ACK service controller for AWS Certificate Manager will automatically export the renewed certificate again so that the Kubernetes TLS Secret `exportTo` contains the certificate data and private key data of the renewed certificate.

#### Export Certificate
To export an ACM exportable public certificate to a Kubernetes TLS Secret, users must specify the namespace and the name of the Secret using the `exportTo` field of the Certificate resource, as shown below.

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

## Contributing

We welcome community contributions and pull requests.

See our [contribution guide](/CONTRIBUTING.md) for more information on how to
report issues, set up a development environment, and submit code.

We adhere to the [Amazon Open Source Code of Conduct][coc].

You can also learn more about our [Governance](/GOVERNANCE.md) structure.

[coc]: https://aws.github.io/code-of-conduct

## License

This project is [licensed](/LICENSE) under the Apache-2.0 License.
