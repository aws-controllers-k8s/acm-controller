{{ $CRD := .CRD }}
{{ $SDKAPI := .SDKAPI }}

{{/* Maintain operations here */}}
{{ range $operationName := Each "ImportCertificate" }}

{{- $operation := (index $SDKAPI.API.Operations $operationName)}}

{{- $inputRef := $operation.InputRef }}
{{- $inputShapeName := $inputRef.ShapeName }}

{{- $outputRef := $operation.OutputRef }}
{{- $outputShapeName := $outputRef.ShapeName }}


{{/* Some operations have custom structure */}}
{{- if (eq $operationName "ImportCertificate") }}

// new{{ $inputShapeName }} returns a {{ $inputShapeName }} object 
// with each field set by the corresponding configuration's fields.
func (rm *resourceManager) new{{ $inputShapeName }}(
    ctx context.Context,
    r *resource,
) (*svcsdk.{{ $inputShapeName }}, error) {
    input := &importCertificateInput{ImportCertificateInput: &svcsdk.ImportCertificateInput{}}
{{ GoCodeSetSDKForStruct $CRD "" "input" $inputRef "" "r.ko.Spec" 1 }}
    refs, err := importSecretRefsFromSpec(r.ko.Spec)
    if err != nil {
        return nil, err
    }
    {{range $fieldName := Each "PrivateKey" "Certificate" "CertificateChain"}}
    {
        var secretRef *ackv1alpha1.SecretKeyReference
        switch "{{$fieldName}}" {
        case "PrivateKey":
            secretRef = refs.PrivateKey
        case "Certificate":
            secretRef = refs.Certificate
        case "CertificateChain":
            secretRef = refs.CertificateChain
        }
        if secretRef != nil {
            tmpSecret, err := rm.secretValueFromReference(ctx, secretRef)
            if err != nil {
                return nil, err
            }
            if tmpSecret != "" {
                if "{{$fieldName}}" == "Certificate" && refs.CertificateChain == nil {
                    cert, chain, err := splitCertificateAndChain([]byte(tmpSecret))
                    if err != nil {
                        return nil, ackerr.NewTerminalError(err)
                    }
                    input.ImportCertificateInput.Certificate = cert
                    if len(chain) > 0 {
                        input.ImportCertificateInput.CertificateChain = chain
                    }
                } else {
                    input.ImportCertificateInput.{{$fieldName}} = []byte(tmpSecret)
                }
            }
        }
    }
    {{end}}
    setImportCertificateARN(input.ImportCertificateInput, r)
    finalizeImportCertificateInput(input.ImportCertificateInput)
    return input.ImportCertificateInput, nil
}
{{ end }}

// setResourceFrom{{ $outputShapeName }} sets a resource {{ $outputShapeName }} type
// given the SDK type.
func (rm *resourceManager) setResourceFrom{{ $outputShapeName }}(
    r *resource,
    resp *svcsdk.{{ $outputShapeName }},
) {
{{ GoCodeSetCreateOutput $CRD "resp" "r.ko" 1 }}
}

{{- end }}
