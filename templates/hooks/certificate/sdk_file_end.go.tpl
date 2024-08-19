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
    {{range $fieldName := Each "PrivateKey" "Certificate" "CertificateChain"}}
    {
        tmpSecret, err := rm.rr.SecretValueFromReference(ctx, r.ko.Spec.{{$fieldName}})
        if err != nil {
            return nil, ackrequeue.Needed(err)
        }
        if tmpSecret != "" {
            input.{{$fieldName}} = []byte(tmpSecret)
        }
    }
    {{end}}
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
