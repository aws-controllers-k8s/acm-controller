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
            input.ImportCertificateInput.{{$fieldName}} = []byte(tmpSecret)
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

var hasBeenAdopted bool = false

func (rm *resourceManager) exportOnAdoption(
    ctx context.Context,
    r *resource) error {
    isAdopted := isAdopted(r)
    shouldExport := r.ko.Spec.ExportTo != nil
    if !hasBeenAdopted && isAdopted && shouldExport {
        rlog := ackrtlog.FromContext(ctx)
        if err := rm.exportCertificate(ctx, r); err != nil {
            rlog.Info("Failed to export adopted certificate", "error", err)
            return err
        }
        rlog.Info("Adopted certificate successfully exported")
        hasBeenAdopted = true
    }
    return nil
}

// IsAdopted returns true if the supplied AWSResource was created with a
// non-nil ARN annotation, which indicates that the Kubernetes user who created
// the CR for the resource expects the ACK service controller to "adopt" a
// pre-existing resource and bring it under ACK management.
func isAdopted(res acktypes.AWSResource) bool {
    mo := res.MetaObject()
    if mo == nil {
        // Should never happen... if it does, it's buggy code.
        panic("IsAdopted received resource with nil RuntimeObject")
    }
    for k, v := range mo.GetAnnotations() {
        if k == ackv1alpha1.AnnotationAdopted {
            return strings.ToLower(v) == "true"
        }
    }
    return false
}
