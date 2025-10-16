// We only support DNS-based validation, because
// certificate renewal is not really automatable when email verification
// is used.
//
// See discussion here:
// https://docs.aws.amazon.com/acm/latest/userguide/email-validation.html
//
// Unfortunately, because fields in the "ignore" configuration list are
// now deleted from the aws-sdk-go private/model/api.Shape object,
// setting `override_values` does not work.

input.ValidationMethod = "DNS"

if desired.ko.Spec.ExportTo != nil {
    options := input.Options
    if options == nil {
        options = &svcsdktypes.CertificateOptions{}
    }
    options.Export = "ENABLED"
}