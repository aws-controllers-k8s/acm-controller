// Export certificate if issued and IssuedAt timestamp changed
if resp.Certificate.Status == "ISSUED" {
    if ko.Spec.ExportTo != nil && ko.Spec.ExportPassphrase != nil {
        oldIssuedAtStr := "nil"
        timeFormat := "2006-01-02T15:04:05Z07:00"
        if oldIssuedAt != nil {
            oldIssuedAtStr = oldIssuedAt.Format(timeFormat)
		}
        newIssuedAtStr := "nil"
        if ko.Status.IssuedAt != nil {
            newIssuedAtStr = ko.Status.IssuedAt.Format(timeFormat)
        }

        // Check if IssuedAt changed (certificate was renewed or newly issued)
        // Use string comparison to avoid metav1.Time precision issues
        issuedAtChanged := (oldIssuedAtStr != newIssuedAtStr)

        if issuedAtChanged {
            rlog.Info("Exporting certificate due to IssuedAt change")
            if err = rm.maybeExportCertificate(ctx, &resource{ko}); err != nil {
                rlog.Info("failed to export certificate", "error", err)
            } else {
                rlog.Info("Certificate export completed successfully")
            }
        }
    }
}