    if delta.DifferentAt("Spec.Status.IssuedAt") {
        rlog.Info("Exporting certificate due to IssuedAt change")
        if err = rm.exportCertificate(ctx, &resource{latest.ko}); err != nil {
            rlog.Info("failed to export certificate", "error", err)
			return nil, err
        } else {
            rlog.Info("Certificate export completed successfully")
        }
        ko := desired.ko.DeepCopy()

        rm.setStatusDefaults(ko)
        ko.Status.IssuedAt = latest.ko.Status.IssuedAt
        ko.Status.Status = latest.ko.Status.Status
        ko.Status.Serial = latest.ko.Status.Serial
        return &resource{ko}, nil
    }

    if delta.DifferentAt("Spec.Status.Serial") {
        rlog.Info("Exporting certificate due to Serial change")
        if err = rm.exportCertificate(ctx, &resource{latest.ko}); err != nil {
            rlog.Info("failed to export certificate", "error", err)
            return nil, err
        } else {
            rlog.Info("Certificate export completed successfully")
        }
        ko := desired.ko.DeepCopy()

        rm.setStatusDefaults(ko)
        ko.Status.IssuedAt = latest.ko.Status.IssuedAt
        ko.Status.Status = latest.ko.Status.Status
        ko.Status.Serial = latest.ko.Status.Serial
        return &resource{ko}, nil
    }

    if delta.DifferentAt("Spec.Tags") {
		if err := syncTags(
			ctx, rm.sdkapi, rm.metrics,
			string(*desired.ko.Status.ACKResourceMetadata.ARN),
			desired.ko.Spec.Tags, latest.ko.Spec.Tags,
		); err != nil {
			return nil, err
		}
	}
	if !delta.DifferentExcept("Spec.Tags") {
        return desired, nil
    }
	if latest.ko.Status.Type != nil && *latest.ko.Status.Type == string(svcapitypes.CertificateType_IMPORTED) {
		if delta.DifferentAt("Spec.Options") {
			return nil, ackerr.NewTerminalError(errors.New("only tags can be updated for an imported certificate"))
		}
		return desired, nil
	}
