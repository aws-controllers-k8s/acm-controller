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
