	if delta.DifferentAt("Spec.Tags") {
		err := syncTags(
			ctx, rm.sdkapi, rm.metrics, 
			string(*desired.ko.Status.ACKResourceMetadata.ARN), 
			desired.ko.Spec.Tags, latest.ko.Spec.Tags,
		)
		if err != nil {
			return nil, err
		}
	}
	// If nothing else has changed, we shouldn't send an update.
    if !delta.DifferentExcept("Spec.Tags") {
        return desired, nil
    }