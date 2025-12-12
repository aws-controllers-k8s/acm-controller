	if resp.Certificate.DomainValidationOptions != nil {
		dvs := []*svcapitypes.DomainValidation{}
		for _, dvsiter := range resp.Certificate.DomainValidationOptions {
			dvselem := &svcapitypes.DomainValidation{}
			if dvsiter.DomainName != nil {
				dvselem.DomainName = dvsiter.DomainName
			}
			if dvsiter.ResourceRecord != nil {
				dvselem.ResourceRecord = &svcapitypes.ResourceRecord{}
				if dvsiter.ResourceRecord.Name != nil {
					dvselem.ResourceRecord.Name = dvsiter.ResourceRecord.Name
				}
				if dvsiter.ResourceRecord.Type != "" {
					dvselem.ResourceRecord.Type = aws.String(string(dvsiter.ResourceRecord.Type))
				}
				if dvsiter.ResourceRecord.Value != nil {
					dvselem.ResourceRecord.Value = dvsiter.ResourceRecord.Value
				}
			}
			if dvsiter.ValidationDomain != nil {
				dvselem.ValidationDomain = dvsiter.ValidationDomain
			}
			for _, ve := range dvsiter.ValidationEmails {
				dvselem.ValidationEmails = append(dvselem.ValidationEmails, &ve)
			}
			if dvsiter.ValidationMethod != "" {
				dvselem.ValidationMethod = aws.String(string(dvsiter.ValidationMethod))
			}
			if dvsiter.ValidationStatus != "" {
				dvselem.ValidationStatus = aws.String(string(dvsiter.ValidationStatus))
			}
			dvs = append(dvs, dvselem)
		}
		ko.Status.DomainValidations = dvs
	} else {
		ko.Status.DomainValidations = nil
	}
	ko.Spec.Tags, err = listTags(
		ctx, rm.sdkapi, rm.metrics,
		string(*r.ko.Status.ACKResourceMetadata.ARN),
	)
	if err != nil {
		return nil, err
	}