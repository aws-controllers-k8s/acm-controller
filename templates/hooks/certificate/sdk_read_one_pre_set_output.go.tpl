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
				if dvsiter.ResourceRecord.Type != nil {
					dvselem.ResourceRecord.Type = dvsiter.ResourceRecord.Type
				}
				if dvsiter.ResourceRecord.Value != nil {
					dvselem.ResourceRecord.Value = dvsiter.ResourceRecord.Value
				}
			}
			if dvsiter.ValidationDomain != nil {
				dvselem.ValidationDomain = dvsiter.ValidationDomain
			}
			if dvsiter.ValidationEmails != nil {
				dvselem.ValidationEmails = dvsiter.ValidationEmails
			}
			if dvsiter.ValidationMethod != nil {
				dvselem.ValidationMethod = dvsiter.ValidationMethod
			}
			if dvsiter.ValidationStatus != nil {
				dvselem.ValidationStatus = dvsiter.ValidationStatus
			}
			dvs = append(dvs, dvselem)
		}
		ko.Status.DomainValidations = dvs
	} else {
		ko.Status.DomainValidations = nil
	}
