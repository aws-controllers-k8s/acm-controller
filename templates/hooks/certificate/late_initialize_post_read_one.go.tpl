	{
		observedKo := rm.concreteResource(observed).ko
		latestKo := rm.concreteResource(latestCopy).ko
		if observedKo.Spec.DomainName != nil && latestKo.Spec.DomainName == nil {
			latestKo.Spec.DomainName = observedKo.Spec.DomainName
		}
		if observedKo.Spec.DomainValidationOptions != nil && latestKo.Spec.DomainValidationOptions == nil {
			latestKo.Spec.DomainValidationOptions = observedKo.Spec.DomainValidationOptions
		}
		if observedKo.Spec.SubjectAlternativeNames != nil && latestKo.Spec.SubjectAlternativeNames == nil {
			latestKo.Spec.SubjectAlternativeNames = observedKo.Spec.SubjectAlternativeNames
		}
	}
