	{
		observedKo := rm.concreteResource(observed).ko
		latestKo := rm.concreteResource(latestCopy).ko
		if observedKo.Spec.DomainValidationOptions != nil && latestKo.Spec.DomainValidationOptions == nil {
			latestKo.Spec.DomainValidationOptions = observedKo.Spec.DomainValidationOptions
		}
		if observedKo.Spec.SubjectAlternativeNames != nil && latestKo.Spec.SubjectAlternativeNames == nil {
			latestKo.Spec.SubjectAlternativeNames = observedKo.Spec.SubjectAlternativeNames
		}
	}
