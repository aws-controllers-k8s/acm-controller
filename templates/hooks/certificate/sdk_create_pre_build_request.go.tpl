	if err = validatePublicValidationOptions(desired); err != nil {
		ackcondition.SetTerminal(
			desired,
			corev1.ConditionTrue,
			&domainValidationOptionsExceededMsg,
			nil,
		)
		return desired, nil
	}
