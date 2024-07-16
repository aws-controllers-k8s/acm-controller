    created, isImport, err := rm.maybeImportCertificate(ctx, desired)
    if err != nil {
        return nil, err
    }
    if isImport {
        return created, nil
    }
    if err = validatePublicValidationOptions(desired); err != nil {
        ackcondition.SetTerminal(
            desired,
            corev1.ConditionTrue,
            &domainValidationOptionsExceededMsg,
            nil,
        )
        return desired, nil
    }
