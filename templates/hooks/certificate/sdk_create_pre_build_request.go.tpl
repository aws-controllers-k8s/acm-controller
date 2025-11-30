    created, isImport, err := rm.maybeImportCertificate(ctx, desired)
    if err != nil {
        return nil, err
    }
    if isImport {
        return created, nil
    }
	if err = validatePublicValidationOptions(desired); err != nil {
		return nil, ackerr.NewTerminalError(err)
	}
