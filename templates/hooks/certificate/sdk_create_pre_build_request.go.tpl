	if err = validatePublicValidationOptions(desired); err != nil {
		return nil, ackerr.NewTerminalError(err)
	}
