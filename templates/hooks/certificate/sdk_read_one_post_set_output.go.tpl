	if ko.Spec.ImportFrom != nil {
		clearImportFromObservedSpecFields(&ko.Spec)
	}
	{
		syncedRes, err := rm.syncImportFromSecretIfNeeded(ctx, &resource{ko: ko})
		if err != nil {
			return nil, err
		}
		if syncedRes != nil && syncedRes.ko != nil {
			ko = syncedRes.ko
		}
	}
