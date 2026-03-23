r := rm.concreteResource(res)
rlog := ackrtlog.FromContext(ctx)
rlog.Info("OnAdopted is called!")
if r.ko.Spec.ExportTo != nil {
    if err := rm.exportCertificate(ctx, r); err != nil {
        rlog.Info("Failed to export adopted certificate", "error", err)
        return nil, err
    } else {
        rlog.Info("Adopted certificate export completed successfully")
    }
}