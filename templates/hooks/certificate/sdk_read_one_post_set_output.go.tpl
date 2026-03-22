err = rm.exportOnAdoption(ctx, &resource{ko})
if err != nil {
    return &resource{ko}, err
}