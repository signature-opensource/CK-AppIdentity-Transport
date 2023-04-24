namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Raised by <see cref="TransportManagerFeature.TransportChanged"/> when a <see cref="TransportFeature"/>
    /// appears, disappears or its <see cref="TransportFeature.IsOff"/> changes.
    /// </summary>
    /// <param name="Feature">The feature that changed.</param>
    /// <param name="Destroyed">True if the <see cref="TransportFeature.Party"/> has been destroyed.</param>
    public sealed record TransportFeatureChangedEvent( TransportFeature Feature, bool Destroyed );
}
