namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Opt-in: "AllowFeatures" of the remote must contain "CountingChannel".
/// <para>
/// The failure switches live here rather than on the feature because they must be set before the
/// first connection, when no feature exists yet.
/// </para>
/// </summary>
public sealed class CountingChannelFeatureDriver : ChannelFeatureDriver<CountingChannelFeature>
{
    public CountingChannelFeatureDriver( TransportFeatureDriver transport )
        : base( transport, isAllowedByDefault: false )
    {
    }

    /// <summary>
    /// Gets or sets how many times <see cref="ChannelFeature.CreateHandler"/> must throw (decremented
    /// on each throw, shared by all the features of this driver).
    /// </summary>
    public int CreateHandlerFailures { get; set; }

    /// <summary>
    /// When true, <see cref="ChannelFeature.OnCurrentHandlerChanged"/> throws.
    /// </summary>
    public bool ThrowOnHandlerChanged { get; set; }

    /// <summary>
    /// When true, <see cref="ChannelFeature.Teardown"/> throws (after having been recorded).
    /// </summary>
    public bool ThrowOnTeardown { get; set; }

    protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportFeature transport, out CountingChannelFeature? channel )
    {
        channel = new CountingChannelFeature( this, transport );
        return true;
    }
}
