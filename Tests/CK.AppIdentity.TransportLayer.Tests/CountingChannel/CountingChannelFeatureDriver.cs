namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Opt-in: "AllowFeatures" of the remote must contain "CountingChannel".
/// </summary>
public sealed class CountingChannelFeatureDriver : ChannelFeatureDriver<CountingChannelFeature>
{
    public CountingChannelFeatureDriver( TransportFeatureDriver transport )
        : base( transport, isAllowedByDefault: false )
    {
    }

    protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportFeature transport, out CountingChannelFeature? channel )
    {
        channel = new CountingChannelFeature( transport );
        return true;
    }
}
