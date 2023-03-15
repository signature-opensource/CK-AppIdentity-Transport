using CK.Core;
using CK.PerfectEvent;

namespace CK.AppIdentity.PocoChannel
{

    /// <summary>
    /// Sender and receiver of <see cref="IPoco"/>.
    /// <para>
    /// This channel handles retries and persistence.
    /// </para>
    /// No correlation is done at this level between sent and received Pocos.
    /// </summary>
    public interface IPocoChannel
    {
        bool IsConnected { get; }

        IRemoteParty Party { get; }

        PerfectEvent<IPocoChannel> IsConnectedChanged { get; }

        ValueTask<StoredPocoHandle> SendAsync( IActivityMonitor monitor, IPoco poco, bool store = false );

        PerfectEvent<IPocoChannel, IPoco> ReceivedPoco { get; }

        ValueTask<IPoco?> LoadAsync( in StoredPocoHandle handle );
    }
}
