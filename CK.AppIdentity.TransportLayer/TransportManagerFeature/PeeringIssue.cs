using CK.Core;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Captures remote peerig related issues: either an invalid clock offset between this local system and
    /// the remote has been detected or an unknwon or not yet trusted remote requests a peering.
    /// </summary>
    public sealed class PeeringIssue
    {
        readonly string _fullName;
        DateTime _time;
        PeeringIssueKind _kind;
        InitialMessage? _incomingRequest;
        TransportFeature? _remote;
        // We don't have internal alternative.
        object _lock;

        internal PeeringIssue( string fullName, PeeringIssueKind kind, InitialMessage? initialMessage, TransportFeature? remote )
        {
            _time = DateTime.UtcNow;
            _fullName = fullName;
            _kind = kind;
            _incomingRequest = initialMessage;
            _remote = remote;
            _lock = new object();
        }

        /// <summary>
        /// Gets the last updated time of this issue.
        /// </summary>
        public DateTime LastUpdated => _time;

        /// <summary>
        /// Gets the type of this issue.
        /// </summary>
        public PeeringIssueKind Kind => _kind;

        /// <summary>
        /// Gets whether we are listening to the remote incoming requests.
        /// </summary>
        [MemberNotNullWhen( true, nameof(IncomingRequest) )]
        [MemberNotNullWhen( false, nameof( Remote ) )]
        public bool IsListener => _incomingRequest != null;

        /// <summary>
        /// Gets whether we are calling the remote.
        /// </summary>
        [MemberNotNullWhen( false, nameof( IncomingRequest ) )]
        [MemberNotNullWhen( true, nameof( Remote ) )]
        public bool IsInitiator => _incomingRequest == null;

        /// <summary>
        /// Gets the remote's full name. This is always available.
        /// </summary>
        public string FullName => _fullName;

        /// <summary>
        /// Gets the incoming request.
        /// This is never null if <see cref="IsListener"/> is true.
        /// </summary>
        public IIncomingRequest? IncomingRequest => _incomingRequest;

        /// <summary>
        /// Gets the transport's remote feature if the remote is locally defined.
        /// This is never null if <see cref="IsInitiator"/> is true, and may be null
        /// or not if <see cref="IsListener"/> is true.
        /// </summary>
        public TransportFeature? Remote => _remote;

        /// <summary>
        /// Gets a url that can be used to accept this initiator on the target remote.
        /// <para>
        /// This may be null even if <see cref="IsInitiator"/> is true since the remote may not have
        /// any url based capility to accept remotes.
        /// </para>
        /// </summary>
        public string? EnlistUrl => _enlistUrl;

        /// <summary>
        /// Gets whether the remote can be accepted: <see cref="Kind"/> is <see cref="PeeringIssue.IncomingRequest"/>
        /// and a <see cref="Remote"/> exists.
        /// <para>
        /// This should be true before calling <see cref="AcceptRemote"/> but this state can change at any time:
        /// <see cref="AcceptRemoteIdentity(IActivityMonitor)"/> may return false if conditions are not met when it is called.
        /// </para>
        /// </summary>
        public bool CanAcceptRemoteIdentity
        {
            get
            {
                lock( _lock )
                {
                    return _kind == PeeringIssueKind.IncomingRequest && _remote != null;
                }
            }
        }

        /// <summary>
        /// Accepts the current <see cref="IIncomingRequest.CurrentRemoteIdentity"/> for this remote.
        /// This information is persited: from now on, the remote incoming connections will be accepted.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <returns>True on success, </returns>
        public bool AcceptRemoteIdentity( IActivityMonitor monitor )
        {
            lock( _lock )
            {
                if( _kind == PeeringIssueKind.IncomingRequest && _remote != null )
                {
                    Debug.Assert( IncomingRequest != null );
                    _remote.RemoteKeys.SetTrustedIdentity( monitor, new KeyManagement.RemoteIdentityKey( IncomingRequest.CurrentRemoteIdentity ) );
                    return true;
                }
            }
            return false;
        }

        internal void Update( PeeringIssueKind kind, InitialMessage? message, TransportFeature? remote, ref int unknwonRemoteCount )
        {
            // Maintain unknwon remote count.
            if( kind == PeeringIssueKind.None )
            {
                if( _remote == null ) unknwonRemoteCount--;
            }
            else
            {
                if( remote == null )
                {
                    if( _remote != null ) unknwonRemoteCount++;
                }
                else
                {
                    if( _remote == null ) unknwonRemoteCount--;
                }
            }
            _time = DateTime.UtcNow;
            // Update atomically for CanAccept/Accept.
            lock(_lock )
            {
                _incomingRequest = message;
                _remote = remote;
                _kind = kind;
            }
        }
    }

}
