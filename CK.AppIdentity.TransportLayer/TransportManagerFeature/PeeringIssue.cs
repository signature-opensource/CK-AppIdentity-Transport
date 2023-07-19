using CK.Core;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Unifies peering related issues, either:
    /// <list type="bullet">
    ///     <item><see cref="PeeringIssueKind.InvalidClockOffset"/>: An invalid clock offset between this local system and the remote has been detected.</item>
    ///     <item><see cref="PeeringIssueKind.UnknwonIncoming"/>: An unknwon remote attempts to connect.</item>
    ///     <item><see cref="PeeringIssueKind.UntrustedIncoming"/>: A not yet trusted remote attempts to connect.</item>
    ///     <item><see cref="PeeringIssueKind.WaitingRemoteApproval"/>: A taget remote is not trusting us yet.</item>
    /// </list>
    /// </summary>
    public sealed class PeeringIssue
    {
        readonly string _fullName;
        DateTime _time;
        PeeringIssueKind _kind;
        InitialMessage? _initialMessage;
        TransportFeature? _remote;
        string? _enlistUrl;
        TimeSpan? _invalidClockOffset;
        // We don't have internal alternative.
        object _lock;

        internal PeeringIssue( string fullName,
                               DateTime now,      
                               PeeringIssueKind kind,
                               InitialMessage? initialMessage,
                               TransportFeature? remote,
                               string? enlistUrl, 
                               TimeSpan? invalidClockOffset )
        {
            Debug.Assert( kind != PeeringIssueKind.None );
            Debug.Assert( initialMessage != null || remote != null, "No InitialMessage => remote is known (initiator)" );
            CheckInvariants( kind, initialMessage, remote, enlistUrl, invalidClockOffset );

            _time = now;
            _fullName = fullName;
            _kind = kind;
            _initialMessage = initialMessage;
            _remote = remote;
            _enlistUrl = enlistUrl;
            _invalidClockOffset = invalidClockOffset;
            _lock = new object();
        }

        [Conditional( "DEBUG" )]
        static void CheckInvariants( PeeringIssueKind kind, InitialMessage? initialMessage, TransportFeature? remote, string? enlistUrl, TimeSpan? invalidClockOffset )
        {
            Debug.Assert( kind != PeeringIssueKind.InvalidClockOffset || invalidClockOffset.HasValue, "InvalidClockOffset => a non null value for the offset" );
            Debug.Assert( !(kind == PeeringIssueKind.InvalidClockOffset && initialMessage != null)
                                || (!initialMessage.ValidClockOffset && invalidClockOffset!.Value == initialMessage.ClockOffset),
                          "Listener InvalidClockOffset => Invalid clock offset is the one of the initialMessage" );
            Debug.Assert( enlistUrl == null
                            || ((kind == PeeringIssueKind.WaitingRemoteApproval || kind == PeeringIssueKind.WaitingRemoteCreation) && initialMessage == null && remote != null),
                          "EnlistUrl => WaitingRemoteApproval/Creation and IsInitiator" );
            Debug.Assert( kind != PeeringIssueKind.WaitingRemoteApproval && kind != PeeringIssueKind.WaitingRemoteCreation
                            || initialMessage == null,
                            "WaitingRemoteApproval/Creation => IsInitiator" );
            Debug.Assert( kind != PeeringIssueKind.UnknwonIncoming || remote == null, "UnknwonIncoming => null remote" );
            Debug.Assert( kind != PeeringIssueKind.UntrustedIncoming
                            || initialMessage != null && remote != null && initialMessage.ValidClockOffset,
                          "UntrustedIncoming => remote is known, clock offset is valid. This is all we can say (our remote may have a TrustedIdentity " +
                          "but it has not been found in the message: this is a 'warning')" );
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
        public bool IsListener => _initialMessage != null;

        /// <summary>
        /// Gets whether we are calling the remote.
        /// </summary>
        [MemberNotNullWhen( false, nameof( IncomingRequest ) )]
        [MemberNotNullWhen( true, nameof( Remote ) )]
        public bool IsInitiator => _initialMessage == null;

        /// <summary>
        /// Gets the remote's full name. This is always available.
        /// </summary>
        public string FullName => _fullName;

        /// <summary>
        /// Gets the incoming request.
        /// This is never null if <see cref="IsListener"/> is true.
        /// </summary>
        public IIncomingRequest? IncomingRequest => _initialMessage;

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
        /// any url based capability to accept remotes.
        /// </para>
        /// </summary>
        public string? EnlistUrl => _enlistUrl;

        /// <summary>
        /// Gets the non null invalid clock offset is <see cref="Kind"/> is <see cref="PeeringIssueKind.InvalidClockOffset"/>.
        /// <para>
        /// This applies to <see cref="IsInitiator"/> or <see cref="IsListener"/>.
        /// </para>
        /// </summary>
        public TimeSpan? InvalidClockOffset => _invalidClockOffset;

        /// <summary>
        /// Gets whether the remote can be accepted: <see cref="Kind"/> is <see cref="PeeringIssueKind.UntrustedIncoming"/>.
        /// <para>
        /// This should be true before calling <see cref="AcceptRemote"/> but this state can change at any time:
        /// <see cref="AcceptRemoteIdentity(IActivityMonitor)"/> may return false if conditions are not met when it is called.
        /// </para>
        /// </summary>
        public bool CanAcceptRemoteIdentity => _kind == PeeringIssueKind.UntrustedIncoming;

        /// <summary>
        /// Accepts the current <see cref="IIncomingRequest.CurrentRemoteIdentity"/> for this remote.
        /// This information is persited: from now on, the remote incoming connections will be accepted.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <returns>True on success, false if <see cref="Kind"/> is not <see cref="PeeringIssueKind.UntrustedIncoming"/>.</returns>
        public bool AcceptRemoteIdentity( IActivityMonitor monitor )
        {
            lock( _lock )
            {
                if( _kind == PeeringIssueKind.UntrustedIncoming )
                {
                    Debug.Assert( _remote != null && IncomingRequest != null );
                    _remote.RemoteKeys.SetTrustedIdentity( monitor, new KeyManagement.RemoteIdentityKey( IncomingRequest.CurrentRemoteIdentity ) );
                    return true;
                }
            }
            return false;
        }

        internal void Update( PeeringIssueKind kind,
                              DateTime now,
                              InitialMessage? message,
                              TransportFeature? remote,
                              string? enlistUrl,
                              TimeSpan? invalidClockOffset,
                              ref int unknwonRemoteCount )
        {
            // Maintain unknwon remote count and check invariants.
            if( kind == PeeringIssueKind.None )
            {
                if( _remote == null ) unknwonRemoteCount--;
            }
            else
            {
                // First idea was:
                //
                //   Debug.Assert( (_initialMessage == null) == (message == null), "Initiator xor Listener cannot change." );
                //
                // This is not true! A possible scenario is:
                //  - A remote "R" (on another system) is configured with an "Address" to us and we have a listener that
                //    received one ore more attempts: we have a "UnknwonIncoming".
                //  - Then "R" is dynamically added here with an "Address" to the remote system that is simultaneously reconfigured
                //    as a listener (no more "Address" configuration in the remote system).
                //  => We now initiate a connection and may receive a WaitingRemoteApproval from it: we transitioned from Listener
                //     to Initiator for the full name.
                //  
                //  Note that we'll never see a transition from Initiator to Listener: this requires a destroy of the RemoteParty
                //  and a new dynamic add of the remote (without the "Address" configuration).
                //
                CheckInvariants( kind, message, remote, enlistUrl, invalidClockOffset );
                if( remote == null )
                {
                    if( _remote != null ) unknwonRemoteCount++;
                }
                else
                {
                    if( _remote == null ) unknwonRemoteCount--;
                }
            }
            // Update atomically for CanAccept/Accept.
            lock(_lock )
            {
                _time = now;
                _kind = kind;
                _initialMessage = message;
                _remote = remote;
                _enlistUrl = enlistUrl;
                _invalidClockOffset = invalidClockOffset;
            }
        }
    }

}
