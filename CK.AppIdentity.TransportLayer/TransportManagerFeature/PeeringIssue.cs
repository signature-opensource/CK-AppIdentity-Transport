using CK.Core;
using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

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
        // We always update from the TransportManager loop,
        // this lock is here to protect CanAccept/Accept decision.
        object _lock;
        PeeringIssue? _cloneSource;

        internal PeeringIssue( string fullName,
                               DateTime now,      
                               PeeringIssueKind kind,
                               InitialMessage? initialMessage,
                               TransportFeature? remote,
                               string? enlistUrl, 
                               TimeSpan? invalidClockOffset )
        {
            Throw.DebugAssert( kind != PeeringIssueKind.None );
            Throw.DebugAssert( initialMessage != null || remote != null, "No InitialMessage => remote is known (initiator)" );
            _fullName = fullName;
            CheckInvariants( kind, initialMessage, remote, enlistUrl, invalidClockOffset );

            _time = now;
            _kind = kind;
            _initialMessage = initialMessage;
            _remote = remote;
            _enlistUrl = enlistUrl;
            _invalidClockOffset = invalidClockOffset;
            _lock = new object();
        }

        [Conditional( "DEBUG" )]
        void CheckInvariants( PeeringIssueKind kind, InitialMessage? initialMessage, TransportFeature? remote, string? enlistUrl, TimeSpan? invalidClockOffset )
        {
            // For None, we keep the data as-is: no invariant exist. 
            if( kind == PeeringIssueKind.None ) return;

            bool isInitiator = remote?.TargetAddress != null;

            Throw.DebugAssert( kind != PeeringIssueKind.InvalidClockOffset || invalidClockOffset.HasValue, "InvalidClockOffset => a non null value for the offset" );

            Throw.DebugAssert( !(kind == PeeringIssueKind.InvalidClockOffset && initialMessage != null)
                                || (!initialMessage.ValidClockOffset && invalidClockOffset!.Value == initialMessage.ClockOffset),
                          "InvalidClockOffset with a message => Invalid clock offset is the one of the initialMessage" );

            Throw.DebugAssert( enlistUrl == null
                            || (kind == PeeringIssueKind.WaitingRemoteApproval || kind == PeeringIssueKind.WaitingRemoteCreation),
                          "EnlistUrl => WaitingRemoteApproval/Creation" );

            Throw.DebugAssert( kind != PeeringIssueKind.WaitingRemoteApproval && kind != PeeringIssueKind.WaitingRemoteCreation
                            || (isInitiator && initialMessage == null),
                            "WaitingRemoteApproval/Creation => IsInitiator and we have no incoming request" );

            Throw.DebugAssert( kind != PeeringIssueKind.UnknwonIncoming || remote == null, "UnknwonIncoming => null remote" );

            Throw.DebugAssert( kind != PeeringIssueKind.UntrustedIncoming
                            || initialMessage != null && remote != null && initialMessage.ValidClockOffset,
                          "UntrustedIncoming => remote is known, clock offset is valid. This is all we can say (our remote may have a TrustedIdentity " +
                          "but it has not been found in the message: this may be a 'warning: no more/lost trust')" );
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
        [MemberNotNullWhen( true, nameof( IncomingRequest ) )]
        [MemberNotNullWhen( false, nameof( Remote ) )]
        public bool IsListener => _remote?.TargetAddress == null;

        /// <summary>
        /// Gets whether we are calling the remote.
        /// If we are the initiator and there is an <see cref="IncomingRequest"/> then it's an <see cref="PeeringIssueKind.InitiatorConflict"/>.
        /// </summary>
        [MemberNotNullWhen( true, nameof( Remote ) )]
        public bool IsInitiator => _remote?.TargetAddress != null;

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
        public bool CanAcceptRemoteIdentity => _cloneSource?.CanAcceptRemoteIdentity ?? _kind == PeeringIssueKind.UntrustedIncoming;

        /// <summary>
        /// Accepts the current <see cref="IIncomingRequest.CurrentRemoteIdentity"/> for this remote.
        /// This information is persited: from now on, the remote incoming connections will be accepted.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <returns>True on success, false if <see cref="Kind"/> is not <see cref="PeeringIssueKind.UntrustedIncoming"/>.</returns>
        public bool AcceptRemoteIdentity( IActivityMonitor monitor )
        {
            if( _cloneSource != null ) return _cloneSource.AcceptRemoteIdentity( monitor );
            lock( _lock )
            {
                if( _kind == PeeringIssueKind.UntrustedIncoming )
                {
                    Throw.DebugAssert( _remote != null && IncomingRequest != null );
                    _remote.RemoteKeys.SetTrustedIdentity( monitor, new KeyManagement.RemoteIdentityKey( IncomingRequest.CurrentRemoteIdentity ) );
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Gets whether this issue is an immutable <see cref="Clone"/>.
        /// </summary>
        public bool IsClone => _cloneSource != null;

        /// <summary>
        /// Creates a snapshot clone of this issue. This clone will not be updated.
        /// </summary>
        /// <returns>An immutable clone</returns>
        public PeeringIssue Clone()
        {
            if( _cloneSource != null ) return this;
            var c = (PeeringIssue)MemberwiseClone();
            c._cloneSource = this;
            return c;
        }

        internal void Update( PeeringIssueKind kind,
                              DateTime now,
                              InitialMessage? message,
                              TransportFeature? remote,
                              string? enlistUrl,
                              TimeSpan? invalidClockOffset )
        {
            Throw.DebugAssert( _cloneSource == null );
            CheckInvariants( kind, message, remote, enlistUrl, invalidClockOffset );
            lock( _lock )
            {
                _time = now;
                _kind = kind;
                _initialMessage = message;
                _remote = remote;
                _enlistUrl = enlistUrl;
                _invalidClockOffset = invalidClockOffset;
            }
        }

        internal void SetNoneIssueKind()
        {
            lock( _lock )
            {
                _kind = PeeringIssueKind.None;
            }
        }

        internal bool OnRemoteTornDown()
        {
            Throw.DebugAssert( _remote != null );
            lock( _lock )
            {
                // If we are the initiator and the transport feature dispappear,
                // there is no point to keep this issue.
                // But if we are listening, we can keep it (with a null Remote) we then are either
                // UnknwonIncoming (if the party itself is destroyed) or DisallowedTransportIncoming
                // if the party is still alive.
                if( _remote.IsListening )
                {
                    if( _remote.Party.IsDestroyed )
                    {
                        _kind = PeeringIssueKind.UnknwonIncoming;
                    }
                    else
                    {
                        _kind = PeeringIssueKind.DisallowedTransportIncoming;
                    }
                }
                else
                {
                    _kind = PeeringIssueKind.None;
                }
                _remote = null;
                CheckInvariants( _kind, _initialMessage, _remote, _enlistUrl, _invalidClockOffset );
                return _kind == PeeringIssueKind.None;
            }
        }

        internal void OnRemoteAppeared( TransportFeature remote )
        {
            Throw.DebugAssert( _remote == null );
            lock( _lock )
            {
                Throw.DebugAssert( _initialMessage != null, "An existing issue without remote has an initial message." );
                // When a remote appears locally and is in UnknwonIncoming state
                // then it becomes known:
                // - If the newcomer is a listener:
                //      - We can transition to UnsupportedTransportIncoming
                //        if the initial message has a IncomingEndPointDescription that is not one of the
                //        remote's listeners.
                //      - Else we are UntrustedIncoming. 
                // - Else (the newcomer is configured to be an initiator): InitiatorConflict.
                if( remote.IsListening )
                {
                    if( !remote.Listeners.Any( l => l.EndPointDescription == _initialMessage.IncomingEndPointDescription ) )
                    {
                        _kind = PeeringIssueKind.UnsupportedTransportIncoming;
                    }
                    else
                    {
                        _kind = PeeringIssueKind.UntrustedIncoming;
                    }
                }
                else 
                {
                    _kind = PeeringIssueKind.InitiatorConflict;
                }
                _remote = remote;
                CheckInvariants( _kind, _initialMessage, _remote, _enlistUrl, _invalidClockOffset );
            }
        }
    }

}
