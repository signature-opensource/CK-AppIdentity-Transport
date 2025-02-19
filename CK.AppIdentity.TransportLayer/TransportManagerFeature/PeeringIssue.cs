using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Unifies peering related issues. See <see cref="PeeringIssueKind"/>.
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
    RemoteIdentityKeyData? _remoteKeyForApproval;
    IReadOnlyList<string>? _localMissingProtocols;
    IReadOnlyList<string>? _remoteMissingProtocols;
    private GoodbyeMessage? _remoteOffMessage;

    // We don't have internal alternative.
    // We always update from the TransportManager loop,
    // this lock is here to protect CanAccept/Accept decision and the Clone.
    object _lock;
    PeeringIssue? _cloneSource;

    internal PeeringIssue( string fullName,
                           DateTime now,
                           PeeringIssueKind kind,
                           InitialMessage? initialMessage,
                           TransportFeature? remote,
                           string? enlistUrl,
                           TimeSpan? invalidClockOffset,
                           RemoteIdentityKeyData? remoteKeyForApproval,
                           IReadOnlyList<string>? localMissingProtocols,
                           IReadOnlyList<string>? remoteMissingProtocols )
    {
        Throw.DebugAssert( kind != PeeringIssueKind.None );
        Throw.DebugAssert( "No InitialMessage => remote is known (initiator)", initialMessage != null || remote != null );
        _fullName = fullName;
        CheckInvariants( kind, initialMessage, remote, enlistUrl, invalidClockOffset, remoteKeyForApproval, localMissingProtocols, remoteMissingProtocols );

        _time = now;
        _kind = kind;
        _initialMessage = initialMessage;
        _remote = remote;
        _enlistUrl = enlistUrl;
        _invalidClockOffset = invalidClockOffset;
        _remoteKeyForApproval = remoteKeyForApproval;
        _localMissingProtocols = localMissingProtocols;
        _remoteMissingProtocols = remoteMissingProtocols;
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
    /// Gets a url that can be used to make the remote accept us.
    /// <para>
    /// This is always nullable since the remote may not have any url based capability to accept remotes.
    /// </para>
    /// </summary>
    public string? EnlistUrl => _enlistUrl;

    /// <summary>
    /// Gets the non null invalid clock offset if <see cref="Kind"/> is <see cref="PeeringIssueKind.InvalidClockOffset"/>.
    /// <para>
    /// This applies to <see cref="IsInitiator"/> or <see cref="IsListener"/>.
    /// </para>
    /// </summary>
    public TimeSpan? InvalidClockOffset => _invalidClockOffset;

    /// <summary>
    /// Gets the remote public identity that can be approved by calling <see cref="AcceptRemoteIdentity(IActivityMonitor)"/>.
    /// </summary>
    public RemoteIdentityKeyData? RemoteKeyForApproval => _remoteKeyForApproval;

    /// <summary>
    /// Gets the missing local protocols.
    /// When kind is <see cref="PeeringIssueKind.MissingProtocols"/> this list and/or <see cref="RemoteMissingProtocols"/>
    /// contain at least one <see cref="MessageProtocol.FullName"/>.
    /// </summary>
    public IReadOnlyList<string>? LocalMissingProtocols => _localMissingProtocols;

    /// <summary>
    /// Gets the missing local protocols.
    /// When kind is <see cref="PeeringIssueKind.MissingProtocols"/> this list and/or <see cref="LocalMissingProtocols"/>
    /// contain at least one <see cref="MessageProtocol.FullName"/>.
    /// </summary>
    public IReadOnlyList<string>? RemoteMissingProtocols => _remoteMissingProtocols;

    /// <summary>
    /// Gets the <see cref="GoodbyeMessage"/> received when <see cref="Kind"/> is <see cref="PeeringIssueKind.RemoteIsSwitchedOff"/>
    /// or <see cref="PeeringIssueKind.RemoteHasBeenEvicted"/>.
    /// </summary>
    public GoodbyeMessage? RemoteOffMessage => _remoteOffMessage;

    /// <summary>
    /// Gets whether the remote can be accepted: <see cref="Kind"/> is <see cref="PeeringIssueKind.RequiresLocalApproval"/>
    /// or <see cref="PeeringIssueKind.RequiresBothApproval"/> and the <see cref="RemoteKeyForApproval"/> is not null.
    /// <para>
    /// This should be true before calling <see cref="AcceptRemote"/> but this state can change at any time:
    /// <see cref="AcceptRemoteIdentity(IActivityMonitor)"/> may return false if conditions are not met when it is called.
    /// </para>
    /// </summary>
    public bool CanAcceptRemoteIdentity => _cloneSource?.CanAcceptRemoteIdentity
                                            ?? (_kind is PeeringIssueKind.RequiresLocalApproval or PeeringIssueKind.RequiresBothApproval
                                                && _remoteKeyForApproval != null);

    /// <summary>
    /// Accepts the current <see cref="IIncomingRequest.CurrentRemoteIdentity"/> for this remote.
    /// This information is persited: from now on, the remote incoming connections will be accepted.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <returns>True on success, false if <see cref="Kind"/> is not <see cref="PeeringIssueKind.RequiresLocalApproval"/>.</returns>
    public bool AcceptRemoteIdentity( IActivityMonitor monitor )
    {
        if( _cloneSource != null ) return _cloneSource.AcceptRemoteIdentity( monitor );
        lock( _lock )
        {
            if( _kind is PeeringIssueKind.RequiresLocalApproval or PeeringIssueKind.RequiresBothApproval
                && _remoteKeyForApproval != null )
            {
                Throw.DebugAssert( _remote != null );
                _remote.RemoteKeys.SetTrustedIdentity( monitor, _remoteKeyForApproval );
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
    /// Creates a snapshot clone of this issue.
    /// This clone will not be updated and is the only way to have coherent properties
    /// for an issue.
    /// </summary>
    /// <returns>An immutable clone (this instance if <see cref="IsClone"/> is true).</returns>
    public PeeringIssue Clone()
    {
        if( _cloneSource != null ) return this;
        lock( _lock )
        {
            var c = (PeeringIssue)MemberwiseClone();
            c._cloneSource = this;
            return c;
        }
    }

    internal void Update( PeeringIssueKind kind,
                          DateTime now,
                          InitialMessage? message,
                          TransportFeature? remote,
                          string? enlistUrl,
                          TimeSpan? invalidClockOffset,
                          RemoteIdentityKeyData? remoteKeyForApproval,
                          IReadOnlyList<string>? localMissingProtocols,
                          IReadOnlyList<string>? remoteMissingProtocols,
                          GoodbyeMessage? remoteOffMessage )
    {
        Throw.DebugAssert( _cloneSource == null );
        CheckInvariants( kind, message, remote, enlistUrl, invalidClockOffset, remoteKeyForApproval, localMissingProtocols, remoteMissingProtocols );
        lock( _lock )
        {
            _time = now;
            _kind = kind;
            _initialMessage = message;
            _remote = remote;
            _enlistUrl = enlistUrl;
            _invalidClockOffset = invalidClockOffset;
            _remoteKeyForApproval = remoteKeyForApproval;
            _localMissingProtocols = localMissingProtocols;
            _remoteMissingProtocols = remoteMissingProtocols;
            _remoteOffMessage = remoteOffMessage;
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
            // IncomingUnknwon (if the party itself is destroyed) or IncomingDisallowedTransport
            // if the party is still alive.
            if( _remote.IsListening )
            {
                if( _remote.Party.IsDestroyed )
                {
                    _kind = PeeringIssueKind.IncomingUnknwon;
                }
                else
                {
                    _kind = PeeringIssueKind.IncomingDisallowedTransport;
                }
            }
            else
            {
                _kind = PeeringIssueKind.None;
            }
            _remoteKeyForApproval = null;
            _localMissingProtocols = null;
            _remoteMissingProtocols = null;
            _remoteOffMessage = null;
            _remote = null;
            CheckInvariants( _kind, _initialMessage, _remote, _enlistUrl, _invalidClockOffset, _remoteKeyForApproval, _localMissingProtocols, _remoteMissingProtocols );
            return _kind == PeeringIssueKind.None;
        }
    }

    internal void OnRemoteAppeared( TransportFeature remote )
    {
        // This is necessarily on the listener side.
        Throw.DebugAssert( _remote == null );
        lock( _lock )
        {
            Throw.DebugAssert( "An existing issue without remote has an initial message.", _initialMessage != null );
            // When a remote appears locally and this issue is in IncomingUnknwon state
            // then it becomes known:
            // - If the newcomer is a listener:
            //      - If the initial message has a IncomingEndPointDescription that is not one of the
            //        remote's listeners, it is IncomingUnsupportedTransport.
            //      - Else we take no risk (and don't introduce a "NewListenerWaiting" state): we could set this
            //        issue to be RequiresLocalApproval if there is no TrustedIdentity but this would be surprising
            //        (may be it is RequiresBothApproval?). It is safer to kill this issue (None) and let the
            //        exchange runs.
            // - Else (the newcomer is configured to be an initiator): InitiatorConflict.
            if( remote.IsListening )
            {
                if( !remote.Listeners.Any( l => l.EndPointDescription == _initialMessage.IncomingEndPointDescription ) )
                {
                    _kind = PeeringIssueKind.IncomingUnsupportedTransport;
                }
                else
                {
                    _kind = PeeringIssueKind.None;
                }
            }
            else
            {
                _kind = PeeringIssueKind.InitiatorConflict;
                _initialMessage = null;
            }
            _remote = remote;
            CheckInvariants( _kind, _initialMessage, _remote, _enlistUrl, _invalidClockOffset, _remoteKeyForApproval, _localMissingProtocols, _remoteMissingProtocols );
        }

    }

    [Conditional( "DEBUG" )]
    static void CheckInvariants( PeeringIssueKind kind,
                                 InitialMessage? initialMessage,
                                 TransportFeature? remote,
                                 string? enlistUrl,
                                 TimeSpan? invalidClockOffset,
                                 RemoteIdentityKeyData? remoteKeyForApproval,
                                 IReadOnlyList<string>? localMissingProtocols,
                                 IReadOnlyList<string>? remoteMissingProtocols )
    {
        // For None, we keep the data as-is: no invariant exist. 
        if( kind == PeeringIssueKind.None ) return;

        bool isInitiator = remote?.TargetAddress != null;
        bool isListener = remote?.TargetAddress == null;

        Throw.DebugAssert( "Initiator and not InitiatorConflict => we have no incoming request.",
                           !(isInitiator && kind != PeeringIssueKind.InitiatorConflict) || (initialMessage == null) );

        Throw.DebugAssert( "RequiresRemoteCreation => IsInitiator",
                           kind != PeeringIssueKind.RequiresRemoteCreation || isInitiator );

        Throw.DebugAssert( "IncomingUnknwon => IsListener",
                            kind != PeeringIssueKind.IncomingUnknwon || isListener );

        Throw.DebugAssert( "InvalidClockOffset => a non null value for the offset.",
                           (kind is not PeeringIssueKind.InvalidClockOffset) || invalidClockOffset.HasValue );

        Throw.DebugAssert( "Listener and InvalidClockOffset <=> Invalid clock offset is the one of the initialMessage.",
                           (isListener && kind == PeeringIssueKind.InvalidClockOffset) == (initialMessage != null && !initialMessage.IsValidClockOffset
                                                                                           && invalidClockOffset == initialMessage.ClockOffset) );

        Throw.DebugAssert( "EnlistUrl => RequiresLocal(Both)Approval or RequiresRemoteCreation.",
                           enlistUrl == null
                            || (kind is PeeringIssueKind.RequiresRemoteCreation
                                        or PeeringIssueKind.RequiresLocalApproval
                                        or PeeringIssueKind.RequiresBothApproval) );

        Throw.DebugAssert( "RemoteKeyForApproval => RequiresLocal(Both)Approval.",
                           remoteKeyForApproval == null
                            || (kind is PeeringIssueKind.RequiresLocalApproval
                                        or PeeringIssueKind.RequiresBothApproval) );

        Throw.DebugAssert( "Listener and RequiresLocal(Both)Approval => remote is known, clock offset is valid.",
                            !(isListener && kind is PeeringIssueKind.RequiresLocalApproval or PeeringIssueKind.RequiresBothApproval)
                            || (initialMessage != null && remote != null && initialMessage.IsValidClockOffset && invalidClockOffset == null) );

        Throw.DebugAssert( "Initiator and RequiresLocal(Both)Approval => clock offset is valid and RemoteKeyForApproval is known.",
                            !(isInitiator && kind is PeeringIssueKind.RequiresLocalApproval or PeeringIssueKind.RequiresBothApproval)
                            || (invalidClockOffset == null && remoteKeyForApproval != null) );

        Throw.DebugAssert( "MissingProtocols <=> LocalMissing or RemoteMissing.",
                           (kind is PeeringIssueKind.MissingProtocols) == (localMissingProtocols?.Count > 0 || remoteMissingProtocols?.Count > 0) );
    }

    /// <summary>
    /// Overridden to return the <see cref="FullName"/> - <see cref="Kind"/>.
    /// </summary>
    /// <returns>The party's full name and kind of this issue.</returns>
    public override string ToString() => $"{_fullName} - {Kind}";

}
