using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using CK.IO.Authentication.Passkey;
using Fido2NetLib;
using Fido2NetLib.Objects;
using System;
using System.Buffers.Text;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter.Passkey;

/// <summary>
/// Handles the passkey operations of a local Authentication Center (see <see cref="AuthCenterPasskey"/>): the passkey
/// commands are executed by the endpoint that receives them (CK.Cris.Authentication.Passkey), which executes these
/// operations, locally or dispatched.
/// <list type="bullet">
///   <item>A ceremony is accepted only from an endpoint whose web origin (carried by the operation) is one of the
///   configured origins, and the origin signed by the browser must be this one.</item>
///   <item>The user is always verified (PIN, biometrics): <c>userVerification: "required"</c>, and the UV flag is checked.</item>
///   <item>The login is usernameless: the options list no credential.</item>
///   <item>A registration requires the Critical level, not impersonated, and must be completed by the session that
///   started it. The attestation is "none".</item>
/// </list>
/// </summary>
public sealed class AuthCenterPasskeyHandlers : ISingletonAutoService
{
    /// <summary>
    /// The name of a registered passkey when the command gives none.
    /// </summary>
    public const string DefaultName = "Passkey";

    #region Validation
    // The incoming validation of the passkey commands (response size, name) is in CK.IO.Authentication.Passkey: the
    // receiving endpoint runs it.

    /// <summary>
    /// Checks that passkeys are available and that the endpoint's origin is accepted.
    /// </summary>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c, IStartPasskeyLoginOperationCommand op, CurrentLocalParty localParty ) => Check( c, localParty, op.WebOrigin );

    /// <inheritdoc cref="Validate(UserMessageCollector, IStartPasskeyLoginOperationCommand, CurrentLocalParty)"/>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c, IFinishPasskeyLoginOperationCommand op, CurrentLocalParty localParty ) => Check( c, localParty, op.WebOrigin );

    /// <summary>
    /// Checks that passkeys are available, that the endpoint's origin is accepted, and that the authentication is at the
    /// Critical level and not impersonated (the session itself is checked by the handler).
    /// </summary>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c,
                          IStartPasskeyRegistrationOperationCommand op,
                          CurrentLocalParty localParty,
                          AuthenticationInfo authentication )
    {
        Check( c, localParty, op.WebOrigin );
        if( authentication.IsImpersonated )
        {
            c.Error( "This is refused while impersonating.", "Authentication.Impersonated" );
        }
        else if( authentication.ActualActor.Level != AuthLevel.Critical )
        {
            c.Error( "This requires the Critical level.", "Authentication.CriticalLevelRequired" );
        }
    }

    /// <inheritdoc cref="Validate(UserMessageCollector, IStartPasskeyLoginOperationCommand, CurrentLocalParty)"/>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c, IFinishPasskeyRegistrationOperationCommand op, CurrentLocalParty localParty ) => Check( c, localParty, op.WebOrigin );

    static void Check( UserMessageCollector c, CurrentLocalParty localParty, string? webOrigin )
    {
        var family = FindFamily( localParty );
        if( family == null )
        {
            c.Error( "Passkeys are not available.", "Authentication.UnknownScheme" );
        }
        else if( !family.Options!.IsAllowedOrigin( webOrigin ) )
        {
            c.Error( string.IsNullOrEmpty( webOrigin )
                        ? "This endpoint cannot serve passkeys."
                        : $"The origin '{webOrigin}' is not allowed for passkeys.", "Authentication.PasskeyOriginNotAllowed" );
        }
    }

    static AuthCenterPasskey? FindFamily( CurrentLocalParty localParty )
    {
        return localParty.LocalParty.GetFeature<LocalAuthCenter>() != null
               && localParty.LocalParty.GetFeature<AuthCenterPasskey>() is { IsAvailable: true } f
                ? f
                : null;
    }

    // The validators have checked the family and the origin.
    static (AuthCenterPasskey Family, string Origin) Get( CurrentLocalParty localParty, string webOrigin )
    {
        return (FindFamily( localParty )!, AuthCenterPasskeyOptions.NormalizeOrigin( webOrigin )!);
    }
    #endregion

    #region Login
    /// <summary>
    /// Starts a usernameless passkey login: the request options, as JSON.
    /// </summary>
    [CommandHandler]
    public string Handle( IActivityMonitor monitor, IStartPasskeyLoginOperationCommand op, CurrentLocalParty localParty )
    {
        var (family, origin) = Get( localParty, op.WebOrigin );
        var options = family.CreateFido2( origin ).GetAssertionOptions( new GetAssertionOptionsParams
        {
            AllowedCredentials = [],
            UserVerification = UserVerificationRequirement.Required
        } );
        var json = options.ToJson();
        AddCeremony( monitor, family, options.Challenge, new PasskeyCeremony( false, origin, json, null, 0, "" ) );
        return json;
    }

    /// <summary>
    /// Completes a passkey login: the response is verified (challenge, origin, relying party, user presence and verification,
    /// signature, counter) and the session of the passkey's owner is opened.
    /// </summary>
    [CommandHandler]
    public async Task<ISessionOperationResult> HandleAsync( IActivityMonitor monitor,
                                                            IFinishPasskeyLoginOperationCommand op,
                                                            CurrentLocalParty localParty,
                                                            IPasskeyStore store,
                                                            IServiceProvider services,
                                                            PocoDirectory pocos )
    {
        var endpoint = new OperationSessionEndpoint( op, webOrigin: op.WebOrigin );
        var command = op.Login;
        return endpoint.ToResult( pocos, command == null
                                            ? AuthCenterResults.Failure( monitor, op, "The passkey operation has no login command.", "Authentication.InvalidCommand" )
                                            : await LoginAsync( monitor, command, localParty, store, AuthCenterOperationHandlers.CreateIssuer( services, endpoint ), op.WebOrigin ).ConfigureAwait( false ) );
    }

    static async Task<ISessionResult> LoginAsync( IActivityMonitor monitor,
                                                  IPasskeyLoginCommand command,
                                                  CurrentLocalParty localParty,
                                                  IPasskeyStore store,
                                                  AuthCenterSessionIssuer issuer,
                                                  string webOrigin )
    {
        var (family, origin) = Get( localParty, webOrigin );
        var raw = Parse<AuthenticatorAssertionRawResponse>( command.Response );
        if( raw?.Response?.ClientDataJson == null || raw.RawId == null || raw.RawId.Length == 0 )
        {
            return AuthCenterResults.Failure( monitor, command, "Invalid passkey response.", "Authentication.InvalidPasskeyResponse" );
        }
        var ceremony = TakeCeremony( monitor, family, raw.Response.ClientDataJson, isRegistration: false, origin, out var error, out var errorId );
        if( ceremony == null ) return AuthCenterResults.Failure( monitor, command, error!, errorId! );
        // A discoverable credential: the user handle is required (and must be the owner's).
        if( raw.Response.UserHandle == null || raw.Response.UserHandle.Length == 0 )
        {
            return AuthCenterResults.Failure( monitor, command, "The passkey response has no user handle.", "Authentication.InvalidPasskeyResponse" );
        }
        var credential = await store.FindAsync( monitor, raw.RawId ).ConfigureAwait( false );
        if( credential == null )
        {
            return AuthCenterResults.Failure( monitor, command, "Unknown passkey.", "Authentication.UnknownPasskey" );
        }
        VerifyAssertionResult verified;
        try
        {
            verified = await family.CreateFido2( origin ).MakeAssertionAsync( new MakeAssertionParams
            {
                AssertionResponse = raw,
                OriginalOptions = AssertionOptions.FromJson( ceremony.OptionsJson ),
                StoredPublicKey = credential.PublicKey.ToArray(),
                StoredSignatureCounter = credential.SignCount,
                IsUserHandleOwnerOfCredentialIdCallback = ( p, _ ) => Task.FromResult( p.UserHandle != null && credential.UserHandle.Span.SequenceEqual( p.UserHandle ) )
            } ).ConfigureAwait( false );
        }
        catch( Fido2VerificationException ex )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Passkey login of actor #{credential.ActorId} refused ({ex.Code}).", ex );
            return AuthCenterResults.Failure( monitor, command, "The passkey cannot be verified.", "Authentication.PasskeyVerificationFailed" );
        }
        var payload = new PasskeyLoginPayload( verified.CredentialId, verified.SignCount, verified.IsBackedUp );
        return await issuer.OpenSessionAsync( monitor, command, PasskeyLoginPayload.Scheme, payload, command.RememberMe ).ConfigureAwait( false );
    }
    #endregion

    #region Registration
    /// <summary>
    /// Starts the registration of a new passkey for the current actor (Critical level, not impersonated): the creation
    /// options, as JSON.
    /// </summary>
    [CommandHandler]
    public async Task<string> HandleAsync( IActivityMonitor monitor,
                                           IStartPasskeyRegistrationOperationCommand op,
                                           CurrentLocalParty localParty,
                                           IServiceProvider services,
                                           AuthenticationInfo authentication,
                                           IPasskeyStore store )
    {
        var (family, origin) = Get( localParty, op.WebOrigin );
        var sessions = AuthCenterOperationHandlers.CreateSessionService( services, new OperationSessionEndpoint( op, webOrigin: op.WebOrigin ) );
        var (session, error, _) = await sessions.GetCriticalSessionAsync( monitor ).ConfigureAwait( false );
        if( session == null ) Throw.CKException( error! );
        var actor = authentication.ActualActor;
        var handle = await store.GetOrCreateUserHandleAsync( monitor, actor.ActorId ).ConfigureAwait( false );
        var existing = await store.GetCredentialsAsync( monitor, actor.ActorId ).ConfigureAwait( false );
        var options = family.CreateFido2( origin ).RequestNewCredential( new RequestNewCredentialParams
        {
            User = new Fido2User { Id = handle.ToArray(), Name = actor.ActorName, DisplayName = actor.ActorName },
            ExcludeCredentials = existing.Select( c => new PublicKeyCredentialDescriptor( PublicKeyCredentialType.PublicKey,
                                                                                          c.CredentialId.ToArray(),
                                                                                          ToTransports( c.Transports ) ) ).ToArray(),
            AuthenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Required
            },
            AttestationPreference = AttestationConveyancePreference.None,
            PubKeyCredParams = [PubKeyCredParam.ES256, PubKeyCredParam.RS256]
        } );
        var json = options.ToJson();
        AddCeremony( monitor, family, options.Challenge, new PasskeyCeremony( true, origin, json, session.SessionKey, actor.ActorId, op.Start?.Name ?? DefaultName ) );
        return json;
    }

    /// <summary>
    /// Completes the registration of a new passkey: the response is verified (challenge, origin, relying party, user
    /// presence and verification) in the session that started it, and the passkey is stored.
    /// </summary>
    [CommandHandler]
    public async Task<IPasskeyRegistrationResult> HandleAsync( IActivityMonitor monitor,
                                                               IFinishPasskeyRegistrationOperationCommand op,
                                                               CurrentLocalParty localParty,
                                                               IServiceProvider services,
                                                               IPasskeyStore store )
    {
        var command = op.Registration;
        if( command == null ) return Failure( monitor, op, "The passkey operation has no registration command.", "Authentication.InvalidCommand" );
        var (family, origin) = Get( localParty, op.WebOrigin );
        var sessions = AuthCenterOperationHandlers.CreateSessionService( services, new OperationSessionEndpoint( op, webOrigin: op.WebOrigin ) );
        var raw = Parse<AuthenticatorAttestationRawResponse>( command.Response );
        if( raw?.Response?.ClientDataJson == null || raw.Response.AttestationObject == null )
        {
            return Failure( monitor, command, "Invalid passkey response.", "Authentication.InvalidPasskeyResponse" );
        }
        var ceremony = TakeCeremony( monitor, family, raw.Response.ClientDataJson, isRegistration: true, origin, out var error, out var errorId );
        if( ceremony == null ) return Failure( monitor, command, error!, errorId! );
        var (session, sessionError, sessionErrorId) = await sessions.GetCriticalSessionAsync( monitor ).ConfigureAwait( false );
        if( session == null ) return Failure( monitor, command, sessionError!, sessionErrorId! );
        if( session.SessionKey != ceremony.SessionKey )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"A passkey registration of actor #{ceremony.ActorId} is completed by another session." );
            return Failure( monitor, command, "This registration has not been started by this session.", "Authentication.PasskeyCeremonyMismatch" );
        }
        RegisteredPublicKeyCredential registered;
        try
        {
            registered = await family.CreateFido2( origin ).MakeNewCredentialAsync( new MakeNewCredentialParams
            {
                AttestationResponse = raw,
                OriginalOptions = CredentialCreateOptions.FromJson( ceremony.OptionsJson ),
                IsCredentialIdUniqueToUserCallback = async ( p, _ ) => await store.FindAsync( monitor, p.CredentialId ).ConfigureAwait( false ) == null
            } ).ConfigureAwait( false );
        }
        catch( Fido2VerificationException ex )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Passkey registration of actor #{ceremony.ActorId} refused ({ex.Code}).", ex );
            return Failure( monitor, command, "The passkey cannot be verified.", "Authentication.PasskeyVerificationFailed" );
        }
        var credential = new PasskeyCredential( registered.Id,
                                                ceremony.ActorId,
                                                registered.User.Id,
                                                registered.PublicKey,
                                                registered.SignCount,
                                                registered.IsBackupEligible,
                                                registered.IsBackedUp,
                                                registered.AaGuid,
                                                (registered.Transports ?? []).Select( ToString ),
                                                ceremony.Name );
        if( !await store.CreateAsync( monitor, credential ).ConfigureAwait( false ) )
        {
            return Failure( monitor, command, "This passkey is already registered.", "Authentication.PasskeyExists" );
        }
        monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"Passkey '{ceremony.Name}' registered for actor #{ceremony.ActorId}." );
        return command.CreateResult( r => r.Name = ceremony.Name );
    }

    static IPasskeyRegistrationResult Failure( IActivityMonitor monitor, ICrisPoco source, string text, string resName )
        => AuthCenterResults.Failure<IPasskeyRegistrationResult>( monitor, source, text, resName );
    #endregion

    #region Ceremonies and helpers
    static void AddCeremony( IActivityMonitor monitor, AuthCenterPasskey family, byte[] challenge, PasskeyCeremony ceremony )
    {
        var store = family.Ceremonies!;
        if( !store.TryAdd( Base64Url.EncodeToString( challenge ), ceremony, DateTime.UtcNow ) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Too many pending passkey ceremonies ({store.Count}): a new one is refused." );
            Throw.CKException( "Too many passkey operations in progress. Please retry later." );
        }
    }

    // Finds the ceremony of the challenge signed in the clientDataJSON (one use), of the expected kind and origin.
    static PasskeyCeremony? TakeCeremony( IActivityMonitor monitor,
                                          AuthCenterPasskey family,
                                          byte[] clientDataJson,
                                          bool isRegistration,
                                          string origin,
                                          out string? error,
                                          out string? errorId )
    {
        error = errorId = null;
        string? challenge = null;
        try
        {
            using var d = JsonDocument.Parse( clientDataJson );
            if( d.RootElement.ValueKind == JsonValueKind.Object
                && d.RootElement.TryGetProperty( "challenge", out var c )
                && c.ValueKind == JsonValueKind.String )
            {
                challenge = c.GetString();
            }
        }
        catch( JsonException )
        {
        }
        var ceremony = family.Ceremonies!.TryTake( challenge, DateTime.UtcNow, out bool expired );
        if( ceremony == null )
        {
            (error, errorId) = (expired ? "This passkey operation has expired." : "This passkey operation is unknown or has expired.", "Authentication.PasskeyCeremonyExpired");
            return null;
        }
        if( ceremony.IsRegistration != isRegistration || ceremony.Origin != origin )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"A passkey {(ceremony.IsRegistration ? "registration" : "login")} started from '{ceremony.Origin}' is completed as a {(isRegistration ? "registration" : "login")} from '{origin}'." );
            (error, errorId) = ("This passkey operation has not been started here.", "Authentication.PasskeyCeremonyMismatch");
            return null;
        }
        return ceremony;
    }

    static T? Parse<T>( string json ) where T : class
    {
        try
        {
            return JsonSerializer.Deserialize<T>( json );
        }
        catch( Exception ex ) when( ex is JsonException or NotSupportedException or ArgumentException )
        {
            return null;
        }
    }

    // The WebAuthn names of the transports.
    static string ToString( AuthenticatorTransport t ) => t switch
    {
        AuthenticatorTransport.Usb => "usb",
        AuthenticatorTransport.Nfc => "nfc",
        AuthenticatorTransport.Ble => "ble",
        AuthenticatorTransport.SmartCard => "smart-card",
        AuthenticatorTransport.Hybrid => "hybrid",
        AuthenticatorTransport.Internal => "internal",
        _ => t.ToString().ToLowerInvariant()
    };

    static AuthenticatorTransport[] ToTransports( System.Collections.Generic.IReadOnlyList<string> transports )
    {
        return transports.Select( t => t switch
        {
            "usb" => (AuthenticatorTransport?)AuthenticatorTransport.Usb,
            "nfc" => AuthenticatorTransport.Nfc,
            "ble" => AuthenticatorTransport.Ble,
            "smart-card" => AuthenticatorTransport.SmartCard,
            "hybrid" => AuthenticatorTransport.Hybrid,
            "internal" => AuthenticatorTransport.Internal,
            _ => null
        } ).Where( t => t.HasValue ).Select( t => t!.Value ).ToArray();
    }
    #endregion
}
