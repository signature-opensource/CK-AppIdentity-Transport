using System;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// A software WebAuthn authenticator (ES256, discoverable credential, attestation "none"): it answers the options of the
/// Authentication Center with the JSON of <c>credential.toJSON()</c>, signed for real. Its knobs break one rule at a time.
/// </summary>
public sealed class SoftAuthenticator : IDisposable
{
    readonly ECDsa _key = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
    readonly byte[] _credentialId = RandomNumberGenerator.GetBytes( 16 );
    byte[]? _userHandle;

    /// <summary>
    /// Gets or sets the origin written in the client data (what the browser signs).
    /// </summary>
    public string Origin { get; set; } = "https://front.example.com";

    /// <summary>
    /// Gets or sets the relying party whose hash is written in the authenticator data. Null: the one of the options.
    /// </summary>
    public string? RpId { get; set; }

    /// <summary>
    /// Gets or sets whether the user is verified (the UV flag).
    /// </summary>
    public bool UserVerified { get; set; } = true;

    /// <summary>
    /// Gets or sets the signature counter (0 like a synchronized passkey): it is incremented before each assertion when
    /// not 0.
    /// </summary>
    public uint SignCount { get; set; }

    /// <summary>
    /// Gets the credential identifier.
    /// </summary>
    public ReadOnlyMemory<byte> CredentialId => _credentialId;

    /// <summary>
    /// Creates the credential: answers the creation options (navigator.credentials.create).
    /// </summary>
    /// <param name="optionsJson">The creation options.</param>
    /// <returns>The JSON response.</returns>
    public string Create( string optionsJson )
    {
        var options = JsonNode.Parse( optionsJson )!;
        _userHandle = Base64Url.DecodeFromChars( options["user"]!["id"]!.GetValue<string>() );
        var rpId = RpId ?? options["rp"]!["id"]!.GetValue<string>();
        var clientData = ClientData( "webauthn.create", options["challenge"]!.GetValue<string>() );

        var p = _key.ExportParameters( false );
        var cose = new CborWriter( CborConformanceMode.Lax );
        cose.WriteStartMap( 5 );
        cose.WriteInt32( 1 ); cose.WriteInt32( 2 );    // kty: EC2
        cose.WriteInt32( 3 ); cose.WriteInt32( -7 );   // alg: ES256
        cose.WriteInt32( -1 ); cose.WriteInt32( 1 );   // crv: P-256
        cose.WriteInt32( -2 ); cose.WriteByteString( p.Q.X! );
        cose.WriteInt32( -3 ); cose.WriteByteString( p.Q.Y! );
        cose.WriteEndMap();

        var authData = new List<byte>( AuthenticatorData( rpId, attested: true ) );
        authData.AddRange( new byte[16] ); // AAGUID: none.
        authData.Add( (byte)(_credentialId.Length >> 8) );
        authData.Add( (byte)_credentialId.Length );
        authData.AddRange( _credentialId );
        authData.AddRange( cose.Encode() );

        var attestation = new CborWriter( CborConformanceMode.Lax );
        attestation.WriteStartMap( 3 );
        attestation.WriteTextString( "fmt" ); attestation.WriteTextString( "none" );
        attestation.WriteTextString( "attStmt" ); attestation.WriteStartMap( 0 ); attestation.WriteEndMap();
        attestation.WriteTextString( "authData" ); attestation.WriteByteString( authData.ToArray() );
        attestation.WriteEndMap();

        return Json( new JsonObject
        {
            ["clientDataJSON"] = Base64Url.EncodeToString( clientData ),
            ["attestationObject"] = Base64Url.EncodeToString( attestation.Encode() ),
            ["transports"] = new JsonArray( "internal", "hybrid" )
        } );
    }

    /// <summary>
    /// Signs an assertion: answers the request options (navigator.credentials.get).
    /// </summary>
    /// <param name="optionsJson">The request options.</param>
    /// <returns>The JSON response.</returns>
    public string Get( string optionsJson )
    {
        var options = JsonNode.Parse( optionsJson )!;
        var rpId = RpId ?? options["rpId"]!.GetValue<string>();
        var clientData = ClientData( "webauthn.get", options["challenge"]!.GetValue<string>() );
        if( SignCount != 0 ) ++SignCount;
        var authData = AuthenticatorData( rpId, attested: false );
        var signed = new byte[authData.Length + 32];
        authData.CopyTo( signed, 0 );
        SHA256.HashData( clientData ).CopyTo( signed, authData.Length );
        var signature = _key.SignData( signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence );
        return Json( new JsonObject
        {
            ["clientDataJSON"] = Base64Url.EncodeToString( clientData ),
            ["authenticatorData"] = Base64Url.EncodeToString( authData ),
            ["signature"] = Base64Url.EncodeToString( signature ),
            ["userHandle"] = Base64Url.EncodeToString( _userHandle ?? throw new InvalidOperationException( "Not created." ) )
        } );
    }

    byte[] ClientData( string type, string challenge )
    {
        return Encoding.UTF8.GetBytes( new JsonObject { ["type"] = type, ["challenge"] = challenge, ["origin"] = Origin, ["crossOrigin"] = false }.ToJsonString() );
    }

    byte[] AuthenticatorData( string rpId, bool attested )
    {
        var data = new byte[37];
        SHA256.HashData( Encoding.UTF8.GetBytes( rpId ) ).CopyTo( data, 0 );
        // UP, BE and BS (a synchronized passkey), UV when verified, AT for a creation.
        data[32] = (byte)(0x01 | 0x08 | 0x10 | (UserVerified ? 0x04 : 0) | (attested ? 0x40 : 0));
        BinaryPrimitives.WriteUInt32BigEndian( data.AsSpan( 33 ), SignCount );
        return data;
    }

    string Json( JsonObject response )
    {
        var id = Base64Url.EncodeToString( _credentialId );
        return new JsonObject
        {
            ["id"] = id,
            ["rawId"] = id,
            ["type"] = "public-key",
            ["response"] = response,
            ["clientExtensionResults"] = new JsonObject()
        }.ToJsonString();
    }

    public void Dispose() => _key.Dispose();
}
