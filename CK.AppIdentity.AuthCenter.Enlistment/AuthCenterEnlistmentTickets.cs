using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace CK.AppIdentity.AuthCenter.Enlistment;

/// <summary>
/// The enlistment tickets of the Authentication Center (<see cref="IEnlistmentTicketAuthority"/>): the System assumes a
/// star topology around it, the center holds the tickets of the parties that enlist. A ticket is kept as public data only
/// (its id, the expected party, its public key, its expiration, its operator, when and by which key it was used): one
/// json file per ticket in the "EnlistTickets" folder of the local store of the center. The expired tickets are forgotten
/// a week after their expiration.
/// </summary>
public sealed class AuthCenterEnlistmentTickets : IEnlistmentTicketAuthority
{
    /// <summary>
    /// The default lifetime of a ticket: 1 day.
    /// </summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromDays( 1 );

    /// <summary>
    /// The maximal lifetime of a ticket: 7 days.
    /// </summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromDays( 7 );

    const string _folderName = "EnlistTickets";
    static readonly TimeSpan _retention = TimeSpan.FromDays( 7 );

    sealed record Ticket( string Id, string PartyFullName, byte[] PublicKey, DateTime Opened, DateTime Expires, int OperatorActorId, DateTime? Used, string? UsedByFingerprint )
    {
        public bool IsOpen( DateTime utcNow ) => Used == null && Expires > utcNow;

        public EnlistmentTicketInfo ToInfo() => new( Id, PartyFullName, Opened, Expires, OperatorActorId, Used, UsedByFingerprint );
    }

    // The tickets of each center (by its full name), loaded on first use.
    readonly ConcurrentDictionary<string, Dictionary<string, Ticket>> _books = new( StringComparer.Ordinal );

    static bool IsCenter( ILocalParty local ) => local.GetFeature<CrisAuthCenter>()?.AuthCenter == local;

    Dictionary<string, Ticket>? GetBook( ILocalParty local )
    {
        if( !IsCenter( local ) ) return null;
        return _books.GetOrAdd( local.FullName.Path, _ => Load( local ) );
    }

    static NormalizedPath Folder( ILocalParty local ) => local.LocalFileStore.FolderPath.AppendPart( _folderName );

    static Dictionary<string, Ticket> Load( ILocalParty local )
    {
        var book = new Dictionary<string, Ticket>( StringComparer.Ordinal );
        var folder = Folder( local );
        if( !Directory.Exists( folder ) ) return book;
        var limit = local.ApplicationIdentityService.SystemClock.UtcNow - _retention;
        foreach( var f in Directory.EnumerateFiles( folder, "*.json" ) )
        {
            try
            {
                var t = JsonSerializer.Deserialize<Ticket>( File.ReadAllBytes( f ) );
                if( t == null ) continue;
                if( t.Expires < limit && t.Used == null || (t.Used != null && t.Used < limit) )
                {
                    File.Delete( f );
                    continue;
                }
                book[t.Id] = t;
            }
            catch( Exception ex ) when( ex is JsonException or IOException )
            {
                ActivityMonitor.StaticLogger.Warn( $"Invalid enlistment ticket file '{f}': ignored.", ex );
            }
        }
        return book;
    }

    static void Save( ILocalParty local, Ticket t )
    {
        var folder = Folder( local );
        local.LocalFileStore.CreateDirectory( folder );
        var bytes = JsonSerializer.SerializeToUtf8Bytes( t );
        local.LocalFileStore.WriteAtomically( folder.AppendPart( t.Id + ".json" ), s => s.Write( bytes ) );
    }

    /// <inheritdoc />
    public bool HasOpenTicket( ILocalParty local, string partyFullName )
    {
        var book = GetBook( local );
        if( book == null ) return false;
        var now = local.ApplicationIdentityService.SystemClock.UtcNow;
        lock( book ) return book.Values.Any( t => t.PartyFullName == partyFullName && t.IsOpen( now ) );
    }

    /// <inheritdoc />
    public bool TryUse( IParallelLogger logger,
                        ILocalParty local,
                        string partyFullName,
                        ReadOnlySpan<byte> proof,
                        KeyCheckpoint identity,
                        string keyFingerprint,
                        ReadOnlySpan<byte> ephemeralPublicKey )
    {
        var book = GetBook( local );
        if( book == null || proof.Length != EnlistTicket.ProofLength ) return false;
        var id = EnlistTicket.GetProofId( proof );
        var now = local.ApplicationIdentityService.SystemClock.UtcNow;
        lock( book )
        {
            if( !book.TryGetValue( id, out var t ) || t.PartyFullName != partyFullName || !t.IsOpen( now ) )
            {
                logger.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{partyFullName}' presents the enlistment ticket {id} of '{local}': it is not open for it." );
                return false;
            }
            if( !EnlistTicket.VerifyProof( t.PublicKey, proof, partyFullName, identity, local.FullName.Path, ephemeralPublicKey ) )
            {
                logger.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{partyFullName}' presents an invalid proof of the enlistment ticket {id} of '{local}'." );
                return false;
            }
            var used = t with { Used = now, UsedByFingerprint = keyFingerprint };
            book[id] = used;
            Save( local, used );
        }
        logger.Info( ActivityMonitor.Tags.SecurityCritical, $"The enlistment ticket {id} of '{local}' enlists '{partyFullName}' (key {keyFingerprint})." );
        return true;
    }

    /// <inheritdoc />
    public string? Open( IActivityMonitor monitor, ILocalParty local, string partyFullName, TimeSpan lifetime, int operatorActorId )
    {
        using var key = EnlistTicket.CreateKey( out var id );
        var expires = local.ApplicationIdentityService.SystemClock.UtcNow + ClampLifetime( lifetime );
        var checkpoint = Register( monitor, local, Convert.ToHexStringLower( id ), partyFullName, key.ExportSubjectPublicKeyInfo(), expires, operatorActorId );
        if( checkpoint == null ) return null;
        // The ticket owns a copy of the key (the "using" disposes this one).
        var owned = System.Security.Cryptography.ECDsa.Create( key.ExportParameters( true ) );
        using var ticket = EnlistTicket.Create( id, owned, local.FullName.Path, checkpoint, expires );
        return ticket.Encode();
    }

    /// <summary>
    /// Clamps a lifetime: <see cref="DefaultLifetime"/> when it is not positive, at most <see cref="MaxLifetime"/>.
    /// </summary>
    /// <param name="lifetime">The requested lifetime.</param>
    /// <returns>The lifetime.</returns>
    public static TimeSpan ClampLifetime( TimeSpan lifetime ) => lifetime <= TimeSpan.Zero ? DefaultLifetime : lifetime > MaxLifetime ? MaxLifetime : lifetime;

    /// <inheritdoc />
    public KeyCheckpoint? Register( IActivityMonitor monitor, ILocalParty local, string ticketId, string partyFullName, byte[] publicKey, DateTime expires, int operatorActorId )
    {
        var book = GetBook( local );
        if( book == null )
        {
            monitor.Warn( $"'{local}' is not an Authentication Center: it holds no enlistment ticket." );
            return null;
        }
        if( !CoreApplicationIdentity.TryParseFullName( partyFullName, out _, out _, out _ ) || partyFullName == local.FullName.Path )
        {
            monitor.Warn( $"Invalid party full name '{partyFullName}' for an enlistment ticket of '{local}'." );
            return null;
        }
        var now = local.ApplicationIdentityService.SystemClock.UtcNow;
        if( expires <= now || expires > now + MaxLifetime + TimeSpan.FromMinutes( 1 ) )
        {
            monitor.Warn( $"Invalid expiration {expires:u} of an enlistment ticket of '{local}' (at most {MaxLifetime.TotalDays} days)." );
            return null;
        }
        var t = new Ticket( ticketId, partyFullName, publicKey, now, expires, operatorActorId, null, null );
        lock( book )
        {
            if( book.ContainsKey( ticketId ) ) return null;
            book[ticketId] = t;
            Save( local, t );
        }
        var checkpoint = local.GetRequiredFeature<ILocalKeys>().Checkpoint;
        monitor.Info( ActivityMonitor.Tags.SecurityCritical,
                      $"'{local}' opens the enlistment ticket {ticketId} for '{partyFullName}' until {expires:u}, by actor #{operatorActorId} (anchor {checkpoint})." );
        return checkpoint;
    }

    /// <inheritdoc />
    public IReadOnlyList<EnlistmentTicketInfo> GetTickets( ILocalParty local )
    {
        var book = GetBook( local );
        if( book == null ) return [];
        lock( book ) return book.Values.OrderBy( t => t.Opened ).Select( t => t.ToInfo() ).ToList();
    }

    /// <inheritdoc />
    public bool Revoke( IActivityMonitor monitor, ILocalParty local, string ticketId )
    {
        var book = GetBook( local );
        if( book == null ) return false;
        lock( book )
        {
            if( !book.Remove( ticketId, out var t ) ) return false;
            local.LocalFileStore.TryTrash( monitor, Folder( local ).AppendPart( ticketId + ".json" ), immediateDelete: true );
            monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"'{local}' revokes the enlistment ticket {ticketId} of '{t.PartyFullName}'." );
            return true;
        }
    }
}
