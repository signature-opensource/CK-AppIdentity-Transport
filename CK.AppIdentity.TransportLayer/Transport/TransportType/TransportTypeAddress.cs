namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Simple immutable encapsulation of a <see cref="TransportTypeService"/> and an address that it understands.
    /// </summary>
    /// <param name="Type">The transport type.</param>
    /// <param name="TypedAddress">Specific address type.</param>
    public sealed record class TransportTypeAddress( TransportTypeService Type, object TypedAddress );

}
