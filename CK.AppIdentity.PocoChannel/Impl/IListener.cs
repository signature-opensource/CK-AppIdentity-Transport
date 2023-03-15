namespace CK.AppIdentity.PocoChannel
{
    interface IListener
    {
        IReadOnlyList<IRemoteParty> Parties { get; }
    }
}
