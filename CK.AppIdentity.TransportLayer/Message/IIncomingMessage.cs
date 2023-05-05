namespace CK.AppIdentity.TransportLayer
{
    public interface IIncomingMessage : IMessage
    {
        bool IsValid { get; }
    }
}
