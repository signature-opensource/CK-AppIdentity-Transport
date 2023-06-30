using CK.Core;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    interface IOwnedPartyInternal : IOwnedParty
    {
        new LocalParty Owner { get; }
    }
}
