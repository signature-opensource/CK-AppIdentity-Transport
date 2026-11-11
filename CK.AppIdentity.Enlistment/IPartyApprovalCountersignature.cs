using CK.Core;
using CK.IO.AppIdentity.Enlistment;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Enlistment;

/// <summary>
/// Optional service: the countersignature of an <see cref="IPartyApprovalStatement"/> by the Authentication Center
/// (implemented by CK.AppIdentity.AuthCenter.Enlistment). Without it, the statement is signed by the host only.
/// </summary>
public interface IPartyApprovalCountersignature : ISingletonAutoService
{
    /// <summary>
    /// On the host of the approval page, in the request of the operator: obtains the countersignature of the statement
    /// (the Authentication Center checks the operator's live proof).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the operator's request (its proof is sent with the request).</param>
    /// <param name="host">The local party that hosts the approval page.</param>
    /// <param name="statement">The statement, signed by the host.</param>
    /// <returns>
    /// Success false when a countersignature is required (the host has an Authentication Center) and can't be obtained;
    /// otherwise the countersignature (null when none is required).
    /// </returns>
    ValueTask<(bool Success, byte[]? Countersignature)> CountersignAsync( IActivityMonitor monitor,
                                                                        IServiceProvider services,
                                                                        ILocalParty host,
                                                                        IPartyApprovalStatement statement );

    /// <summary>
    /// On the holder of the pending approval: checks the countersignature of the statement. It is required when the holder
    /// has an Authentication Center (fail closed), ignored otherwise.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="holder">The local party that holds the pending approval.</param>
    /// <param name="statement">The statement.</param>
    /// <returns>True when the statement is accepted (countersigned, or no countersignature is required here).</returns>
    ValueTask<bool> VerifyAsync( IActivityMonitor monitor, ILocalParty holder, IPartyApprovalStatement statement );
}
