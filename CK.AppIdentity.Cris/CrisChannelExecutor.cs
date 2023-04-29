using CK.Cris;
using System;

namespace CK.AppIdentity.Cris
{
    public sealed class CrisChannelExecutor : CrisExecutor<CrisChannelExecutorRequest>
    {
        public CrisChannelExecutor( IServiceProvider serviceProvider, CommandValidator commandValidator, RawCommandExecutor commandExecutor )
            : base( serviceProvider, commandValidator, commandExecutor )
        {
        }
    }
}
