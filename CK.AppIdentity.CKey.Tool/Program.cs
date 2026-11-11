using CK.AppIdentity.CKey.Tool;
using System;

return await CKeyTool.RunAsync( args, Console.Out, Console.Error, ConsolePassword.Read, AppContext.BaseDirectory );
