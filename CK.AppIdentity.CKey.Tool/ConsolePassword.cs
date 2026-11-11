using System;
using System.Text;

namespace CK.AppIdentity.CKey.Tool;

/// <summary>
/// Reads a password on the console, without echo.
/// </summary>
public static class ConsolePassword
{
    /// <summary>
    /// Reads a password on the console (not echoed). Null when there is no interactive console (the input is redirected):
    /// the password must then be given by "--pwd".
    /// </summary>
    /// <param name="prompt">The prompt.</param>
    /// <returns>The password, or null.</returns>
    public static string? Read( string prompt )
    {
        if( Console.IsInputRedirected ) return null;
        Console.Error.Write( prompt );
        var b = new StringBuilder();
        for( ; ; )
        {
            var k = Console.ReadKey( intercept: true );
            if( k.Key == ConsoleKey.Enter ) break;
            if( k.Key == ConsoleKey.Backspace )
            {
                if( b.Length > 0 ) b.Length--;
            }
            else if( !char.IsControl( k.KeyChar ) )
            {
                b.Append( k.KeyChar );
            }
        }
        Console.Error.WriteLine();
        return b.ToString();
    }
}
