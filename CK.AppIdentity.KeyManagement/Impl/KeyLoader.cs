using CK.Core;
using System;
using System.Collections.Generic;
using System.IO;

namespace CK.AppIdentity.KeyManagement
{
    abstract class KeyLoader
    {
        protected IFileStore _store;

        protected KeyLoader( IFileStore store )
        {
            _store = store;
        }

        protected IEnumerable<(string Name, DateTime timeName, string Path)> FilterFileNames( IActivityMonitor monitor, DateTime now, IEnumerable<string> candidates )
        {
            foreach( var path in candidates )
            {
                var name = Path.GetFileNameWithoutExtension( path );
                if( !FileUtil.TryParseFileNameUniqueTimeUtcFormat( name, out var timeName ) )
                {
                    LogAndCleanup( monitor, path, $"Invalid file name '{path}': the name must strictly be in '{FileUtil.FileNameUniqueTimeUtcFormat}' " +
                                                     $"format (based on the certificate's UTC creation time).", LogLevel.Error );
                }
                else if( timeName >= now )
                {
                    LogAndCleanup( monitor, path, $"Invalid file name '{path}': the date must be in the past (now is: {now.ToString( FileUtil.FileNameUniqueTimeUtcFormat )}).", LogLevel.Error );
                }
                else yield return (name, timeName, path);
            }
        }

        protected void LogAndCleanup( IActivityMonitor monitor, string path, string message, LogLevel level = LogLevel.Warn, Exception? ex = null, CKTrait? tags = null )
        {
            monitor.Log( level, tags ?? ActivityMonitor.Tags.Empty, $"{message}. Skipping it and sending it to the '$TrashBin' folder.", ex );
            DoTrash( monitor, path );
        }

        protected virtual void DoTrash( IActivityMonitor monitor, string path )
        {
            _store.TryTrash( monitor, path );
        }
    }
}
