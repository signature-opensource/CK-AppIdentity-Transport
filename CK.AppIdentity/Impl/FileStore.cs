using CK.Core;
using System;
using System.IO;

namespace CK.AppIdentity
{
    sealed class FileStore : IFileStore
    {
        NormalizedPath _folderPath;
        NormalizedPath _binPath;

        internal FileStore( in NormalizedPath folderPath )
        {
            _folderPath = folderPath;
            _binPath = folderPath.AppendPart( "$TrashBin" );
            Directory.CreateDirectory( _folderPath );
        }

        public NormalizedPath FolderPath => _folderPath;

        public NormalizedPath TrashBinPath => _binPath;

        public bool TryTrash( IActivityLineEmitter logger, in NormalizedPath fullPath, bool immediateDelete = false )
        {
            Throw.CheckArgument( fullPath.StartsWith( FolderPath ) && !fullPath.StartsWith( TrashBinPath ) );
            if( !File.Exists( fullPath ) ) return true;
            if( immediateDelete ) return TryDelete( logger, fullPath );
            var targetPath = $"{_binPath.Path}/{Guid.NewGuid()}{Path.GetExtension( fullPath.Path )}";
            try
            {
                Directory.CreateDirectory( _binPath );
                File.Move( fullPath, targetPath );
                File.WriteAllText( targetPath + ".binInfo", fullPath.RemovePrefix( _folderPath ) );
                return true;
            }
            catch( Exception ex )
            {
                logger.Error( $"While moving '{fullPath}' to the trash bin.", ex );
                return false;
            }
        }

        bool TryDelete( IActivityLineEmitter logger, NormalizedPath fullPath )
        {
            try
            {
                File.Delete( fullPath );
                return true;
            }
            catch( Exception ex )
            {
                logger.Error( $"While deleting file '{fullPath}'.", ex );
                return false;
            }
        }

        internal void OnShutdownOrDestroyed( IActivityMonitor monitor, bool isDestroyed )
        {
            // TODO: $TrashBin housekeeping.
        }

    }
}
