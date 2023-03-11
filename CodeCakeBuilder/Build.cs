
using Cake.Common.Solution;
using Cake.Core;
using Cake.Core.Diagnostics;
using SimpleGitVersion;
using System.Linq;

namespace CodeCake
{
    /// <summary>
    /// Standard build "script".
    /// </summary>
    
    public partial class Build : CodeCakeHost
    {
        public Build()
        {
            Cake.Log.Verbosity = Verbosity.Diagnostic;
            StandardGlobalInfo globalInfo = CreateStandardGlobalInfo()
                                                .AddDotnet()
                                                .SetCIBuildTag();
            Task( "Check-Repository" )
                .Does( () =>
                {
                    globalInfo.TerminateIfShouldStop();
                } );

            Task( "Clean" )
                .IsDependentOn( "Check-Repository" )
                .Does( () =>
                {
                    globalInfo.GetDotnetSolution().Clean();
                } );


            Task( "Build" )
                .IsDependentOn( "Check-Repository" )
                .IsDependentOn( "Clean" )
                .Does( () =>
                {
                    globalInfo.GetDotnetSolution().Build();
                } );

            Task( "Unit-Testing" )
                .IsDependentOn( "Build" )
                .WithCriteria( () => Cake.InteractiveMode() == InteractiveMode.NoInteraction
                                     || Cake.ReadInteractiveOption( "RunUnitTests", "Run Unit Tests?", 'Y', 'N' ) == 'Y' )
               .Does( () =>
               {
                   globalInfo.GetDotnetSolution().Test();
               } );

            Task( "Create-Packages" )
                .WithCriteria( () => globalInfo.IsValid )
                .IsDependentOn( "Unit-Testing" )
                .Does( () =>
                {
                    globalInfo.GetDotnetSolution().Pack();
                } );

            Task( "Push-Packages" )
                .WithCriteria( () => globalInfo.IsValid )
                .IsDependentOn( "Create-Packages" )
                .Does( async () =>
                {
                    await globalInfo.PushArtifactsAsync();
                } );

            // The Default task for this script can be set here.
            Task( "Default" )
                .IsDependentOn( "Push-Packages" );

        }


    }
}
