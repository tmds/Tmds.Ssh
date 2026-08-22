using Tmds.Utils;

namespace Tmds.Ssh.Tests;

internal class Program
{
    public static int Main(string[] args)
    {
        // Check if this is an ExecFunction command
        if (ExecFunction.IsExecFunctionCommand(args))
        {
            return ExecFunction.Program.Main(args);
        }

        if (args.Any(arg => arg == "--server" || arg == "--internal-msbuild-node"))
            return Xunit.MicrosoftTestingPlatform.TestPlatformTestFramework
                .RunAsync(args, SelfRegisteredExtensions.AddSelfRegisteredExtensions)
                .GetAwaiter().GetResult();
        else
            return Xunit.Runner.InProc.SystemConsole.ConsoleRunner.Run(args)
                .GetAwaiter().GetResult();
    }
}
