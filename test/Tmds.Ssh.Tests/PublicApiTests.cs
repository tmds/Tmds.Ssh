using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using PublicApiGenerator;

namespace Tmds.Ssh.Tests;

public class PublicApiTest
{
    [Fact]
    public Task PublicApi()
    {
        // Get the assembly for the library we want to document
        Assembly assembly = typeof(SshClient).Assembly;

        var options = new ApiGeneratorOptions
        {
            // These attributes won't be included in the public API
            ExcludeAttributes =
            [
                typeof(InternalsVisibleToAttribute).FullName!,
                "System.Runtime.CompilerServices.IsByRefLike",
                typeof(TargetFrameworkAttribute).FullName!,
            ],
            // By default types found in Microsoft or System 
            // namespaces are not treated as part of the public API.
            // By passing an empty array, we ensure they're all 
            DenyNamespacePrefixes = []
        };

        var publicApi = assembly.GeneratePublicApi(options);

        // Run a snapshot test on the returned string
        var settings = new VerifySettings();
        settings.UniqueForRuntime();
        return Verifier.Verify(publicApi, settings);
    }
}
