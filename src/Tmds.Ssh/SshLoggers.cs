using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh;

sealed class SshLoggers
{
    public ILoggerFactory Factory { get; }

    public ILogger<SshClient> SshClientLogger { get; }

    public ILogger<LocalForward> DirectForwardLogger => Factory.CreateLogger<LocalForward>();

    public ILogger<SocksForward> SocksForwardLogger => Factory.CreateLogger<SocksForward>();

    public ILogger<RemoteForward> RemoteForwardLogger => Factory.CreateLogger<RemoteForward>();

    public SshLoggers(ILoggerFactory? loggerFactory = null)
    {
        Factory = loggerFactory ??= new NullLoggerFactory();

        SshClientLogger = loggerFactory.CreateLogger<SshClient>();
    }
}