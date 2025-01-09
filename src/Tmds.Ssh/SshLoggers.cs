using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh;

sealed class SshLoggers
{
    public ILoggerFactory Factory { get; }

    public ILogger<SshClient> SshClientLogger { get; }

    public ILogger<DirectForward> DirectForwardLogger => Factory.CreateLogger<DirectForward>();

    public ILogger<SocksForward> SocksForwardLogger => Factory.CreateLogger<SocksForward>();

    public SshLoggers(ILoggerFactory? loggerFactory = null)
    {
        Factory = loggerFactory ??= new NullLoggerFactory();

        SshClientLogger = loggerFactory.CreateLogger<SshClient>();
    }
}