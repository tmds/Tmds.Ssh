using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh;

sealed class SshLoggers
{
    private readonly ILoggerFactory _loggerFactory;

    public ILogger<SshClient> SshClientLogger { get; }

    public ILogger<DirectForward> DirectForwardLogger => _loggerFactory.CreateLogger<DirectForward>();

    public ILogger<SocksForward> SocksForwardLogger => _loggerFactory.CreateLogger<SocksForward>();

    public SshLoggers(ILoggerFactory? loggerFactory = null)
    {
        _loggerFactory = loggerFactory ??= new NullLoggerFactory();

        SshClientLogger = loggerFactory.CreateLogger<SshClient>();
    }
}