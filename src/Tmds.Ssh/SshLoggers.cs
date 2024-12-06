using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh;

sealed class SshLoggers
{
    private readonly ILoggerFactory _loggerFactory;

    public ILogger<SshClient> SshClientLogger { get; }

    public ILogger<LocalForward> GetLocalPortForwardLogger() => _loggerFactory.CreateLogger<LocalForward>();

    public SshLoggers(ILoggerFactory? loggerFactory = null)
    {
        _loggerFactory = loggerFactory ??= new NullLoggerFactory();

        SshClientLogger = loggerFactory.CreateLogger<SshClient>();
    }
}