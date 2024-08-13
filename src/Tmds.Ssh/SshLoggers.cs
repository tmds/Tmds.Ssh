using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tmds.Ssh;

sealed class SshLoggers
{
    public ILogger<SshClient> SshClientLogger { get; }

    public SshLoggers(ILoggerFactory? loggerFactory = null)
    {
        loggerFactory ??= new NullLoggerFactory();

        SshClientLogger = loggerFactory.CreateLogger<SshClient>();
    }
}