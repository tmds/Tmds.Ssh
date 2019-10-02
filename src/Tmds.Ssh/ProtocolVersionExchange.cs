// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    internal delegate Task ExchangeProtocolVersionAsyncDelegate(SshConnection sshConnection, SshConnectionInfo connectionInfo, ILogger logger, SshClientSettings settings, CancellationToken token);
    sealed class ProtocolVersionExchange
    {
        public static readonly ExchangeProtocolVersionAsyncDelegate Default = PerformDefaultExchange;

        private static async Task PerformDefaultExchange(SshConnection sshConnection, SshConnectionInfo connectionInfo, ILogger logger, SshClientSettings settings, CancellationToken ct)
        {
            // Protocol Version Exchange: https://tools.ietf.org/html/rfc4253#section-4.2.

            // The maximum length of the string is 255 characters, including the Carriage Return and Line Feed.
            const int MaxLineLength = 255 - 2;
            // The server MAY send other lines of data before sending the version string.
            const int MaxLineReads = 20;

            AssemblyInformationalVersionAttribute? versionAttribute = typeof(SshClient).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>();
            string version = versionAttribute?.InformationalVersion ?? "0.0";
            version = version.Replace('-', '_');
            string identificationString = $"SSH-2.0-TmdsSsh_{version}";
            connectionInfo.ClientIdentificationString = identificationString;

            // Send our identification string.
            logger.LogInformation("Local version string {identificationString}", identificationString);
            await sshConnection.WriteLineAsync(identificationString, ct);

            // Receive peer identification string.
            for (int i = 0; i < MaxLineReads; i++)
            {
                string line = await sshConnection.ReceiveLineAsync(MaxLineLength, ct);
                if (line.StartsWith("SSH-", StringComparison.Ordinal))
                {
                    connectionInfo.ServerIdentificationString = line;
                    if (line.StartsWith("SSH-2.0-", StringComparison.Ordinal))
                    {
                        logger.LogInformation("Remote version string {identificationString}", connectionInfo.ServerIdentificationString);
                        return;
                    }
                    ThrowHelper.ThrowProtocolUnsupportedVersion(line);
                }
            }
            ThrowHelper.ThrowProtocolNoVersionIdentificationString();
        }
    }
}