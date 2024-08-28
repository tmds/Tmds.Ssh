// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Reflection;

namespace Tmds.Ssh;

sealed partial class SshSession
{
    private async Task ProtocolVersionExchangeAsync(SshConnection connection, CancellationToken ct)
    {
        // Protocol Version Exchange: https://tools.ietf.org/html/rfc4253#section-4.2.

        // The maximum length of the string is 255 characters, including the Carriage Return and Line Feed.
        const int MaxLineLength = 255 - 2;
        // The server MAY send other lines of data before sending the version string.
        const int MaxLineReads = 20;

        AssemblyInformationalVersionAttribute? versionAttribute = typeof(SshSession).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>();
        string version = versionAttribute?.InformationalVersion ?? "0.0";
        version = version.Replace('-', '_');
        string identificationString = $"SSH-2.0-TmdsSsh_{version}";
        ConnectionInfo.ClientIdentificationString = identificationString;

        // Send our identification string.
        Logger.LocalVersion(identificationString);
        await connection.WriteLineAsync(identificationString, ct).ConfigureAwait(false);

        // Receive peer identification string.
        for (int i = 0; i < MaxLineReads; i++)
        {
            string line = await connection.ReceiveLineAsync(MaxLineLength, ct).ConfigureAwait(false);
            Logger.RemoteVersion(line);
            if (line.StartsWith("SSH-", StringComparison.Ordinal))
            {
                ConnectionInfo.ServerIdentificationString = line;
                if (line.StartsWith("SSH-2.0-", StringComparison.Ordinal))
                {
                    return;
                }
                ThrowHelper.ThrowProtocolUnsupportedVersion(line);
            }
        }
        ThrowHelper.ThrowProtocolNoVersionIdentificationString();
    }
}
