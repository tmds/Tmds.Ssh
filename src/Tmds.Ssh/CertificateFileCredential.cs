// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

// internal class to represent a CertificateFile from an OpenSSH ssh_config file.
sealed class CertificateFileCredential : Credential
{
    internal string Path { get; }
    internal List<string>? IdentityFiles { get; }
    internal SshAgentCredentials? SshAgent { get; }

    public CertificateFileCredential(string path, List<string>? identityFiles, SshAgentCredentials? sshAgent)
    {
        ArgumentNullException.ThrowIfNull(path);

        Path = path;
        IdentityFiles = identityFiles;
        SshAgent = sshAgent;
    }
}
