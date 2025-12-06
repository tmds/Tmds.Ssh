`Tmds.Ssh` is a modern, managed .NET SSH client library for .NET.

## Getting Started

To start using the library in your application, see [Getting Started](getting-started.md).

To try out the library with an SSH server before writing any code, check out the [.NET Tools](tools.md).

## Features

**SSH Operations**
- Execute remote commands
- Interactive shell support
- Connection forwarding
- SFTP support for file operations

**Flexible Authentication**
- Public key authentication
- SSH Agent support
- OpenSSH certificate authentication
- Password authentication
- Kerberos authentication

**OpenSSH Compatibility**
- Supports OpenSSH private key formats and configuration files
- Compatible with `known_hosts` for host key verification

**Security First**
- Secure cryptographic algorithms (no legacy/insecure algorithms)
- Post-quantum key exchange support
- Uses BCL and Bouncy Castle for cryptography—no custom crypto implementations

**Modern .NET**
- Built from the ground up with C# `async`/`await` and `Task`/`ValueTask` for efficient asynchronous operations
- Optimized for performance with .NET primitives like `Span<T>` to minimize allocations
- Integration with `Microsoft.Extensions.Logging`

## Supported Algorithms

This section lists the supported algorithms. If you would like support for other algorithms, you can request it with [an issue in the repository](https://github.com/tmds/Tmds.Ssh/issues). If the requested algorithm is considered insecure by current practice, it is unlikely to be added.

Private key formats*:
- RSA, ECDSA, ED25519 in `OPENSSH PRIVATE KEY` (`openssh-key-v1`) with encryption:
  - none
  - aes[128|192|256]-[cbc|ctr]
  - aes[128|256]-gcm@openssh.com
  - chacha20-poly1305@openssh.com

Client key algorithms:
- ssh-ed25519-cert-v01@openssh.com
- ecdsa-sha2-nistp521-cert-v01@openssh.com
- ecdsa-sha2-nistp384-cert-v01@openssh.com
- ecdsa-sha2-nistp256-cert-v01@openssh.com
- rsa-sha2-512-cert-v01@openssh.com
- rsa-sha2-256-cert-v01@openssh.com
- ssh-ed25519
- ecdsa-sha2-nistp521
- ecdsa-sha2-nistp384
- ecdsa-sha2-nistp256
- rsa-sha2-512
- rsa-sha2-256

Server key algorithms:
- ssh-ed25519-cert-v01@openssh.com
- ecdsa-sha2-nistp521-cert-v01@openssh.com
- ecdsa-sha2-nistp384-cert-v01@openssh.com
- ecdsa-sha2-nistp256-cert-v01@openssh.com
- rsa-sha2-512-cert-v01@openssh.com
- rsa-sha2-256-cert-v01@openssh.com
- ssh-ed25519
- ecdsa-sha2-nistp521
- ecdsa-sha2-nistp384
- ecdsa-sha2-nistp256
- rsa-sha2-512
- rsa-sha2-256

Key exchange methods:
- mlkem768x25519-sha256
- sntrup761x25519-sha512, sntrup761x25519-sha512@openssh.com
- curve25519-sha256, curve25519-sha256@libssh.org
- ecdh-sha2-nistp256
- ecdh-sha2-nistp384
- ecdh-sha2-nistp521

Encryption algorithms:
- aes256-gcm@openssh.com
- aes128-gcm@openssh.com
- chacha20-poly1305@openssh.com

Message authentication code algorithms:
- none

Compression algorithms:
- none

Authentications:
- publickey (<xref:Tmds.Ssh.PrivateKeyCredential>)
- publickey from SSH Agent (<xref:Tmds.Ssh.SshAgentCredentials>)
- publickey with OpenSSH certificate (<xref:Tmds.Ssh.CertificateCredential>)
- password (<xref:Tmds.Ssh.PasswordCredential>)
- gssapi-with-mic (<xref:Tmds.Ssh.KerberosCredential>)
- none (<xref:Tmds.Ssh.NoCredential>)

*: Please convert your keys (using `ssh-keygen`, `PuttyGen`, ...) to a supported format rather than suggesting the library should support an additional format. If you can motivate why the library should support a additional format, open an issue to request support.

