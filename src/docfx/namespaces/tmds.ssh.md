---
uid: Tmds.Ssh
summary: *content
---

## Main Types

The library provides two client types:

- <xref:Tmds.Ssh.SshClient> - For connecting to SSH servers to execute remote commands, forward connections, and perform filesystem operations.
- <xref:Tmds.Ssh.SftpClient> - For performing filesystem operations on SSH servers using SFTP (SSH File Transfer Protocol).

The documentation for both types includes examples to help you get started.

## Logging

The library supports logging through `Microsoft.Extensions.Logging`.

In production, the log level should be set to `Information` or higher.

Under these levels, the logged messages may include:
- usernames
- hostnames
- key types
- authentication methods
- public keys
- file paths (including those of private keys)

The `Debug` and `Trace` loglevels should not be used in production. Under the `Trace` level all packets are logged. This will expose sensitive data related to the SSH connection and the application itself.
