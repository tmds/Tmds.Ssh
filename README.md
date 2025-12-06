[![NuGet](https://img.shields.io/nuget/v/Tmds.Ssh.svg)](https://www.nuget.org/packages/Tmds.Ssh)

# Tmds.Ssh

`Tmds.Ssh` is a modern, managed .NET SSH client library for .NET 6+.

Documentation: https://tmds.github.io/Tmds.Ssh

Releases: https://github.com/tmds/Tmds.Ssh/releases

## Design

* Since SSH is a network protocol, the APIs are asynchronous and implemented using C# `async` and .NET's `Task`/`ValueTask`.

* For cryptographic algorithms, we use the BCL (.NET base classes) when available and otherwise we use a 3rd party library ([Bouncy Castle.NET](https://github.com/bcgit/bc-csharp)). For security reasons, we avoid implementing cryptographic algorithms ourselves*.

* The library aims to solve common SSH client use-cases similar to functionality offered by CLI tools like `ssh` and `sftp`. We do not provide an API at the SSH protocol level that enables sending custom messages or provide APIs to enable custom encryption algorithms. Such APIs are required only for a small set of use-cases but require a much larger API surface to be maintained. By keep this API internal, we are free to change it.

* SSH cryptographic algorithms continue to evolve. We aim to enable connectivity with SSH servers that (by current standards) support a secure set of algorithms. We do not add support for older (less secure/insecure) algorithms that should no longer be used.

* Performance is a goal. We aim to minimize allocations by using modern .NET primitives like `Span`. For SSH operations, we try to minimize latency and maximize throughput.

* Besides the SSH connection, SSH applications must deal with private keys, known hosts, connection configuration, ... The library supports using [OpenSSH](https://www.openssh.com/) file formats to deal with these concerns. This provides a familiar mechanism to developers and end-users that is compatible with the OpenSSH software stack. Using the OpenSSH formats is optional, developers can choose implement their own configuration.

*: (For historic reasons) some cryptographic algorithms are included for decoding private key files. We don't consider these to impact security in any way.

## CI Feed

You can obtain packages from the CI NuGet feed: https://www.myget.org/F/tmds/api/v3/index.json.
