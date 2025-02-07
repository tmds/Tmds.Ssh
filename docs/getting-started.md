# Getting Started

The following topics are covered in this document:
- Introduction to SSH
- Running an SSH server
- Setting up client keys
- Connecting using `Tmds.Ssh`

## SSH

SSH (Secure Shell or Secure Socket Shell) is an (IETF-)standard network protocol for running commands, manage files, and forward connections.

SSH is supported on many operating systems including Linux, Windows, and macOS. Most often these OSes include the [OpenSSH](https://www.openssh.com/) implementation which includes both an SSH server, client programs (like `ssh` and `sftp`), and utilites (like `ssh-keygen` for generating keys).

Besides servers and PCs, SSH is also often found on (Linux-)based appliances, like a NAS, a KODI-based streaming device, an OpenWRT router, a network switch, .... Such appliances may run OpenSSH, or they may run a smaller SSH server like [tinyssh](https://tinyssh.org/) or [Dropbear](https://matt.ucc.asn.au/dropbear/dropbear.html).

SSH uses [public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography) to authenticate the remote computer. In short, this means the client expects the server to use certain public key(s), and the server can prove it owns those keys by signing data using the corresponding private key.

For authenticating the client, public-key may be used as well (the server is then configured to accept certain public keys for a user). When the client is using a public-key, the private key can be stored encrypted in the file system using a password/passphrase. It is also possible to use a key manager, which is called an SSH Agent. Other mechanisms (like passwords) can also be used to authenticate clients.

## Running an SSH server

To run an SSH server, you must follow the documentation of the operating system. Typically it involves installing the SSH server, and then configuring the system to start it.

For example, on Fedora you can install the OpenSSH package and configure systemd to start the server with the following commands:
```
dnf install -y openssh-server
systemctl start sshd
systemctl enable sshd
```

## Setting up client keys

If you won't be using public-key to authenticate your client, you can skip to the next section.

### Generating a key

To generate an SSH key, you can run the OpenSSH `ssh-keygen` tool. The tool will prompt for a passphrase, which is the password that is used to encrypt/decrypt the private key. You can leave this prompt empty for an unencrypted private key. By default, the key will be placed at a location under a `~/.ssh` that is automatically picked up by OpenSSH. The key is split into two files. One will hold the private key with permissions configured to only allow access to the user, and the other (with the `.pub` extension) holds the public key and is readable for others.

The following output shows generation of a key using `ssh-keygen` in the default location for an RSA key: `~/.ssh/id_rsa` (for the private part), `~/.ssh/id_rsa` (for the public part).

```
$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/tmds/.ssh/id_rsa): 
Created directory '/home/tmds/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/tmds/.ssh/id_rsa.
Your public key has been saved in /home/tmds/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:XVbJHhkAQzWAecTjzMhALJH8vngKokO6wL+BXZdQeq0 tmds@dcd14c1a5bdd
The key's randomart image is:
+---[RSA 3072]----+
|   ..=.. **++oo+ |
|    + = + +. o=  |
|     = + B .o. . |
|      + =.+o  .  |
|     o ES .      |
|..o . o          |
|=o.o . .         |
|=...o o          |
|oo ooo           |
+----[SHA256]-----+
```

### Trusting the client key on the server

Once we have a client key, we can configure an SSH server to trust that key. The configuration depends on the SSH server. For example, when accessing GitHub/GitLab repos via SSH, the public key would be entered as part of the user configuration on those platforms.

An OpenSSH server trust keys for a user when they are in the user's `~/.ssh/authorized_keys` file. So, in order to allow login with a certain key, we need to add the contents of the `<key>.pub` file on the remote server. To do this, we can for example log into the server using a password and then edit that file.

Get the public key contents:

```
$ cat ~/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEKi0HLx5M/5RJDtBoqB1VVWeKJ1hB+Llw+wLJ04mJBqoWzL0O5Y5wMOz2wPXhJJhhh8TQucuNjhL0nT93O23cV9ub45xc51pJjKEz1avyv7dsyoPepAohaO3Fieh4o4jPxzzj8l4dHIVAu/OkBY/GN+TamEJGQRD2NrLnDQTOUDZLLYF05Ya3c9XPBFY77XstD9dmsMKMjYL7MAU4wZI01HR9Y/3LMTT2+jQhYU1Oxps6v9I6YKc1LXfJKP2MLDJL+gg2CifmKU4INwChUh7b4Xti2S+oFnjBMSKvREJg7bCMrv/gRmRoci1/j+VeE2gWZI7y62oylRg0Ml1czQVhtf1SsddWIo+40MRT+oRrFdr57CsDDC7KjXR6EYLpbSOSiUem6fj5rWznER1ZiCLtCYHTzjx9keLiyPWysMoQmhOXEHAdsnFLctDUQNvxK4rY+hFXBjmvWRq0Zlxtdf5JO93j5d2qlGjNXkt1iH9Hq8iJVwb2/tzYud15nky4KwM= tmds@dcd14c1a5bdd
```

Add it to `~/.ssh/authorized_keys` on the remote server using a password login:

```
$ ssh <[user@]remoteserver>
<[user@]remoteserver>'s password: 
$ mkdir -m 700 -p ~/.ssh
$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEKi0HLx5M/5RJDtBoqB1VVWeKJ1hB+Llw+wLJ04mJBqoWzL0O5Y5wMOz2wPXhJJhhh8TQucuNjhL0nT93O23cV9ub45xc51pJjKEz1avyv7dsyoPepAohaO3Fieh4o4jPxzzj8l4dHIVAu/OkBY/GN+TamEJGQRD2NrLnDQTOUDZLLYF05Ya3c9XPBFY77XstD9dmsMKMjYL7MAU4wZI01HR9Y/3LMTT2+jQhYU1Oxps6v9I6YKc1LXfJKP2MLDJL+gg2CifmKU4INwChUh7b4Xti2S+oFnjBMSKvREJg7bCMrv/gRmRoci1/j+VeE2gWZI7y62oylRg0Ml1czQVhtf1SsddWIo+40MRT+oRrFdr57CsDDC7KjXR6EYLpbSOSiUem6fj5rWznER1ZiCLtCYHTzjx9keLiyPWysMoQmhOXEHAdsnFLctDUQNvxK4rY+hFXBjmvWRq0Zlxtdf5JO93j5d2qlGjNXkt1iH9Hq8iJVwb2/tzYud15nky4KwM= root@dcd14c1a5bdd' >>~/.ssh/authorized_keys
$ exit
```

Once you've added your key to the server, you can consider to configure the remote server so it no longer allows password login.

### Trusting the server key on the client

To trust the server key on the local machine, we'll invoke the `ssh` command to connect to the remote server so it prompts to trust the server key.

```
$ ssh <[user@]remoteserver> exit
The authenticity of host '<remoteserver>' can't be established.
ED25519 key fingerprint is SHA256:BkEYx77wOyUBL8UZfgoYKPLkwLJ7XMrsTwAu5sQC4C8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

By entering `yes`, the key will be included in the `~/.ssh/known_hosts` file for `<remoteserver>`. The next time when we log into that server, the public key can be checked against the one stored in the `known_hosts` file.

## Connecting using Tmds.Ssh

Create a new console project:
```
$ dotnet new console -o example
$ cd example
```

Add the `Tmds.Ssh` package:
```
$ dotnet add package Tmds.Ssh
```

Update `Program.cs`:

```cs
using Tmds.Ssh;

if (args.Length == 0)
{
    Console.Error.WriteLine("Specify the destination as an argument");
    return 1;
}

string destination = args[0];

using var sshClient = new SshClient(destination);
using var process = await sshClient.ExecuteAsync("echo 'hello world!'");
(bool isError, string? line) = await process.ReadLineAsync();
Console.WriteLine(line);

return 0;
```

If you have followed the steps earlier for setting up a private key, then this program will work because `SshClient` is using the default keys (like `~/.ssh/id_rsa`) and known hosts file (`~/.ssh/known_hosts`) from OpenSSH.

```
$ dotnet run <[user@]remoteserver>
hello world!
```

You can fully configure this behavior. To do that we need to create an `SshClientSetting` with our custom settings and pass it to the `SshClient` constructor.

The following code shows how we can set the `Credentials` to use a specific private key file, and a password login. It also shows how to clear `UserKnownHostFilePaths` (for not using `~/.ssh/known_hosts`) and set `HostAuthentication` for custom server authentication. The variables in the example need to be updated to match your setup.

```cs
string destination = args[0];
string privatekeyFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify), ".ssh/id_rsa");
string trustedServerFingerprint = "BkEYx77wOyUBL8UZfgoYKPLkwLJ7XMrsTwAu5sQC4C8"; // note: value as printed out by 'ssh` earlier.
string trustedServerHostname = "<remoteserver>";
bool insecure = false; // set this to 'true' to accept any public key from the server.
string password = "password";

var settings = new SshClientSettings(destination)
{
    Credentials = [ new PrivateKeyCredential(privatekeyFile), new PasswordCredential(password) ],
    UserKnownHostsFilePaths = [ ], // ignore user known_host files.
    HostAuthentication =
    async (KnownHostResult knownHostResult, SshConnectionInfo connectionInfo, CancellationToken cancellationToken) =>
    {
        if (connectionInfo.HostName == trustedServerHostname &&
            connectionInfo.ServerKey.Key.SHA256FingerPrint == trustedServerFingerprint)
        {
            return true;
        }
        return insecure;
    }
};

using var sshClient = new SshClient(settings);
```
