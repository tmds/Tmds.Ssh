`ssh` and `ssh-cp` are .NET tools built using `Tmds.Ssh`. `ssh` provide an SSH client similar to OpenSSH `ssh`, and `ssh-cp` enables copying files to and from remote hosts similar to OpenSSH `scp`.

The `ssh` and `ssh-cp` tools provides an easy way try out `Tmds.Ssh` against an SSH server without coding it yourself.

## Running `ssh` and `ssh-cp`

### .NET 10+

With .NET 10, the `ssh` and `ssh-cp` can run directly using the new .NET 10 `dnx` command:

```
dnx ssh --help
dnx ssh-cp --help
```

### .NET 8+

`ssh` and `ssh-cp` can be installed as .NET tools.

```
dotnet tool update -g ssh
dotnet tool update -g ssh-cp
```

To invoke the `ssh` tool, run:

```
dotnet ssh --help
```

To invoke the `ssh-cp` tool, run:

```
dotnet ssh-cp --help
```
