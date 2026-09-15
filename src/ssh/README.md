.NET tool that implements the `ssh` command using [Tmds.Ssh](https://www.nuget.org/packages/Tmds.Ssh).

Documentation: https://tmds.github.io/Tmds.Ssh
Release notes: https://github.com/tmds/Tmds.Ssh/releases

## Wayland forwarding

`--forward-wayland` forwards Wayland connections using [waypipe](https://gitlab.freedesktop.org/mstoeckl/waypipe), like `waypipe ssh` does:

```
ssh --forward-wayland myhost weston-terminal
```

This requires `waypipe` on the client and on the server, a local Wayland compositor, and a server that allows
Unix socket (`streamlocal`) remote forwarding. waypipe runs on Linux/BSD; on Windows the client needs to run
inside WSL (WSLg provides the compositor).

Wayland forwarding is not a Tmds.Ssh library feature. It is implemented on top of the public API in
[WaypipeForward.cs](https://github.com/tmds/Tmds.Ssh/blob/main/src/ssh/WaypipeForward.cs),
which you can copy into your own application.
