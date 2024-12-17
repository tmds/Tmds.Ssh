// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

// Use separate namespace since these are typed against ILogger and not a specific ILogger<T>.
namespace Tmds.Ssh.ForwardServerLogging;

static partial class ForwardServerLogger
{
    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Information,
        Message = "Forwarding connections from '{BindEndPoint}' to '{RemoteEndPoint}'")]
    public static partial void DirectForwardStart(this ILogger logger, EndPoint bindEndPoint, RemoteEndPoint remoteEndPoint);

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Information,
        Message = "Forwarding SOCKS connections from '{BindEndPoint}'")]
    public static partial void SocksForwardStart(this ILogger logger, EndPoint bindEndPoint);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Information,
        Message = "Accepted connection at '{BindEndPoint}' from '{PeerEndPoint}'")]
    public static partial void AcceptConnection(this ILogger logger, EndPoint bindEndPoint, EndPoint peerEndPoint);

    [LoggerMessage(
        EventId = 3,
        Level = LogLevel.Error,
        Message = "Failed to forward connection from '{PeerEndPoint}' to '{RemoteEndPoint}'")]
    public static partial void ForwardConnectionFailed(this ILogger logger, EndPoint? peerEndPoint, RemoteEndPoint? remoteEndPoint, Exception exception);

    [LoggerMessage(
        EventId = 4,
        Level = LogLevel.Information,
        Message = "Forwarding connection from '{PeerEndPoint}' to '{RemoteEndPoint}'")]
    public static partial void ForwardConnection(this ILogger logger, EndPoint peerEndPoint, RemoteEndPoint remoteEndPoint);

    [LoggerMessage(
        EventId = 5,
        Level = LogLevel.Information,
        Message = "Closed forwarded connection from '{PeerEndPoint}' to '{RemoteEndPoint}'")]
    public static partial void ForwardConnectionClosed(this ILogger logger, EndPoint peerEndPoint, RemoteEndPoint remoteEndPoint);

    [LoggerMessage(
        EventId = 6,
        Level = LogLevel.Error,
        Message = "Aborted forwarded connection from '{PeerEndPoint}' to '{RemoteEndPoint}'")]
    public static partial void ForwardConnectionAborted(this ILogger logger, EndPoint peerEndPoint, RemoteEndPoint remoteEndPoint, Exception exception);

    [LoggerMessage(
        EventId = 7,
        Level = LogLevel.Information,
        Message = "Stopped forwarding connections from '{BindEndPoint}'")]
    public static partial void ForwardStopped(this ILogger logger, EndPoint bindEndPoint);

    [LoggerMessage(
        EventId = 8,
        Level = LogLevel.Error,
        Message = "Aborted forwarding connections from '{BindEndPoint}'")]
    public static partial void ForwardAborted(this ILogger logger, EndPoint bindEndPoint, Exception exception);
}
