using System.Buffers;
using System.Net;
using System.Net.Security;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

static partial class SshPortForwardLogger
{
    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Information,
        Message = "Forwarding connections from '{BindEndPoint}' to '{RemoteEndPoint}'")]
    public static partial void ForwardStart(this ILogger<LocalForward> logger, EndPoint bindEndPoint, string remoteEndPoint);

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Information,
        Message = "Accepted connection at '{BindEndPoint}' from '{PeerEndPoint}' to forward to '{RemoteEndPoint}'")]
    public static partial void AcceptConnection(this ILogger<LocalForward> logger, EndPoint bindEndPoint, EndPoint peerEndPoint, string remoteEndPoint);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Error,
        Message = "Failed to forward connection from '{PeerEndPoint}' to '{RemoteEndPoint}'")]
    public static partial void ForwardConnectionFailed(this ILogger<LocalForward> logger, EndPoint? peerEndPoint, string remoteEndPoint, Exception exception);

    [LoggerMessage(
        EventId = 3,
        Level = LogLevel.Information,
        Message = "Forwarding connection from '{PeerEndPoint}' to '{RemoteEndPoint}'")]
    public static partial void ForwardConnection(this ILogger<LocalForward> logger, EndPoint peerEndPoint, string remoteEndPoint);

    [LoggerMessage(
        EventId = 4,
        Level = LogLevel.Information,
        Message = "Closed forwarded connection from '{PeerEndPoint}' to '{RemoteEndPoint}'")]
    public static partial void ForwardConnectionClosed(this ILogger<LocalForward> logger, EndPoint peerEndPoint, string remoteEndPoint);

    [LoggerMessage(
        EventId = 5,
        Level = LogLevel.Error,
        Message = "Aborted forwarded connection from '{PeerEndPoint}' to '{RemoteEndPoint}'")]
    public static partial void ForwardConnectionAborted(this ILogger<LocalForward> logger, EndPoint peerEndPoint, string remoteEndPoint, Exception exception);

    [LoggerMessage(
        EventId = 6,
        Level = LogLevel.Information,
        Message = "Stopped forwarding connections from '{BindEndPoint}' to '{RemoteEndPoint}'")]
    public static partial void ForwardStopped(this ILogger<LocalForward> logger, EndPoint bindEndPoint, string remoteEndPoint);

    [LoggerMessage(
        EventId = 7,
        Level = LogLevel.Error,
        Message = "Aborted forwarding connections from '{BindEndPoint}' to '{RemoteEndPoint}'")]
    public static partial void ForwardAborted(this ILogger<LocalForward> logger, EndPoint bindEndPoint, string remoteEndPoint, Exception exception);
}