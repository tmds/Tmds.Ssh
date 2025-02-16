// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;
using Microsoft.Extensions.Logging;

// Use separate namespace since these are typed against ILogger and not a specific ILogger<T>.
namespace Tmds.Ssh.ForwardServerLogging;

static partial class ForwardServerLogger
{
    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Information,
        Message = "Forwarding connections from '{ListenEndPoint}' to '{TargetEndPoint}'")]
    public static partial void DirectForwardStart(this ILogger logger, string listenEndPoint, string targetEndPoint);

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Information,
        Message = "Forwarding SOCKS connections from '{ListenEndPoint}'")]
    public static partial void SocksForwardStart(this ILogger logger, string listenEndPoint);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Information,
        Message = "Accepted connection at '{ListenEndPoint}' from '{SourceEndPoint}'")]
    public static partial void AcceptConnection(this ILogger logger, string listenEndPoint, string sourceEndPoint);

    [LoggerMessage(
        EventId = 3,
        Level = LogLevel.Error,
        Message = "Failed to forward connection from '{SourceEndPoint}' to '{TargetEndPoint}'")]
    public static partial void ForwardConnectionFailed(this ILogger logger, string? sourceEndPoint, string? targetEndPoint, Exception exception);

    [LoggerMessage(
        EventId = 4,
        Level = LogLevel.Information,
        Message = "Forwarding connection from '{SourceEndPoint}' to '{TargetEndPoint}'")]
    public static partial void ForwardConnection(this ILogger logger, string sourceEndPoint, string targetEndPoint);

    [LoggerMessage(
        EventId = 5,
        Level = LogLevel.Information,
        Message = "Closed forwarded connection from '{SourceEndPoint}' to '{TargetEndPoint}'")]
    public static partial void ForwardConnectionClosed(this ILogger logger, string sourceEndPoint, string targetEndPoint);

    [LoggerMessage(
        EventId = 6,
        Level = LogLevel.Error,
        Message = "Aborted forwarded connection from '{SourceEndPoint}' to '{TargetEndPoint}'")]
    public static partial void ForwardConnectionAborted(this ILogger logger, string sourceEndPoint, string targetEndPoint, Exception exception);

    [LoggerMessage(
        EventId = 7,
        Level = LogLevel.Information,
        Message = "Stopped forwarding connections from '{ListenEndPoint}'")]
    public static partial void ForwardStopped(this ILogger logger, string listenEndPoint);

    [LoggerMessage(
        EventId = 8,
        Level = LogLevel.Error,
        Message = "Aborted forwarding connections from '{ListenEndPoint}'")]
    public static partial void ForwardAborted(this ILogger logger, string listenEndPoint, Exception exception);
}
