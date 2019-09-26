// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    // https://docs.microsoft.com/en-us/aspnet/core/fundamentals/logging/loggermessage?view=aspnetcore-3.0
    static class LoggingExtensions
    {
        private static readonly Action<ILogger, string, int, Exception?> _connecting;
        private static readonly Action<ILogger, Exception?> _connectionEstablished;
        private static readonly Action<ILogger, string, Exception?> _localVersionString;
        private static readonly Action<ILogger, string, Exception?> _remoteVersionString;

        static LoggingExtensions()
        {
            _connecting = LoggerMessage.Define<string, int>(
                eventId: 1,
                logLevel: LogLevel.Information,
                formatString: "Connecting to {host} port {port}."
            );

            _connectionEstablished = LoggerMessage.Define(
                eventId: 2,
                logLevel: LogLevel.Information,
                formatString: "Connection established."
            );

            _localVersionString = LoggerMessage.Define<string>(
                eventId: 3,
                logLevel: LogLevel.Information,
                formatString: "Local version string {identificationString}."
            );

            _remoteVersionString = LoggerMessage.Define<string>(
                eventId: 4,
                logLevel: LogLevel.Information,
                formatString: "Remote version string {identificationString}."
            );
        }

        public static void Connecting(this ILogger logger, string host, int port)
        {
            _connecting(logger, host, port, null);
        }

        public static void ConnectionEstablished(this ILogger logger)
        {
            _connectionEstablished(logger, null);
        }

        public static void LocalVersionString(this ILogger logger, string identificationString)
        {
            _localVersionString(logger, identificationString, null);
        }

        public static void RemoteVersionString(this ILogger logger, string identificationString)
        {
            _remoteVersionString(logger, identificationString, null);
        }
    }
}