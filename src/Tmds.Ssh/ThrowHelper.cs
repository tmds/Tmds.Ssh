// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Tmds.Ssh
{
    static class ThrowHelper
    {
        [DoesNotReturn]
        public static void ThrowArgumentOutOfRange(string paramName)
        {
            throw new ArgumentOutOfRangeException(paramName);
        }

        [DoesNotReturn]
        public static void ThrowInvalidOperation(string message)
        {
            throw new InvalidOperationException(message);
        }

        [DoesNotReturn]
        public static void ThrowProtocolUnexpectedEndOfPacket()
        {
            throw new ProtocolException("Unexpected end of packet.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolUnexpectedMessageId(MessageId messageId)
        {
            throw new ProtocolException($"Unexpected message id: {messageId}.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolUnexpectedSftpPacketType(SftpPacketType packetType)
        {
            throw new ProtocolException($"Unexpected SFTP packet type: {packetType}.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolInvalidPacketLength()
        {
            throw new ProtocolException("The packet length is not valid.");
        }

        [DoesNotReturn]
        public static void ThrowArgumentNull(string paramName)
        {
            throw new ArgumentNullException(paramName);
        }

        [DoesNotReturn]
        public static void ThrowProtocolInvalidUtf8()
        {
            throw new ProtocolException("Data contains an invalid UTF-8 sequence.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolIncorrectMac()
        {
            throw new ProtocolException("The packet MAC is incorrect.");
        }

        internal static void ThrowProtocolPacketTooLong()
        {
            throw new ProtocolException("Packet is too long.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolInvalidAscii()
        {
            throw new ProtocolException("Data contains an invalid ASCII characters.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolUnsupportedVersion(string identificationString)
        {
            throw new ProtocolException($"Unsupported protocol version: {identificationString}.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolNoVersionIdentificationString()
        {
            throw new ProtocolException("No protocol version string received.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolUnexpectedPeerClose()
        {
            throw new ProtocolException("Peer unexpectedly closed connection.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolPacketLongerThanExpected()
        {
            throw new ProtocolException("The packet contains more data than expected.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolUnexpectedValue()
        {
            throw new ProtocolException("The packet contains an unexpected value.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolStringTooLong()
        {
            throw new ProtocolException("The string is too long.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolNameTooLong()
        {
            throw new ProtocolException("The identifier name is too long.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolInvalidName()
        {
            throw new ProtocolException("The identifier name is invalid.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolECPointInvalidLength()
        {
            throw new ProtocolException("The elliptic curve point has an invalid length.");
        }

        [DoesNotReturn]
        public static void ThrowProtocolECPointTooLong()
        {
            throw new ProtocolException("The elliptic curve point is too long.");
        }

        [DoesNotReturn]
        public static void ThrowNotSupportedException(string message)
        {
            throw new NotSupportedException(message);
        }

        [DoesNotReturn]
        public static void ThrowProtocolDataWindowExceeded()
        {
            throw new ProtocolException("The peer sent more data than the window allowed.");
        }
    }
}