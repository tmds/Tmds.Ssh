// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics.CodeAnalysis;

namespace Tmds.Ssh;

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
    public static void ThrowDataUnexpectedEndOfPacket()
    {
        throw new InvalidDataException("Unexpected end of packet.");
    }

    [DoesNotReturn]
    public static void ThrowProtocolUnexpectedMessageId(MessageId messageId)
    {
        throw new ProtocolException($"Unexpected message id: {messageId}.");
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
    public static void ThrowDataInvalidUtf8()
    {
        throw new InvalidDataException("Data contains an invalid UTF-8 sequence.");
    }

    [DoesNotReturn]
    public static void ThrowProtocolIncorrectMac()
    {
        throw new ProtocolException("The packet MAC is incorrect.");
    }

    public static void ThrowProtocolPacketTooLong()
    {
        throw new ProtocolException("Packet is too long.");
    }

    public static void ThrowBannerTooLong()
    {
        throw new ProtocolException("Too many banner messages.");
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
    public static void ThrowDataPacketLongerThanExpected()
    {
        throw new InvalidDataException("The packet contains more data than expected.");
    }

    [DoesNotReturn]
    public static void ThrowDataValueOutOfRange()
    {
        throw new InvalidDataException("The value is out of the expected range.");
    }

    [DoesNotReturn]
    public static void ThrowDataUnexpectedValue()
    {
        throw new InvalidDataException("The packet contains an unexpected value.");
    }

    [DoesNotReturn]
    public static void ThrowDataStringTooLong()
    {
        throw new InvalidDataException("The string is too long.");
    }

    [DoesNotReturn]
    public static void ThrowDataNameTooLong()
    {
        throw new InvalidDataException("The identifier name is too long.");
    }

    [DoesNotReturn]
    public static void ThrowDataInvalidName()
    {
        throw new InvalidDataException("The identifier name is invalid.");
    }

    [DoesNotReturn]
    public static void ThrowDataECPointInvalidLength()
    {
        throw new InvalidDataException("The elliptic curve point has an invalid length.");
    }

    [DoesNotReturn]
    public static void ThrowDataECPointTooLong()
    {
        throw new InvalidDataException("The elliptic curve point is too long.");
    }

    [DoesNotReturn]
    public static void ThrowDataMPIntTooLong()
    {
        throw new InvalidDataException("The mpint is too long.");
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
