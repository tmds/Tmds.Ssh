// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Tmds.Ssh;

abstract partial class ForwardServer<T, TTargetStream>
{
    private const int SocksNegotiationTimeOut = 10_000; // 10s

    private const int BufferSize = 256 + 6; // This fits the connect message request.
    private const int ProtocolVersion5 = 5;
    private const byte METHOD_NO_AUTH = 0;
    private const byte CMD_CONNECT = 1;
    private const byte ATYP_IPV4 = 1;
    private const byte ATYP_DOMAIN_NAME = 3;
    private const byte ATYP_IPV6 = 4;
    private const byte Socks5_Success = 0;

    protected static async ValueTask<(string host, int port)> ReadSocks5HostAndPortAsync(Stream stream, CancellationToken ct)
    {
        string remoteHost;
        int remotePort;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            using var socksCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            socksCts.CancelAfter(SocksNegotiationTimeOut);

            // SOCKS Protocol Version 5 - https://tools.ietf.org/html/rfc1928

            // Version identification/method selection message.
            // +----+----------+----------+
            // |VER | NMETHODS | METHODS  |
            // +----+----------+----------+
            // | 1  |    1     | 1 to 255 |
            // +----+----------+----------+
            await stream.ReadExactlyAsync(buffer.AsMemory(0, 3), socksCts.Token).ConfigureAwait(false);
            byte ver = buffer[0];
            if (ver != ProtocolVersion5)
            {
                throw new SocksException($"Unexpected SOCKS protocol version: {ver}.");
            }
            byte nmethods = buffer[1];
            if (nmethods > 1)
            {
                await stream.ReadExactlyAsync(buffer.AsMemory(3, nmethods - 1), socksCts.Token).ConfigureAwait(false);
            }
            ReadOnlySpan<byte> methods = buffer.AsSpan(2, nmethods);
            if (!methods.Contains(METHOD_NO_AUTH))
            {
                throw new SocksException($"Client does not support 'NO AUTHENTICATION' authentication method.");
            }

            // Method selection.
            // +----+--------+
            // |VER | METHOD |
            // +----+--------+
            // | 1  |   1    |
            // +----+--------+
            buffer[0] = ProtocolVersion5;
            buffer[1] = METHOD_NO_AUTH;
            await stream.WriteAsync(buffer.AsMemory(0, 2), socksCts.Token);

            // Connect request.
            // +----+-----+-------+------+----------+----------+
            // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+
            await stream.ReadExactlyAsync(buffer.AsMemory(0, 5), socksCts.Token).ConfigureAwait(false);
            ver = buffer[0];
            if (ver != ProtocolVersion5)
            {
                throw new SocksException($"Unexpected SOCKS protocol version: {ver}.");
            }
            byte cmd = buffer[1];
            if (cmd != CMD_CONNECT)
            {
                throw new SocksException($"Unexpected SOCKS command: {cmd}.");
            }
            byte rsv = buffer[2];
            if (rsv != 0)
            {
                throw new SocksException($"Unexpected RSV value: {rsv}.");
            }
            byte atyp = buffer[3];
            int addressRemaining = atyp switch
            {
                ATYP_IPV4 => 4 - 1,
                ATYP_IPV6 => 16 - 1,
                ATYP_DOMAIN_NAME => buffer[4],
                _ => throw new SocksException($"Unexpected ATYP value: {atyp}.")
            };
            await stream.ReadExactlyAsync(buffer.AsMemory(5, addressRemaining + 2), socksCts.Token).ConfigureAwait(false);
            remoteHost = atyp switch
            {
                ATYP_IPV4 or ATYP_IPV6 => new IPAddress(buffer.AsSpan(4, addressRemaining + 1)).ToString(),
                ATYP_DOMAIN_NAME => Encoding.UTF8.GetString(buffer.AsSpan(5, addressRemaining)),
                _ => throw new SocksException($"Unexpected ATYP value: {atyp}.")
            };
            remotePort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(5 + addressRemaining));

            // Reply
            // +----+-----+-------+------+----------+----------+
            // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+
            buffer[0] = ProtocolVersion5;
            buffer[1] = Socks5_Success;
            buffer[2] = 0;
            buffer[3] = ATYP_IPV4;
            buffer.AsSpan(4, 6).Fill(0);
            await stream.WriteAsync(buffer.AsMemory(0, 10), socksCts.Token);
        }
        catch (OperationCanceledException e) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException("SOCKS protocol did not complete within timeout.", e);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return (remoteHost, remotePort);
    }

    sealed class SocksException : Exception
    {
        public SocksException(string message) : base(message)
        { }
    }
}
