// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

sealed class StreamSshConnection : SshConnection
{
    private static ReadOnlySpan<byte> NewLine => new byte[] { (byte)'\r', (byte)'\n' };

    private readonly ILogger<SshClient> _logger;
    private readonly Stream _stream;
    private readonly Sequence _receiveBuffer;
    private readonly Sequence _sendBuffer;
    private IPacketDecryptor _decryptor;
    private IPacketEncryptor _encryptor;
    private uint _sendSequenceNumber;
    private uint _receiveSequenceNumber;
    private int _keepAlivePeriod;
    private Action? _keepAliveCallback;
    private Timer? _keepAliveTimer;
    private int _lastReceivedTime;

    public override void EnableKeepAlive(int period, Action callback)
    {
        if (period > 0)
        {
            if (_keepAliveTimer is not null)
            {
                throw new InvalidOperationException();
            }

            _keepAlivePeriod = period;
            _keepAliveCallback = callback;
            _lastReceivedTime = GetTime();
            _keepAliveTimer = new Timer(o => ((StreamSshConnection)o!).OnKeepAliveTimerCallback(), this, -1, -1);
            // Start timer after assigning the variable to ensure it is set when the callback is invoked.
            _keepAliveTimer.Change(_keepAlivePeriod, _keepAlivePeriod);
        }
    }

    private static int GetTime()
        => Environment.TickCount;

    private static int GetElapsed(int previous)
        => Math.Max(GetTime() - previous, 0);

    private void OnKeepAliveTimerCallback()
    {
        Debug.Assert(_keepAliveTimer is not null);
        Debug.Assert(_keepAliveCallback is not null);

        int elapsedTime = GetElapsed(_lastReceivedTime);
        lock (_keepAliveTimer)
        {
            // Synchronize with dispose.
            if (_keepAlivePeriod < 0)
            {
                return;
            }

            if (elapsedTime < _keepAlivePeriod)
            {
                // Wait for the period to expire.
                _keepAliveTimer.Change(_keepAlivePeriod - elapsedTime, _keepAlivePeriod);
                return;
            }
            else
            {
                _keepAliveTimer.Change(_keepAlivePeriod, _keepAlivePeriod);
            }
        }

        _keepAliveCallback();
    }

    public StreamSshConnection(ILogger<SshClient> logger, SequencePool sequencePool, Stream stream) :
        base(sequencePool)
    {
        if (!stream.CanRead || !stream.CanWrite)
        {
            throw new ArgumentException("Stream must be readable and writable", nameof(stream));
        }

        _logger = logger;
        _stream = stream;
        _receiveBuffer = sequencePool.RentSequence();
        _sendBuffer = sequencePool.RentSequence();
        _decryptor = new TransformAndHMacPacketDecryptor(SequencePool, new EncryptionCryptoTransform.EncryptionCryptoTransformNone(), new HMac.HMacNone());
        _encryptor = new TransformAndHMacPacketEncryptor(new EncryptionCryptoTransform.EncryptionCryptoTransformNone(), new HMac.HMacNone());
    }

    public override async ValueTask<string> ReceiveLineAsync(int maxLength, CancellationToken ct)
    {
        while (true)
        {
            if (TryParseLine(maxLength, out string? line))
            {
                return line!;
            }

            int received = await ReceiveAsync(ct).ConfigureAwait(false);
            if (received == 0)
            {
                throw new ProtocolException("Client closed connection while receiving line.");
            }
        }
    }

    private async ValueTask<int> ReceiveAsync(CancellationToken ct)
    {
        var memory = _receiveBuffer.AllocGetMemory(Constants.PreferredBufferSize);
        int received = await _stream.ReadAsync(memory, ct).ConfigureAwait(false);
        _receiveBuffer.AppendAlloced(received);
        return received;
    }

    private bool TryParseLine(int maxLength, out string? line)
    {
        maxLength += NewLine.Length;

        var data = _receiveBuffer.AsReadOnlySequence();
        bool lineExpected = data.Length >= maxLength;
        if (lineExpected)
        {
            // Don't look at more than maxLength data.
            data = data.Slice(0, maxLength);
        }

        var reader = new SequenceReader<byte>(data);
        if (reader.TryReadTo(out ReadOnlySequence<byte> lineSequence, NewLine))
        {
            try
            {
                line = ProtocolEncoding.UTF8.GetString(lineSequence.ToArray());
            }
            catch (DecoderFallbackException)
            {
                ThrowHelper.ThrowDataInvalidUtf8();
                throw;
            }
            _receiveBuffer.Remove(reader.Consumed);
            return true;
        }

        if (lineExpected)
        {
            throw new ProtocolException($"Line delimited by '\\r\\n' exceeds {maxLength}");
        }

        line = null;
        return false;
    }

    public async override ValueTask<Packet> ReceivePacketAsync(CancellationToken ct, int maxLength)
    {
        while (true)
        {
            if (_decryptor.TryDecrypt(_receiveBuffer, _receiveSequenceNumber, maxLength, out Packet packet))
            {
                _lastReceivedTime = GetTime();

                _receiveSequenceNumber++;

                using Packet p = packet;
                _logger.PacketReceived(packet);
                return p.Move();
            }

            int received = await ReceiveAsync(ct).ConfigureAwait(false);
            if (received == 0)
            {
                if (_receiveBuffer.AsReadOnlySequence().IsEmpty)
                {
                    return new Packet(null);
                }
                else
                {
                    throw new ProtocolException("Client closed connection while receiving packet.");
                }
            }
        }
    }

    public override async ValueTask SendPacketAsync(Packet packet, CancellationToken ct)
    {
        _logger.PacketSend(packet);

        _encryptor.Encrypt(_sendSequenceNumber, packet.Move(), _sendBuffer);
        var encryptedData = _sendBuffer.AsReadOnlySequence();

        if (encryptedData.IsSingleSegment)
        {
            await _stream.WriteAsync(encryptedData.First, ct).ConfigureAwait(false);
        }
        else
        {
            foreach (var memory in encryptedData)
            {
                await _stream.WriteAsync(memory, ct).ConfigureAwait(false);
            }
        }

        _sendSequenceNumber = unchecked(_sendSequenceNumber + 1);
        _sendBuffer.Clear();
    }

    public override async ValueTask WriteLineAsync(string line, CancellationToken ct)
    {
        line += "\r\n";
        await _stream.WriteAsync(Encoding.UTF8.GetBytes(line), ct).ConfigureAwait(false);
    }

    public override void SetEncryptorDecryptor(IPacketEncryptor packetEncoder, IPacketDecryptor packetDecoder, bool resetSequenceNumbers, bool throwIfReceiveSNZero)
    {
        _encryptor?.Dispose();
        _decryptor?.Dispose();
        _encryptor = packetEncoder;
        _decryptor = packetDecoder;

        if (resetSequenceNumbers)
        {
            if (_receiveSequenceNumber == 0 && throwIfReceiveSNZero)
            {
                ThrowHelper.ThrowDataValueOutOfRange();
            }
            _sendSequenceNumber = 0;
            _receiveSequenceNumber = 0;
        }
    }

    public override void Dispose()
    {
        if (_keepAliveTimer is not null)
        {
            lock (_keepAliveTimer)
            {
                _keepAlivePeriod = -1;
                _keepAliveTimer.Dispose();
            }
        }
        _keepAliveTimer?.Dispose();
        _receiveBuffer.Dispose();
        _sendBuffer.Dispose();
        _encryptor.Dispose();
        _decryptor.Dispose();
        _stream.Dispose();
    }
}
