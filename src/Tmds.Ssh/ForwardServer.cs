// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Tmds.Ssh.ForwardServerLogging;

namespace Tmds.Ssh;

// Implements forwarding on behalf of the public class 'T".
abstract partial class ForwardServer<T, TTargetStream> : IDisposable where TTargetStream : Stream
{
    protected enum ForwardProtocol
    {
        Direct = 1,
        Socks
    }

    // Sentinel stop reasons.
    protected static readonly Exception ConnectionClosed = new();
    protected static readonly Exception Disposed = new();

    protected readonly ILogger<T> _logger;
    protected readonly CancellationTokenSource _cancel;

    protected SshSession? _session { get; private set; }
    protected ForwardProtocol _protocol { get; private set; }
    protected string? _listenEndPoint { get; private set; }
    private string? _targetEndPoint;
    protected CancellationTokenRegistration _ctr;
    protected Exception? _stopReason;
    private bool _logStopped;

    public bool IsDisposed => ReferenceEquals(_stopReason, Disposed);

    protected void UpdateListenEndPoint(string endpoint)
        => _listenEndPoint = endpoint;

    public CancellationToken Stopped
    {
        get
        {
            ThrowIfDisposed();
            return _cancel.Token;
        }
    }

    public void ThrowIfStopped()
    {
        Exception? stopReason = _stopReason;
        if (ReferenceEquals(stopReason, Disposed))
        {
            throw new ObjectDisposedException(typeof(T).FullName);
        }
        else if (ReferenceEquals(stopReason, ConnectionClosed))
        {
            Debug.Assert(_session is not null);
            throw _session.CreateCloseException();
        }
        else if (stopReason is not null)
        {
            throw new SshException($"{typeof(T).FullName} stopped due to an unexpected error.", stopReason);
        }
    }

    public void Dispose()
        => Stop(Disposed);

    private void Stop(Exception stopReason)
    {
        bool disposing = ReferenceEquals(stopReason, Disposed);
        if (disposing)
        {
            if (Interlocked.Exchange(ref _stopReason, Disposed) != null)
            {
                return;
            }
        }
        else
        {
            if (Interlocked.CompareExchange(ref _stopReason, stopReason, null) != null)
            {
                return;
            }
        }

        if (_logStopped)
        {
            Debug.Assert(_listenEndPoint is not null);
            if (disposing)
            {
                _logger.ForwardStopped(_listenEndPoint);
            }
            else if (ReferenceEquals(stopReason, ConnectionClosed))
            {
                if (_logger.IsEnabled(LogLevel.Error))
                {
                    Debug.Assert(_session is not null);
                    _logger.ForwardAborted(_listenEndPoint, _session.CreateCloseException());
                }
            }
            else
            {
                _logger.ForwardAborted(_listenEndPoint, stopReason);
            }
        }

        _ctr.Dispose();

        Stop();

        _cancel.Cancel();
    }

    protected abstract void Stop();

    internal ForwardServer(ILogger<T> logger)
    {
        _logger = logger;
        _cancel = new();
    }

    public void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(IsDisposed, typeof(T));
    }

    protected async ValueTask StartAsync(SshSession session, ForwardProtocol forwardProtocol, string listenEndPoint, string? targetEndPoint, CancellationToken cancellationToken)
    {
        _session = session;
        _listenEndPoint = listenEndPoint;
        _targetEndPoint = targetEndPoint;
        _protocol = forwardProtocol;

        try
        {
            await ListenAsync(cancellationToken).ConfigureAwait(false);
            _ctr = _session.ConnectionClosed.UnsafeRegister(o => ((ForwardServer<T, TTargetStream>)o!).Stop(ConnectionClosed), this);

            Debug.Assert(_listenEndPoint is not null);
            if (_protocol == ForwardProtocol.Direct)
            {
                Debug.Assert(_targetEndPoint is not null);
                _logger.DirectForwardStart(_listenEndPoint, _targetEndPoint);
            }
            else if (_protocol == ForwardProtocol.Socks)
            {
                _logger.SocksForwardStart(_listenEndPoint);
            }
            else
            {
                throw new IndexOutOfRangeException(_protocol.ToString());
            }
            // Log stop when we've logged the start.
            _logStopped = true;

            _ = AcceptLoop();
        }
        catch (Exception ex)
        {
            Stop(ex);

            throw;
        }
    }

    protected abstract ValueTask ListenAsync(CancellationToken cancellationToken);

    private async Task AcceptLoop()
    {
        try
        {
            Debug.Assert(_listenEndPoint is not null);
            while (true)
            {
                (Stream? acceptedStream, string address) = await AcceptAsync().ConfigureAwait(false);
                if (acceptedStream is null)
                {
                    Debug.Assert(_stopReason is not null);
                    break;
                }
                _logger.AcceptConnection(_listenEndPoint, address);
                _ = HandleAccept(acceptedStream, address);
            }
        }
        catch (Exception ex)
        {
            Stop(ex);
        }
    }

    private async Task HandleAccept(Stream sourceStream, string sourceAddress)
    {
        Task<TTargetStream> connect;
        string address;
        try
        {
            (connect, address) = await ConnectToTargetAsync(sourceStream, _cancel.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.ForwardConnectionFailed(sourceAddress, _targetEndPoint, ex);
            sourceStream.Dispose();
            return;
        }

        _ = ForwardConnectionAsync(sourceStream, connect, sourceAddress, address);
    }

    protected abstract Task<(Stream?, string)> AcceptAsync();

    protected abstract Task<(Task<TTargetStream> Connect, string Address)> ConnectToTargetAsync(Stream clientStream, CancellationToken ct);

    protected async Task ForwardConnectionAsync(Stream sourceStream, Task<TTargetStream> targetStreamConnect, string sourceAddress, string targetAddress)
    {
        Exception? exception = null;
        try
        {
            _logger.ForwardConnection(sourceAddress, targetAddress);
            Stream? targetStream = await targetStreamConnect.ConfigureAwait(false);
            Task first, second;
            try
            {
                Task copy1 = CopyTillEofAsync(sourceStream, targetStream);
                Task copy2 = CopyTillEofAsync(targetStream, sourceStream);

                first = await Task.WhenAny(copy1, copy2).ConfigureAwait(false);
                second = first == copy1 ? copy2 : copy1;
            }
            finally
            {
                // When the copy stops in one direction, stop it in the other direction too.
                // Though TCP allows data still to be received when the writing is shutdown
                // application protocols (usually) follow the pattern of only closing
                // when they will no longer receive.
                sourceStream.Dispose();
                targetStream.Dispose();
            }
            // The dispose will cause the second copy to stop.
            await second.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);

            await first.ConfigureAwait(false); // Throws if faulted.
        }
        catch (Exception ex)
        {
            exception = ex;
        }
        finally
        {
            if (exception is null)
            {
                _logger.ForwardConnectionClosed(sourceAddress, targetAddress);
            }
            else
            {
                _logger.ForwardConnectionAborted(sourceAddress, targetAddress, exception);
            }
        }

        static async Task CopyTillEofAsync(Stream from, Stream to)
        {
            int bufferSize;
            if (to is SshDataStream toDataStream)
            {
                bufferSize = toDataStream.WriteMaxPacketDataLength;
            }
            else
            {
                bufferSize = ((SshDataStream)from).ReadMaxPacketDataLength;
            }
            await from.CopyToAsync(to, bufferSize).ConfigureAwait(false);
            if (to is NetworkStream ns)
            {
                ns.Socket.Shutdown(SocketShutdown.Send);
            }
            else if (to is SshDataStream ds)
            {
                ds.WriteEof();
            }
        }
    }
    
}
