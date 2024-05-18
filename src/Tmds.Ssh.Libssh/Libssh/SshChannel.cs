// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using static Tmds.Ssh.Libssh.Interop;

namespace Tmds.Ssh.Libssh;

class SshChannel : ISshChannel
{
    private const int MinPacketLength = 32768;

    private static readonly Dictionary<IntPtr, SshChannel> s_callbacksToChannel = new();

    enum ChannelState
    {
        Initial,

        OpenSession,

        RequestSubsystem,

        RequestExec,

        OpenForwardTcp,

        OpenForwardUnix,

        Open,

        Eof,

        Closed, // Channel closed by peer
        ConnectionClosed, // Session closed
        Canceled, // Canceled by user
        Aborted, // Channel closed due to an error

        Disposed // By user
    }

    private readonly LibsshSshClient _client;
    private readonly SshChannelOptions _options;

    private ChannelState _state = ChannelState.Initial;
    private ChannelHandle _handle = null!;
    private TaskCompletionSource<object?>? _openTcs;
    private TaskCompletionSource<object?>? _readableTcs;
    private TaskCompletionSource<object?>? _windowReadyTcs;
    private bool _skippingStdout;
    private bool _skippingStderr;
    private ChannelReadType _readNextType = ChannelReadType.StandardOutput;
    private CancellationTokenSource? _abortedCts;
    private IntPtr _channel_callbacks; // ssh_channel_callbacks_struct*
    private bool _remoteClosed;
    private int _stdoutLength;
    private int _stderrLength;
    private Exception? _abortReason;
    private bool _disposed;

    public int? ExitCode { get; private set; }

    // libssh doesn't have APIs to get these of the channel. Assume the minimum.
    public int ReceiveMaxPacket => MinPacketLength;
    public int SendMaxPacket => MinPacketLength - 10; // https://gitlab.com/libssh/libssh-mirror/-/merge_requests/393

    internal SshChannel(LibsshSshClient session, SshChannelOptions options)
    {
        // TODO: validate options

        _client = session;
        _options = options;
    }

    internal unsafe Task OpenAsync()
    {
        LibsshSshClient.EnableDebugLogging();
        Debug.Assert(Monitor.IsEntered(_client.Gate));
        Debug.Assert(_state == ChannelState.Initial);

        ssh_channel_callbacks_struct* pCallbacks;
        lock (s_callbacksToChannel)
        {
            int cbSize = Marshal.SizeOf<ssh_channel_callbacks_struct>();
            _channel_callbacks = Marshal.AllocHGlobal(cbSize);

            pCallbacks = (ssh_channel_callbacks_struct*)_channel_callbacks;
            new Span<ssh_channel_callbacks_struct>(pCallbacks, 1).Clear();
            pCallbacks->size = cbSize;
            pCallbacks->userdata = _channel_callbacks;
            pCallbacks->channel_data_function = &OnDataCallback;
            pCallbacks->channel_close_function = &OnCloseCallback;
            pCallbacks->channel_eof_function = &OnEofCallback;
            pCallbacks->channel_request_response_function = &OnRequestResponse;
            pCallbacks->channel_open_response_function = &OnOpenResponse;
            pCallbacks->channel_write_wontblock_function = &OnWriteWontBlock;

            s_callbacksToChannel.Add(_channel_callbacks, this);
        }
        bool releaseRef = false;
        try
        {
            // A ChannelHandle holds a reference to the SessionHandle
            // to ensure the session can't be free-ed before the channel.
            bool refAdded = false;
            _client.SshHandle.DangerousAddRef(ref refAdded);
            releaseRef = refAdded;
            _handle = ssh_channel_new(_client.SshHandle);
            _handle.SessionHandle = _client.SshHandle;
            releaseRef = false; // ref will be released by ChannelHandle.
        }
        finally
        {
            if (releaseRef)
            {
                _client.SshHandle.DangerousRelease();
            }
        }
        ssh_set_channel_callbacks(_handle, pCallbacks);
        var tcs = _openTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

        _state = _options.Type switch
        {
            SshChannelType.Execute => ChannelState.OpenSession,
            SshChannelType.Sftp => ChannelState.OpenSession,
            SshChannelType.TcpStream => ChannelState.OpenForwardTcp,
            SshChannelType.UnixStream => ChannelState.OpenForwardUnix,
            _ => throw new IndexOutOfRangeException($"Unknown channel type: {_options.Type}")
        };

        Open();

        return tcs.Task;
    }

    private void Open()
    {
        int rv;
        switch (_state)
        {
            case ChannelState.OpenSession:
                rv = ssh_channel_open_session(_handle);
                break;
            case ChannelState.OpenForwardTcp:
                rv = ssh_channel_open_forward(_handle, _options.Host!, _options.Port, "0.0.0.0", 0); // TODO nullable
                break;
            case ChannelState.OpenForwardUnix:
                rv = ssh_channel_open_forward_unix(_handle, _options.Path!, "0.0.0.0", 0); // TODO nullable
                break;
            default:
                rv = SSH_ERROR;
                break;
        }
        if (rv == SSH_ERROR)
        {
            CompleteOpen(success: false);
            return;
        }
        Debug.Assert(rv == SSH_AGAIN || rv == SSH_OK, $"Open failed with {rv}");
    }

    private void HandleCallback(Callback callback, bool isSuccess = true, bool isStdout = true, int length = 0)
    {
        Debug.Assert(Monitor.IsEntered(_client.Gate));

        if (_state >= ChannelState.Closed)
        {
            return;
        }

        switch (callback)
        {
            case Callback.OpenResponse:
                switch (_state)
                {
                    case ChannelState.OpenSession:
                        int rv;
                        switch (_options.Type)
                        {
                            case SshChannelType.Execute:
                                _state = ChannelState.RequestExec;
                                rv = ssh_channel_request_exec(_handle, _options.Command!); // TODO nullable
                                break;
                            case SshChannelType.Sftp:
                                _state = ChannelState.RequestSubsystem;
                                string subsystem;
                                switch (_options.Type)
                                {
                                    case SshChannelType.Sftp:
                                        subsystem = "sftp";
                                        break;
                                    default:
                                        throw new IndexOutOfRangeException($"Unexpected channel type: {_options.Type}");
                                };
                                rv = ssh_channel_request_subsystem(_handle, subsystem);
                                break;
                            default:
                                throw new IndexOutOfRangeException($"Unexpected channel type: {_options.Type}");
                        };
                        if (rv == SSH_ERROR)
                        {
                            CompleteOpen(success: false);
                            return;
                        }
                        Debug.Assert(rv == SSH_AGAIN);
                        break;
                    case ChannelState.OpenForwardUnix:
                    case ChannelState.OpenForwardTcp:
                        _state = ChannelState.Open;
                        CompleteOpen(success: isSuccess);
                        break;
                }
                break;
            case Callback.RequestResponse:
                switch (_state)
                {
                    case ChannelState.RequestExec:
                    case ChannelState.RequestSubsystem:
                        // issue a request to get the pending result.
                        int rv = ssh_channel_request_subsystem(_handle, "");
                        isSuccess = rv == SSH_OK;
                        if (isSuccess)
                        {
                            _state = ChannelState.Open;
                        }
                        CompleteOpen(isSuccess);
                        break;
                }
                break;
            case Callback.Close:
                _remoteClosed = true;
                CancelAbortedTcs();
                if (_readableTcs != null)
                {
                    CompleteReadable();
                }
                break;
            case Callback.Data:
                if (isStdout)
                {
                    _stdoutLength = length;
                }
                else
                {
                    _stderrLength = length;
                }
                if (_readableTcs != null)
                {
                    CompleteReadable();
                }
                break;
            case Callback.Eof:
                if (_readableTcs != null)
                {
                    CompleteReadable();
                }
                break;
            case Callback.Writable:
                if (_windowReadyTcs != null)
                {
                    var tcs = _windowReadyTcs;
                    _windowReadyTcs = null;
                    tcs.SetResult(null);
                }
                break;
        }
    }

    private void CompleteOpen(bool success)
    {
        Debug.Assert(_openTcs != null);

        if (success)
        {
            var tcs = _openTcs;
            _openTcs = null;
            tcs.SetResult(null);
        }
        else
        {
            // Because this gets called on a channel callback, we can't
            // dispose the channel handle immediately.
            // https://gitlab.com/libssh/libssh-mirror/-/issues/171
            ThreadPool.QueueUserWorkItem(
                static o =>
                {
                    SshChannel channel = (SshChannel)o!;
                    LibsshSshClient client = channel._client;

                    lock (client.Gate)
                    {
                        var tcs = channel._openTcs;
                        channel._openTcs = null;

                        // may cause change to ChannelState.SessionClosed
                        var exception = client.GetErrorException();

                        channel.Close(ChannelState.Disposed);

                        tcs?.SetException(exception);
                    }
                },
                this
            );
        }
    }

    private void CancelAbortedTcs()
    {
        if (_abortedCts != null)
        {
            ThreadPool.QueueUserWorkItem(
                o => ((CancellationTokenSource)o!).Cancel(),
                _abortedCts
            );
        }
    }

    internal void OnSessionDisconnect()
    {
        Close(ChannelState.ConnectionClosed);
    }

    public CancellationToken ChannelAborted
    {
        get
        {
            ThrowIfDisposed();

            lock (_client.Gate)
            {
                if (_state == ChannelState.Disposed)
                {
                    ThrowNewObjectDisposedException();
                }
                else if (_state >= ChannelState.Closed || _remoteClosed)
                {
                    return new CancellationToken(true);
                }
                if (_abortedCts == null)
                {
                    _abortedCts = new CancellationTokenSource();
                }
                return _abortedCts.Token;
            }
        }
    }

    public void Dispose()
    {
        _disposed = true;

        using (_client.GateWithPollCheck()) // TODO: poll check still needed?
        {
            Close(ChannelState.Disposed);
        }
    }

    internal void Cancel()
    {
        using (_client.GateWithPollCheck()) // TODO: poll check still needed?
        {
            Close(ChannelState.Canceled);
        }
    }

    public void Abort(Exception abortReason)
    {
        Debug.Assert(abortReason is not null);
        using (_client.GateWithPollCheck()) // TODO: poll check still needed?
        {
            Close(ChannelState.Aborted, abortReason);
        }
    }

    private unsafe void Close(ChannelState targetState, Exception? abortReason = null)
    {
        Debug.Assert(targetState >= ChannelState.Closed);
        Debug.Assert(Monitor.IsEntered(_client.Gate));

        if (_state >= ChannelState.Closed)
        {
            // from a Closed state we can move to Disposed.
            if (targetState == ChannelState.Disposed)
            {
                _state = ChannelState.Disposed;
            }
            return;
        }
        _state = targetState;
        _abortReason = abortReason;

        _client.RemoveChannel(this);

        CompletePending(ref _openTcs);
        CompletePending(ref _readableTcs, success: true);
        CompletePending(ref _windowReadyTcs, success: true);
        CancelAbortedTcs();

        void CompletePending(ref TaskCompletionSource<object?>? tcsField, bool success = false)
        {
            var tcs = tcsField;
            if (tcs != null)
            {
                tcsField = null;
                if (success)
                {
                    tcs.SetResult(null);
                }
                else
                {
                    Exception exception = _state == ChannelState.Canceled ? new OperationCanceledException()
                                                                          : CreateCloseException();
                    tcs.SetException(exception);
                }
            }
        }

        if (_channel_callbacks != IntPtr.Zero)
        {
            if (_handle != null)
            {
                ssh_remove_channel_callbacks(_handle, (ssh_channel_callbacks_struct*)_channel_callbacks);
            }
            lock (s_callbacksToChannel)
            {
                s_callbacksToChannel.Remove(_channel_callbacks);

                Marshal.FreeHGlobal(_channel_callbacks);
                _channel_callbacks = IntPtr.Zero;
            }
        }

        _handle?.Dispose();
    }

    public Exception CreateCloseException()
    => _state switch
    {
        ChannelState.ConnectionClosed => _client.CreateCloseExceptionGated(),
        ChannelState.Canceled => new SshChannelClosedException(SshChannelClosedException.ChannelClosedByCancel),
        ChannelState.Aborted => new SshChannelClosedException(SshChannelClosedException.ChannelClosedByAbort, _abortReason),
        ChannelState.Closed => new SshChannelClosedException(SshChannelClosedException.ChannelClosedByPeer),
        ChannelState.Disposed => new SshChannelClosedException(SshChannelClosedException.ChannelClosedByDispose),
        _ => throw new IndexOutOfRangeException($"Unhandled state: {_state}."),
    };

    void CompleteReadable()
    {
        lock (_client.Gate)
        {
            if (_readableTcs != null)
            {
                var tcs = _readableTcs;
                _readableTcs = null;
                tcs.SetResult(null);
            }
        }
    }

    public ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
        => WriteAsync(buffer, isError: false, cancellationToken);

    public ValueTask WriteErrorAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
        => WriteAsync(buffer, isError: true, cancellationToken);

    private async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        bool isError,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        try
        {
            Task? windowReady = null;
            CancellationTokenRegistration ctr = default;
            while (true)
            {
                if (windowReady != null)
                {
                    try
                    {
                        await windowReady.ConfigureAwait(false);
                    }
                    finally
                    {
                        ctr.Dispose();
                        cancellationToken.ThrowIfCancellationRequested();
                    }
                }

                LibsshSshClient.EnableDebugLogging();
                using (_client.GateWithPollCheck()) // TODO: poll check still needed?
                {
                    if (windowReady == null && _windowReadyTcs != null)
                    {
                        throw new InvalidOperationException("Concurrent writes are not allowed.");
                    }

                    if (_state >= ChannelState.Closed)
                    {
                        throw CreateCloseException();
                    }
                    Debug.Assert(_handle != null);

                    int length = buffer.Length;
                    if (length == 0)
                    {
                        return; // initial buffer was empty
                    }

                    length = (int)Math.Min(ssh_channel_window_size(_handle), length);
                    if (length > 0)
                    {
                        int rv = isError ? ssh_channel_write_stderr(_handle, buffer.Span.Slice(0, length)) :
                                           ssh_channel_write(_handle, buffer.Span.Slice(0, length));

                        if (rv < 0)
                        {
                            throw _client.GetErrorException();
                        }
                        else if (rv == 0)
                        {
                            throw new IndexOutOfRangeException($"Unexpected ssh_channel_write return value: {rv}");
                        }
                        buffer = buffer.Slice(rv);
                        if (buffer.Length == 0)
                        {
                            break;
                        }
                    }
                    else
                    {
                        _windowReadyTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
                        windowReady = _windowReadyTcs.Task;
                        ctr = cancellationToken.Register(o => ((SshChannel)o!).Cancel(), this);
                    }
                }
            } while (buffer.Length > 0) ;

            // TODO: can we check we don't need to flush while holding the lock?
            await FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Cancel();
            throw;
        }
    }

    private ValueTask FlushAsync(CancellationToken cancellationToken)
        => _client.FlushAsync(cancellationToken);

    public async ValueTask<(ChannelReadType ReadType, int BytesRead)> ReadAsync
        (Memory<byte>? stdoutBuffer = default,
         Memory<byte>? stderrBuffer = default,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (stdoutBuffer is { Length: 0 })
        {
            throw new ArgumentException("Buffer length cannot be zero.", nameof(stdoutBuffer));
        }
        if (stderrBuffer is { Length: 0 })
        {
            throw new ArgumentException("Buffer length cannot be zero.", nameof(stderrBuffer));
        }
        try
        {
            Task? readable = null;
            CancellationTokenRegistration ctr = default;
            while (true)
            {
                if (readable != null)
                {
                    try
                    {
                        await readable.ConfigureAwait(false);
                    }
                    finally
                    {
                        ctr.Dispose();

                        cancellationToken.ThrowIfCancellationRequested();
                    }
                }

                LibsshSshClient.EnableDebugLogging();
                using (_client.GateWithPollCheck()) // TODO: poll check still needed?
                {
                    if (readable == null && _readableTcs != null)
                    {
                        throw new InvalidOperationException("Concurrent reads are not allowed.");
                    }

                    if (stdoutBuffer.HasValue && _skippingStdout)
                    {
                        throw new InvalidOperationException("Standard output is being skipped.");
                    }
                    if (stderrBuffer.HasValue && _skippingStderr)
                    {
                        throw new InvalidOperationException("Standard error is being skipped.");
                    }
                    _skippingStdout = !stdoutBuffer.HasValue;
                    _skippingStderr = !stderrBuffer.HasValue;

                    if (_state >= ChannelState.Closed)
                    {
                        if (_state == ChannelState.Closed)
                        {
                            throw new InvalidOperationException("Channel closed.");
                        }
                        else
                        {
                            throw CreateCloseException();
                        }
                    }
                    Debug.Assert(_handle != null);

                    if (_state == ChannelState.Eof)
                    {
                        if (ssh_channel_is_read_closed(_handle))
                        {
                            ExitCode = ssh_channel_get_exit_status(_handle);
                            Close(ChannelState.Closed);
                            return (ChannelReadType.Closed, 0);
                        }
                        // await readable
                    }
                    else
                    {
                        if (_skippingStdout)
                        {
                            ReadAll(ChannelReadType.StandardOutput);
                        }
                        if (_skippingStderr)
                        {
                            ReadAll(ChannelReadType.StandardError);
                        }

                        if (!_skippingStdout || !_skippingStderr)
                        {
                            // Alternate between reading StandardOutput and StandardError.
                            ChannelReadType readType = _readNextType;
                            ChannelReadType otherType = readType == ChannelReadType.StandardOutput ? ChannelReadType.StandardError : ChannelReadType.StandardOutput;
                            (ChannelReadType type, int bytesRead) result;
                            if (IsNotSkipped(readType) && TryRead(readType, out result))
                            {
                                _readNextType = otherType;
                                return result;
                            }
                            else if (IsNotSkipped(otherType) && TryRead(otherType, out result))
                            {
                                return result;
                            }
                        }
                        else if (_state == ChannelState.Eof)
                        {
                            return (ChannelReadType.Eof, 0);
                        }
                    }

                    _readableTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
                    readable = _readableTcs.Task;
                    ctr = cancellationToken.Register(o => ((SshChannel)o!).Cancel(), this);
                }
            }
        }
        catch (OperationCanceledException)
        {
            Cancel();
            throw;
        }

        bool IsNotSkipped(ChannelReadType readType)
            => readType == ChannelReadType.StandardOutput ? !_skippingStdout : !_skippingStderr;

        void ReadAll(ChannelReadType readType)
        {
            Span<byte> buffer = stackalloc byte[128]; // TODO: no initlocal stuff.
            while (TryReadBuffer(readType, buffer, out var rv) && rv.type == readType)
            { }
        }

        bool TryRead(ChannelReadType readType, out (ChannelReadType type, int bytesRead) rv)
        {
            Memory<byte> memory = readType == ChannelReadType.StandardOutput ? stdoutBuffer!.Value : stderrBuffer!.Value;
            return TryReadBuffer(readType, memory.Span, out rv);
        }

        bool TryReadBuffer(ChannelReadType readType, Span<byte> buffer, out (ChannelReadType type, int bytesRead) rv)
        {
            int is_stderr = readType == ChannelReadType.StandardError ? 1 : 0;
            int bytesAvailable = is_stderr != 0 ? _stderrLength : _stdoutLength;
            if (bytesAvailable > 0)
            {
                bytesAvailable = Math.Min(bytesAvailable, buffer.Length);
                int bytesRead = ssh_channel_read(_handle, buffer.Slice(0, bytesAvailable), is_stderr);
                if (bytesRead < bytesAvailable)
                {
                    throw _client.GetErrorException();
                }
                if (is_stderr != 0)
                {
                    _stderrLength -= bytesRead;
                }
                else
                {
                    _stdoutLength -= bytesRead;
                }
                rv = (readType, bytesRead);
                return true;
            }
            else if (ssh_channel_is_eof(_handle)) // TODO: (libssh) poll can return EOF when there is still data to read?
            {
                _state = ChannelState.Eof;
                rv = (ChannelReadType.Eof, 0);
                return true;
            }
            else
            {
                // await readable
                rv = default;
                return false;
            }
        }
    }

    private bool ssh_channel_is_read_closed(ChannelHandle channel)
    {
        return ssh_channel_is_closed(channel)
                // workaround https://bugs.libssh.org/T31.
                || (_remoteClosed && ssh_channel_is_eof(channel));
    }

    private static SshChannel? GetChannel(IntPtr userdata)
    {
        lock (s_callbacksToChannel)
        {
            s_callbacksToChannel.TryGetValue(userdata, out SshChannel? channel);
            return channel;
        }
    }

    [UnmanagedCallersOnly]
    private static void OnCloseCallback(IntPtr pSession, IntPtr pChannel, IntPtr userdata)
        => GetChannel(userdata)?.HandleCallback(Callback.Close);

    [UnmanagedCallersOnly]
    private static void OnWriteWontBlock(IntPtr pSession, IntPtr pChannel, uint size, IntPtr userdata)
    {
        if (size != 0)
        {
            GetChannel(userdata)?.HandleCallback(Callback.Writable);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnEofCallback(IntPtr pSession, IntPtr pChannel, IntPtr userdata)
        => GetChannel(userdata)?.HandleCallback(Callback.Eof);

    [UnmanagedCallersOnly]
    private static int OnDataCallback(IntPtr pSession, IntPtr pChannel, IntPtr data, int len, int is_stderr, IntPtr userdata)
    {
        GetChannel(userdata)?.HandleCallback(Callback.Data, isStdout: is_stderr == 0, length: len);
        return 0;
    }

    [UnmanagedCallersOnly]
    private static void OnOpenResponse(IntPtr pSession, IntPtr pChannel, int is_success, IntPtr userdata)
        => GetChannel(userdata)?.HandleCallback(Callback.OpenResponse, isSuccess: is_success == 1);

    [UnmanagedCallersOnly]
    private static void OnRequestResponse(IntPtr pSession, IntPtr pChannel, IntPtr userdata)
        => GetChannel(userdata)?.HandleCallback(Callback.RequestResponse);

    private enum Callback
    {
        OpenResponse,
        RequestResponse,
        Data,
        Close,
        Eof,
        Writable
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            ThrowNewObjectDisposedException();
        }
    }

    private void ThrowNewObjectDisposedException()
    {
        throw new ObjectDisposedException(typeof(SshChannel).FullName);
    }
}
