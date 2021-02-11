// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using static Tmds.Ssh.Interop;

namespace Tmds.Ssh
{
    class SshChannel : IDisposable
    {
        enum ChannelState
        {
            Initial,

            OpenSession,
            RequestExec,

            Open,

            Eof,

            Closed, // Channel closed by peer
            SessionClosed, // Session closed,
            Canceled, // Canceled by user

            Disposed // By user
        }

        private readonly SshClient _client;
        private readonly SshChannelOptions _options;

        private ChannelState _state = ChannelState.Initial;
        private ChannelHandle? _handle;
        private TaskCompletionSource<object?>? _openTcs;
        private TaskCompletionSource<object?>? _readableTcs;
        private TaskCompletionSource<object?>? _windowReadyTcs;
        private bool _skippingStdout;
        private bool _skippingStderr;
        private ChannelReadType _readNextType = ChannelReadType.StandardOutput;

        public int? ExitCode { get; private set; }

        internal SshChannel(SshClient session, SshChannelOptions options)
        {
            // TODO: validate options

            _client = session;
            _options = options;
        }

        internal Task OpenAsync()
        {
            SshClient.EnableDebugLogging();
            Debug.Assert(Monitor.IsEntered(_client.Gate));
            Debug.Assert(_state == ChannelState.Initial);

            _handle = ssh_channel_new(_client.SshHandle);
            var tcs = _openTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

            _state = ChannelState.OpenSession;
            HandleEvents();

            return tcs.Task;
        }

        internal void OnSessionDisconnect()
        {
            Close(ChannelState.SessionClosed);
        }

        public void Dispose()
        {
            using (_client.GateWithPollCheck())
            {
                Close(ChannelState.Disposed);
            }
        }

        internal void Cancel()
        {
            using (_client.GateWithPollCheck())
            {
                Close(ChannelState.Canceled);
            }
        }

        private void Close(ChannelState targetState)
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

            _client.RemoveChannel(this);

            CompletePending(ref _openTcs);
            CompletePending(ref _readableTcs, success: true);
            CompletePending(ref _windowReadyTcs, success: true);

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
                        Exception ex = targetState switch
                        {
                            ChannelState.SessionClosed => _client.GetErrorException(),
                            ChannelState.Canceled => new OperationCanceledException(),
                            ChannelState.Closed => new SshOperationException("Channel closed."),
                            ChannelState.Disposed => new SshOperationException("Channel disposed."),
                            _ => throw new IndexOutOfRangeException($"Unhandled state: {targetState}."),
                        };
                        tcs.SetException(ex);
                    }
                }
            }

           _handle?.Dispose();
        }

        internal unsafe void HandleEvents()
        {
            Debug.Assert(Monitor.IsEntered(_client.Gate));

            while (true)
            {
                if (_state >= ChannelState.Closed)
                {
                    return;
                }
                Debug.Assert(_handle != null);

                switch (_state)
                {
                    case ChannelState.OpenSession:
                        int rv = ssh_channel_open_session(_handle);
                        if (rv == SSH_AGAIN)
                        {
                            return;
                        }
                        else if (rv == SSH_OK)
                        {
                            _state = ChannelState.RequestExec;
                        }
                        else
                        {
                            CompleteOpen(success: false);
                            return;
                        }
                        break;
                    case ChannelState.RequestExec:
                        rv = ssh_channel_request_exec(_handle, _options.Command!); // TODO nullable
                        if (rv == SSH_AGAIN)
                        {
                            return;
                        }
                        else if (rv == SSH_OK)
                        {
                            _state = ChannelState.Open;
                            CompleteOpen(success: true);
                        }
                        else
                        {
                            CompleteOpen(success: false);
                            return;
                        }
                        break;
                    case ChannelState.Open:
                    case ChannelState.Eof:
                        if (_readableTcs != null)
                        {
                            if (_state == ChannelState.Open)
                            {
                                // TODO: pass result of check through TaskCompletionSource
                                // TODO (libssh): avoid using syscalls.
                                if (ssh_channel_poll(_handle, is_stderr: 0) != 0 ||
                                    ssh_channel_poll(_handle, is_stderr: 1) != 0 ||
                                    ssh_channel_is_eof(_handle))
                                {
                                    CompleteReadable();
                                }
                            }
                            else
                            {
                                if (ssh_channel_is_closed(_client.SshHandle, _handle))
                                {
                                    CompleteReadable();
                                }
                            }
                        }
                        if (_windowReadyTcs != null)
                        {
                            if (ssh_channel_window_size(_handle) > 0)
                            {
                                var tcs = _windowReadyTcs;
                                _windowReadyTcs = null;
                                tcs.SetResult(null);
                            }
                        }
                        return;
                    default:
                        throw new IndexOutOfRangeException($"Invalid Channel state: {_state}.");
                }
            }

            void CompleteReadable()
            {
                var tcs = _readableTcs;
                _readableTcs = null;
                tcs.SetResult(null);
            }

            void CompleteOpen(bool success)
            {
                Debug.Assert(_openTcs != null);
                var tcs = _openTcs;
                _openTcs = null;
                if (success)
                {
                    tcs.SetResult(null);
                }
                else
                {
                    // may cause change to ChannelState.SessionClosed
                    var exception = _client.GetErrorException();

                    Close(ChannelState.Disposed);

                    tcs.SetException(exception);
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
                        }
                    }

                    SshClient.EnableDebugLogging();
                    using (_client.GateWithPollCheck())
                    {
                        if (windowReady == null && _windowReadyTcs != null)
                        {
                            throw new InvalidOperationException("Concurrent writes are not allowed.");
                        }

                        if (_state >= ChannelState.Closed)
                        {
                            ThrowNotOpen(closedIsInvalid: false, cancellationToken);
                        }
                        Debug.Assert(_handle != null);

                        cancellationToken.ThrowIfCancellationRequested();

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
                } while (buffer.Length > 0);

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
                        }
                    }

                    SshClient.EnableDebugLogging();
                    using (_client.GateWithPollCheck())
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
                            ThrowNotOpen(closedIsInvalid: true, cancellationToken);
                        }
                        Debug.Assert(_handle != null);

                        cancellationToken.ThrowIfCancellationRequested();

                        if (_state == ChannelState.Eof)
                        {
                            if (ssh_channel_is_closed(_client.SshHandle, _handle))
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
                int bytesAvailable = ssh_channel_poll(_handle, is_stderr);
                if (bytesAvailable > 0)
                {
                    bytesAvailable = Math.Min(bytesAvailable, buffer.Length);
                    int bytesRead = ssh_channel_read(_handle, buffer.Slice(0, bytesAvailable), is_stderr);
                    if (bytesRead < bytesAvailable)
                    {
                        throw _client.GetErrorException();
                    }
                    rv = (readType, bytesRead);
                    return true;
                }
                else if ((bytesAvailable == SSH_EOF || bytesAvailable == 0)
                         && ssh_channel_is_eof(_handle)) // TODO: (libssh) poll can return EOF when there is still data to read?
                {
                    _state = ChannelState.Eof;
                    rv = (ChannelReadType.Eof, 0);
                    return true;
                }
                else if (bytesAvailable == 0 || bytesAvailable == SSH_AGAIN || bytesAvailable == SSH_EOF)
                {
                    // await readable
                    rv = default;
                    return false;
                }
                else if (bytesAvailable == SSH_ERROR)
                {
                    throw _client.GetErrorException();
                }
                else
                {
                    throw new IndexOutOfRangeException($"Unexpected ssh_channel_poll return value: {bytesAvailable}");
                }
            }
        }

        private void ThrowNotOpen(bool closedIsInvalid, CancellationToken cancellationToken)
        {
            Debug.Assert(_state >= ChannelState.Closed);
            switch (_state)
            {
                case ChannelState.Closed:
                    throw closedIsInvalid ? new InvalidOperationException("Channel closed.") :
                                            new SshOperationException("Channel closed.") ; 
                case ChannelState.SessionClosed:
                    throw _client.GetErrorException();
                case ChannelState.Canceled:
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new SshOperationException("Channel closed due to canceled operation.");
                case ChannelState.Disposed:
                    throw new ObjectDisposedException(typeof(SshChannel).FullName);
                default:
                    throw new IndexOutOfRangeException($"Unknown state {_state}");
            }
        }
    }
}