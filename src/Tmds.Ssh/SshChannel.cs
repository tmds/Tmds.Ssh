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
    public class SshChannel : IDisposable // TODO: internal
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
        private ChannelHandle _channel;
        private TaskCompletionSource<object> _openTcs;
        private TaskCompletionSource<object> _readableTcs;
        private TaskCompletionSource<object> _windowReadyTcs; // TODO: split for stdout and stderr.

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

            _channel = ssh_channel_new(_client.SshHandle);
            var tcs = _openTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

            _state = ChannelState.OpenSession;
            Process();

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
            CompletePending(ref _readableTcs);
            CompletePending(ref _windowReadyTcs);

            void CompletePending(ref TaskCompletionSource<object> tcsField)
            {
                var tcs = tcsField;
                if (tcs != null)
                {
                    tcsField = null;
                    Exception ex = targetState switch
                    {
                        ChannelState.SessionClosed => _client.GetErrorException(),
                        ChannelState.Canceled => new OperationCanceledException(),
                        ChannelState.Closed => new SshOperationException("Channel closed."),
                        ChannelState.Disposed => new SshOperationException("Channel disposed."),
                        _ => null,
                    };
                    tcs.SetException(ex);
                }
            }

           _channel.Dispose();
        }

        internal unsafe void Process()
        {
            Debug.Assert(Monitor.IsEntered(_client.Gate));

            while (true)
            {
                if (_state >= ChannelState.Closed)
                {
                    return;
                }
                switch (_state)
                {
                    case ChannelState.OpenSession:
                        int rv = ssh_channel_open_session(_channel);
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
                        rv = ssh_channel_request_exec(_channel, _options.Command);
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
                                if (ssh_channel_poll(_channel, is_stderr: 0) != 0 ||
                                    ssh_channel_poll(_channel, is_stderr: 1) != 0 ||
                                    ssh_channel_is_eof(_channel))
                                {
                                    CompleteReadable();
                                }
                            }
                            else
                            {
                                if (ssh_channel_is_closed(_channel))
                                {
                                    CompleteReadable();
                                }
                            }
                        }
                        if (_windowReadyTcs != null)
                        {
                            if (ssh_channel_window_size(_channel) > 0)
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
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
            => WriteAsync(buffer, isError: false);

        public ValueTask WriteErrorAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
            => WriteAsync(buffer, isError: true, cancellationToken);

        private async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            bool isError,
            CancellationToken cancellationToken = default)
        {
            try
            {
                Task windowReady = null;
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
                            ThrowNotOpen();
                        }

                        cancellationToken.ThrowIfCancellationRequested();

                        int length = buffer.Length;
                        if (length == 0)
                        {
                            return; // initial buffer was empty
                        }

                        length = (int)Math.Min(ssh_channel_window_size(_channel), length);
                        if (length > 0)
                        {
                            int rv = isError ? ssh_channel_write_stderr(_channel, buffer.Span.Slice(0, length)) :
                                               ssh_channel_write(_channel, buffer.Span.Slice(0, length));

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
                            ctr = cancellationToken.Register(o => ((SshChannel)o).Cancel(), this);
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

        public ValueTask FlushAsync(CancellationToken cancellationToken)
            => _client.FlushAsync(cancellationToken);

        public async ValueTask<(ChannelReadType ReadType, int BytesRead)> ReadAsync
            (Memory<byte>/*?*/ stdoutBuffer/*, // TODO
            Memory<byte>? stderrBuffer*/,      // TODO
            CancellationToken cancellationToken = default)
        {
            try
            {
                Task readable = null;
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

                        if (_state >= ChannelState.Closed)
                        {
                            ThrowNotOpen();
                        }

                        cancellationToken.ThrowIfCancellationRequested();

                        if (_state == ChannelState.Eof)
                        {
                            if (ssh_channel_is_closed(_channel))
                            {
                                Close(ChannelState.Closed);
                                return (ChannelReadType.Closed, 0);
                            }
                            // await readable
                        }
                        else
                        {
                            // note: libssh fakes an EOF when the peer closes the
                            //       connection without sending one.

                            int bytesAvailable = ssh_channel_poll(_channel, is_stderr: 0);
                            if (bytesAvailable > 0)
                            {
                                bytesAvailable = Math.Min(bytesAvailable, stdoutBuffer.Length);
                                int rv = ssh_channel_read(_channel, stdoutBuffer.Span.Slice(0, bytesAvailable), is_stderr: 0);
                                if (rv < bytesAvailable)
                                {
                                    throw _client.GetErrorException();
                                }
                                return (ChannelReadType.StandardOutput, rv);
                            }
                            else if (bytesAvailable == SSH_EOF
                                    || (bytesAvailable == 0 && ssh_channel_is_eof(_channel)))
                            {
                                _state = ChannelState.Eof;
                                return (ChannelReadType.Eof, 0);
                            }
                            else if (bytesAvailable == 0 || bytesAvailable == SSH_AGAIN)
                            {
                                // await readable
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

                        _readableTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
                        readable = _readableTcs.Task;
                        ctr = cancellationToken.Register(o => ((SshChannel)o).Cancel(), this);
                    }
                }                
            }
            catch (OperationCanceledException)
            {
                Cancel();
                throw;
            }
        }

        private void ThrowNotOpen()
        {
            Debug.Assert(_state >= ChannelState.Closed);
            switch (_state)
            {
                case ChannelState.Closed:
                    throw new InvalidOperationException("Channel closed."); 
                case ChannelState.SessionClosed:
                    throw _client.GetErrorException();
                case ChannelState.Canceled:
                    throw new OperationCanceledException();
                case ChannelState.Disposed:
                    throw new ObjectDisposedException(typeof(SshChannel).FullName);
                default:
                    throw new IndexOutOfRangeException($"Unknown state {_state}");
            }
        }
    }
}