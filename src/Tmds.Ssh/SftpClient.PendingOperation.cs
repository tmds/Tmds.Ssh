// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks.Sources;
using System.Collections.Concurrent;
using System.Threading.Channels;

namespace Tmds.Ssh
{
    public partial class SftpClient
    {
        private readonly Channel<Packet> _pendingSends = Channel.CreateUnbounded<Packet>();
        private readonly ConcurrentDictionary<int, PendingOperation> _pendingOperations = new();
        private readonly ConcurrentBag<PendingOperation> _pendingOperationPool = new();

        sealed class PendingOperation : IValueTaskSource<object?>, IValueTaskSource<int>
        {
            const int NotCompleted = 0;
            const int Completed = 1;
            const int Canceled = 2;

            private readonly SftpClient _client;
            private ManualResetValueTaskSourceCore<object?> _core;
            private int IntResult;
            private CancellationTokenRegistration _ctr;
            private int _state = NotCompleted;

            private void SetIntResult(int value)
            {
                // Synchronize with Cancel to ensure a recycled instance can not be canceled by a previous registration.
                _ctr.Dispose();

                int previousState = Interlocked.CompareExchange(ref _state, Completed, NotCompleted);
                if (previousState == NotCompleted)
                {
                    IntResult = value;
                    _core.SetResult(null!);
                }
            }

            private void SetResult(object? value)
            {
                // Synchronize with Cancel to ensure a recycled instance can not be canceled by a previous registration.
                _ctr.Dispose();

                int previousState = Interlocked.CompareExchange(ref _state, Completed, NotCompleted);
                if (previousState == NotCompleted)
                {
                    _core.SetResult(value);
                }
                else if (previousState == Canceled)
                {
                    if (value is SftpFile file)
                    {
                        file.Dispose();
                    }
                }
            }

            private void SetException(Exception exception)
            {
                // Synchronize with Cancel to ensure a recycled instance can not be canceled by a previous registration.
                _ctr.Dispose();

                int previousState = Interlocked.CompareExchange(ref _state, Completed, NotCompleted);
                if (previousState == NotCompleted)
                {
                    _core.SetException(exception);
                }
            }

            private void Cancel()
            {
                // note: do NOT dispose the CancellationTokenRegistration so the Set* methods can synchronize.
                if (Interlocked.CompareExchange(ref _state, Canceled, NotCompleted) == NotCompleted)
                {
                    _core.SetException(new OperationCanceledException());
                }
            }

            public short Token => _core.Version;

            public Memory<byte> Buffer { get; set; }
            public PacketType RequestType { get; set; }

            public PendingOperation(SftpClient client)
            {
                _client = client;
                _core.RunContinuationsAsynchronously = true;
            }

            internal void HandleClose()
            {
                SetException(_client.CreatePendingOperationCloseException());
            }

            public void Reset()
            {
                // Don't root objects.
                Buffer = default;

                // Reset ValueTask state.
                _state = NotCompleted;
                _core.Reset();
            }

            internal void HandleReply(SftpClient client, ReadOnlySpan<byte> reply)
            {
                PacketReader reader = new(reply);

                PacketType responseType = reader.ReadPacketType();
                reader.ReadInt(); // id

                SftpError error = SftpError.None;
                if (responseType == PacketType.SSH_FXP_STATUS)
                {
                    error = (SftpError)reader.ReadUInt();
                }

                if (error != SftpError.None &&
                    !( (error, RequestType) is (SftpError.Eof, PacketType.SSH_FXP_READ              // Read: return 0
                                                               or PacketType.SSH_FXP_READDIR        // Read: return Array.Empty<byte>
                                               )
                                            or (SftpError.NoSuchFile, PacketType.SSH_FXP_STAT       // GetAttributes: return null
                                                                      or PacketType.SSH_FXP_LSTAT   // GetAttributes: return null
                                                                      or PacketType.SSH_FXP_OPEN    // OpenFile: return null
                                                                      or PacketType.SSH_FXP_REMOVE  // DeleteFile: don't throw
                                                                      or PacketType.SSH_FXP_RMDIR   // DeleteDirectory: don't throw
                                               )
                    ))
                {
                    SetException(new SftpException(error));
                    return;
                }
                switch (RequestType, responseType)
                {
                    case (PacketType.SSH_FXP_OPEN, _):
                        SetResult(error == SftpError.NoSuchFile ? null : new SftpFile(client, handle: reader.ReadStringAsBytes()));
                        return;
                    case (PacketType.SSH_FXP_OPENDIR, _):
                        SetResult(reader.ReadStringAsBytes());
                        return;
                    case (PacketType.SSH_FXP_STAT, _):
                    case (PacketType.SSH_FXP_LSTAT, _):
                    case (PacketType.SSH_FXP_FSTAT, _):
                        SetResult(error == SftpError.NoSuchFile ? null : reader.ReadFileAttributes());
                        return;
                    case (PacketType.SSH_FXP_READ, _):
                        int count;
                        if (error == SftpError.Eof)
                        {
                            count = 0;
                        }
                        else
                        {
                            count = reader.ReadInt();
                            reader.Remainder.Slice(0, count).CopyTo(Buffer.Span);
                        }

                        SetIntResult(count);
                        return;
                    case (PacketType.SSH_FXP_READLINK, _):
                        reader.ReadInt(); // skip count, which should be '1'
                        SetResult(reader.ReadString());
                        return;
                    case (PacketType.SSH_FXP_REMOVE, _):
                    case (PacketType.SSH_FXP_RMDIR, _):
                        SetResult(null!);
                        return;
                    case (PacketType.SSH_FXP_READDIR, _):
                        SetResult(error == SftpError.Eof ? Array.Empty<byte>() : _client.StealPacketBuffer());
                        return;
                }
                if (responseType == PacketType.SSH_FXP_STATUS && error == SftpError.None)
                {
                    SetResult(null!);
                }
                else
                {
                    SetException(new SshOperationException($"Cannot handle {responseType} for {RequestType}."));
                }
            }

            public object? GetResult(short token)
            {
                bool recycle = CanRecycle;
                try
                {
                    var result = _core.GetResult(token);
                    return result;
                }
                finally
                {
                    if (recycle)
                    {
                        _client.ReturnPendingOperation(this);
                    }
                }
            }

            int IValueTaskSource<int>.GetResult(short token)
            {
                bool recycle = CanRecycle;
                var result = IntResult;
                try
                {
                    _core.GetResult(token);
                    return result;
                }
                finally
                {
                    if (recycle)
                    {
                        _client.ReturnPendingOperation(this);
                    }
                }
            }

            // Don't recycle Canceled operations as they are only canceled by returning
            // OperationCanceledException. We still expect a reply for the on-going operation.
            private bool CanRecycle => _state == Completed;

            public ValueTaskSourceStatus GetStatus(short token) => _core.GetStatus(token);

            public void OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
                => _core.OnCompleted(continuation, state, token, flags);

            internal CancellationTokenRegistration RegisterForCancellation(CancellationToken cancellationToken)
            {
                 return _ctr = cancellationToken.Register(pending => ((PendingOperation)pending!).Cancel(), this);
            }
        }

        private PendingOperation CreatePendingOperation(PacketType type)
        {
            PendingOperation operation = _pendingOperationPool.TryTake(out PendingOperation? item)
                                                ? item
                                                : new PendingOperation(this);
            operation.RequestType = type;
            return operation;
        }

        private void ReturnPendingOperation(PendingOperation operation)
        {
            operation.Reset();

            _pendingOperationPool.Add(operation);
        }
    }
}