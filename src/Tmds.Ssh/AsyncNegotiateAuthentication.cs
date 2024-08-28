using System.Net.Security;
#if NET8_0
using System.Buffers;
using System.Runtime.CompilerServices;
#endif

namespace Tmds.Ssh;

// This wraps NegotiateAuthentication to provide an async API that accepts a CancellationToken.
sealed class AsyncNegotiateAuthentication : IDisposable
{
    private readonly NegotiateAuthentication _negotiateAuthentication;
    private int _state;

    private enum State
    {
        Idle,
        InProgress,
        Disposed,
        DisposeRequested
    }

#if NET8_0
    // This API was made public in .NET 9 through ComputeIntegrityCheck.
    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "GetMIC")]
    private extern static void GetMICMethod(NegotiateAuthentication context, ReadOnlySpan<byte> data, IBufferWriter<byte> writer);
#endif

    public AsyncNegotiateAuthentication(NegotiateAuthenticationClientOptions clientOptions)
    {
        _negotiateAuthentication = new NegotiateAuthentication(clientOptions);
    }

    public void Dispose()
    {
        while (true)
        {
            int state = Volatile.Read(ref _state);
            if (state == (int)State.Idle)
            {
                // Try change from Idle to Disposed.
                if (Interlocked.CompareExchange(ref _state, (int)State.Disposed, state) == state)
                {
                    _negotiateAuthentication.Dispose();
                    return;
                }
            }
            else if (state == (int)State.InProgress)
            {
                // Try change from InProgress to DisposeRequested.
                if (Interlocked.CompareExchange(ref _state, (int)State.DisposeRequested, state) == state)
                {
                    return;
                }
            }
            else
            {
                // Disposed or DisposeRequested.
                return;
            }
        }
    }

    public bool IsSigned
    {
        get
        {
            return _negotiateAuthentication.IsSigned;
        }
    }

    public async Task<(byte[]? outgoingBlob, NegotiateAuthenticationStatusCode statusCode)> GetOutgoingBlobAsync(byte[] incomingBlob, CancellationToken cancellationToken)
    {
        if (Interlocked.CompareExchange(ref _state, (int)State.InProgress, (int)State.Idle) != (int)State.Idle)
        {
            throw new InvalidOperationException($"Cannot {nameof(GetOutgoingBlobAsync)} when {_state}.");
        }

        Task<(byte[]? outgoingBlob, NegotiateAuthenticationStatusCode)> result = Task.Run(() =>
        {
            try
            {
                byte[]? outgoingBlob = _negotiateAuthentication.GetOutgoingBlob(incomingBlob, out NegotiateAuthenticationStatusCode statusCode);
                return (outgoingBlob, statusCode);
            }
            finally
            {
                State previous = (State)Interlocked.CompareExchange(ref _state, (int)State.Idle, (int)State.InProgress);
                // When an async operation is cancelled, Dispose may have been called already
                // and we're responsible for disposing the NegotiateAuthentication.
                if (previous == State.DisposeRequested)
                {
                    _negotiateAuthentication.Dispose();
                }
            }
        });

        await result.WaitAsync(cancellationToken).ConfigureAwait(false);

        return await result.ConfigureAwait(false);
    }

    public void ComputeIntegrityCheck(ReadOnlySpan<byte> message, System.Buffers.IBufferWriter<byte> signatureWriter)
    {
#if NET8_0
        GetMICMethod(_negotiateAuthentication, message, signatureWriter);
#else
        _negotiateAuthentication.ComputeIntegrityCheck(message, signatureWriter);
#endif
    }
}