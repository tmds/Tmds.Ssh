// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

internal sealed class ConnectCancellation : IDisposable
{
    private readonly TimeProvider _timeProvider;
    private readonly CancellationTokenSource _linkedCts;
    private readonly ConnectCancellation? _outer;
    private readonly long _startTimestamp;
    private ITimer? _timer;
    private long _endTimeOrRemaining;
    private bool _isRunning;

    public CancellationToken Token => _linkedCts.Token;

    public ConnectCancellation(TimeSpan timeout, CancellationToken connectToken, CancellationToken abortToken, TimeProvider? timeProvider = null, ConnectCancellation? outer = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _startTimestamp = _timeProvider.GetTimestamp();
        _endTimeOrRemaining = _startTimestamp + TimeSpanToTimestampDelta(timeout);
        _isRunning = true;
        _outer = outer;
        _linkedCts = CancellationTokenSource.CreateLinkedTokenSource(connectToken, abortToken);
        _timer = _timeProvider.CreateTimer(static state => ((ConnectCancellation)state!).OnTimerFired(), this, timeout, Timeout.InfiniteTimeSpan);
    }

    private void OnTimerFired()
    {
        lock (this)
        {
            if (_isRunning)
            {
                _linkedCts.Cancel();
            }
        }
    }

    public void SuspendTimeout()
    {
        _outer?.SuspendTimeout();

        lock (this)
        {
            _linkedCts.Token.ThrowIfCancellationRequested();

            if (!_isRunning)
                return;

            _isRunning = false;
            _timer!.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);

            long remaining = _endTimeOrRemaining - _timeProvider.GetTimestamp();
            if (remaining <= 0)
            {
                _linkedCts.Cancel();
                _linkedCts.Token.ThrowIfCancellationRequested();
            }
            _endTimeOrRemaining = remaining;
        }
    }

    public void ResumeTimeout()
    {
        lock (this)
        {
            if (_isRunning || _linkedCts.IsCancellationRequested)
                return;

            long remaining = _endTimeOrRemaining;
            _endTimeOrRemaining = _timeProvider.GetTimestamp() + remaining;
            _isRunning = true;
            _timer!.Change(TimestampDeltaToTimeSpan(remaining), Timeout.InfiniteTimeSpan);
        }

        _outer?.ResumeTimeout();
    }

    public void UpdateTimeout(TimeSpan newTimeout)
    {
        lock (this)
        {
            if (_linkedCts.IsCancellationRequested)
                return;

            if (!_isRunning)
            {
                throw new InvalidOperationException("Cannot update timeout while suspended.");
            }

            long now = _timeProvider.GetTimestamp();
            TimeSpan totalElapsed = _timeProvider.GetElapsedTime(_startTimestamp);
            TimeSpan newRemaining = newTimeout - totalElapsed;

            if (newRemaining <= TimeSpan.Zero)
            {
                _linkedCts.Cancel();
            }
            else
            {
                _endTimeOrRemaining = now + TimeSpanToTimestampDelta(newRemaining);
                _timer!.Change(newRemaining, Timeout.InfiniteTimeSpan);
            }
        }
    }

    public void Dispose()
    {
        lock (this)
        {
            _isRunning = false;
            _timer?.Dispose();
            _linkedCts.Dispose();
        }
    }

    private long TimeSpanToTimestampDelta(TimeSpan ts)
        => (long)(ts.Ticks * ((double)_timeProvider.TimestampFrequency / TimeSpan.TicksPerSecond));

    private TimeSpan TimestampDeltaToTimeSpan(long delta)
        => _timeProvider.GetElapsedTime(0, delta);
}
