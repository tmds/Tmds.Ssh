// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    internal static class TaskExtensions
    {
        public static async Task<bool> WithCancellation(this ValueTask task, CancellationToken cancellationToken)
        {
            /* From the docs:

                The following operations should never be performed on a ValueTask<TResult> instance:

                    Awaiting the instance multiple times.
                    Calling AsTask multiple times.
                    Using .Result or .GetAwaiter().GetResult() when the operation hasn't yet completed, or using them multiple times.
                    Using more than one of these techniques to consume the instance.
             */
            if (cancellationToken.CanBeCanceled && !task.IsCompleted)
            {
                var tcs = new TaskCompletionSource<object?>();

                using (cancellationToken.Register(state =>
                {
                    ((TaskCompletionSource<object?>)state!).TrySetResult(null);
                },
                tcs))
                {
                    Task vtAsTask = task.AsTask();

                    var resultTask = await Task.WhenAny(vtAsTask, tcs.Task);
                    if (resultTask == tcs.Task)
                    {
                        // Operation cancelled
                        return false;
                    }

                    await vtAsTask;
                    return true;
                }
            }
            else
            {
                await task;
                return true;
            }
        }
    }
}