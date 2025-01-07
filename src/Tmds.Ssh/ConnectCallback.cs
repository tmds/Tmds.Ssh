// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public delegate ValueTask<Stream> ConnectCallback(ConnectContext context, CancellationToken cancellationToken);