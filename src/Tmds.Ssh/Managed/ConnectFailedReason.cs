// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh.Managed;

enum ConnectFailedReason
{
    Unknown, // An unexpected exception occurred.
    KeyExchangeFailed, // Unable to negotiate keys with the peer.
    UntrustedPeer, // KeyExchangeFailed because we don't trust the peer.
    AuthenticationFailed, // We failed to authenticate ourselves.
    Timeout, // The connect operation timed out.
    ConnectionAborted, // The connection was closed for some reason.
}
