// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

enum DisconnectReason
{
  HostNotAllowedToConnect = 1,
  ProtocolError = 2,
  KeyExchangeFailed = 3,
  Reserved = 4,
  MacError = 5,
  CompressionError = 6,
  ServiceNotAvailable = 7,
  ProtocolVersionNotSupported = 8,
  HostKeyNotVerifiable = 9,
  ConnectionLost = 10,
  ByApplication = 11,
  TooManyConnections = 12,
  AuthCanceledByUser = 13,
  NoMoreAuthMethodsAvailable = 14,
  IllegalUserName = 15,
}
