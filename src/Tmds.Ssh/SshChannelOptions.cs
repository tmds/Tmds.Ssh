// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    sealed class SshChannelOptions
    {
        public SshChannelOptions(SshChannelType type)
        {
            Type = type;
        }

        public SshChannelType Type { get; private set; }
        public string? Command { get; set; }
        public string? Host { get; set; }
        public int Port { get; set; }
        public string? Path { get; set; }
    }
}