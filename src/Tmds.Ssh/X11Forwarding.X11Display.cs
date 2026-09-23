// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Tmds.Ssh;

partial class X11Forwarding
{
    // An X11 display as specified by the DISPLAY environment variable: [host]:displaynumber[.screennumber].
    internal sealed class X11Display
    {
        private X11Display(string name, string? host, string? socketPath, int displayNumber, int screenNumber)
        {
            Name = name;
            Host = host;
            SocketPath = socketPath;
            DisplayNumber = displayNumber;
            ScreenNumber = screenNumber;
        }

        public string Name { get; }

        // Host for a TCP display. 'null' for a local display.
        public string? Host { get; }

        // Unix socket path that is part of the display name (e.g. set by launchd on macOS).
        public string? SocketPath { get; }

        public int DisplayNumber { get; }

        public int ScreenNumber { get; }

        // The display name to pass to xauth.
        public string XAuthDisplayName
        {
            get
            {
                // Like OpenSSH: xauth doesn't find entries for 'localhost:N' and the launchd socket path.
                if (string.Equals(Host, "localhost", StringComparison.OrdinalIgnoreCase))
                {
                    return $"unix:{DisplayAndScreen}";
                }
                if (SocketPath is not null)
                {
                    return $":{DisplayAndScreen}";
                }
                return Name;
            }
        }

        private string DisplayAndScreen => ScreenNumber == 0
            ? DisplayNumber.ToString(CultureInfo.InvariantCulture)
            : string.Create(CultureInfo.InvariantCulture, $"{DisplayNumber}.{ScreenNumber}");

        public static bool TryParse(string name, [NotNullWhen(true)] out X11Display? display)
        {
            display = null;

            int colonPos = name.LastIndexOf(':');
            if (colonPos == -1)
            {
                return false;
            }

            ReadOnlySpan<char> host = name.AsSpan(0, colonPos);
            ReadOnlySpan<char> displayNumberSpan = name.AsSpan(colonPos + 1);
            int screenNumber = 0;
            int dotPos = displayNumberSpan.IndexOf('.');
            if (dotPos != -1)
            {
                if (!int.TryParse(displayNumberSpan.Slice(dotPos + 1), NumberStyles.None, CultureInfo.InvariantCulture, out screenNumber))
                {
                    return false;
                }
                displayNumberSpan = displayNumberSpan.Slice(0, dotPos);
            }
            if (!int.TryParse(displayNumberSpan, NumberStyles.None, CultureInfo.InvariantCulture, out int displayNumber) ||
                displayNumber > ushort.MaxValue - BaseTcpPort)
            {
                return false;
            }

            string? hostName = null;
            string? socketPath = null;
            if (host.Length > 0 && host[0] == '/')
            {
                // The socket path includes the display number but not the screen number.
                socketPath = name.Substring(0, colonPos + 1 + displayNumberSpan.Length);
            }
            else if (host.Length > 0 && !host.SequenceEqual("unix"))
            {
                if (host.Length > 1 && host[0] == '[' && host[^1] == ']')
                {
                    host = host[1..^1];
                }
                hostName = host.ToString();
            }

            display = new X11Display(name, hostName, socketPath, displayNumber, screenNumber);
            return true;
        }

        public override string ToString()
            => Name;
    }
}
