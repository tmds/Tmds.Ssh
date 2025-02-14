// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

static class ArgumentValidation
{
    public static void ValidatePort(int port, bool allowZero, string argumentName = "port")
    {
        if (port < 0 || port > 0xffff || (!allowZero && port == 0))
        {
            throw new ArgumentException(argumentName);
        }
    }

    public static void ValidateIPListenAddress(string address, string argumentName = "address")
    {
        if (address is null)
        {
            throw new ArgumentNullException(argumentName);
        }

        if (address.Length == 0)
        {
            throw new ArgumentException("The address can not be empty.", argumentName);
        }

        if (address == Constants.AnyAddress)
        {
            return;
        }

        if (!IsValidHostName(address))
        {
            throw new ArgumentException("The address is not valid", argumentName);
        }
    }

    public static void ValidateHost(string host, bool allowEmpty = false, string argumentName = "host")
    {
        if (host is null)
        {
            throw new ArgumentNullException(argumentName);
        }

        if (host.Length == 0)
        {
            if (allowEmpty)
            {
                return;
            }
            throw new ArgumentException("The host can not be empty.", argumentName);
        }

        if (!IsValidHostName(host))
        {
            throw new ArgumentException("The host name is not valid", argumentName);
        }
    }

    private static bool IsValidHostName(string address)
    {
        // Check whether the name is an IPv4/IPv6/DNS name using 'Uri.CheckHostName'.
        // Disallow IPv6 addresses to be enclosed with '[]'.
        return !address.StartsWith('[') && Uri.CheckHostName(address) is UriHostNameType.IPv4 or UriHostNameType.IPv6 or UriHostNameType.Dns;
    }
}