// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using static System.Environment;

namespace Tmds.Ssh
{
    sealed public class IdentityFileCredential : Credential
    {
        public IdentityFileCredential() :
            this(GetDefaultFile())
        { }

        private static string GetDefaultFile()
        {
            return Path.Combine(Environment.GetFolderPath(SpecialFolder.MyDocuments, SpecialFolderOption.DoNotVerify), ".ssh", "id_rsa");
        }

        public IdentityFileCredential(string filename)
        {
            Filename = filename ?? throw new ArgumentNullException(nameof(filename));
        }

        internal string Filename { get; }

        internal static bool TryParseFile(string filename, out PrivateKey? privateKey)
        {
            privateKey = null;
            StringBuilder sb;
            try
            {
                // TODO verify file doesn't have permissions for group/other.
                if (!File.Exists(filename))
                {
                    return false;
                }

                sb = new StringBuilder();
                bool collect = false;
                foreach (var line in File.ReadAllLines(filename))
                {
                    if (line == "-----BEGIN RSA PRIVATE KEY-----")
                    {
                        collect = true;
                    }
                    else if (line.StartsWith("-----END ", StringComparison.Ordinal))
                    {
                        break;
                    }
                    else if (line.Contains(":"))
                    { }
                    else if (collect)
                    {
                        sb.Append(line.Trim());
                    }
                }
            }
            catch (IOException)
            {
                return false;
            }

            byte[] keyData;
            try
            {
                keyData = Convert.FromBase64String(sb.ToString());
            }
            catch (FormatException)
            {
                return false;
            }

            RSA? rsa = RSA.Create();
            try
            {
                rsa.ImportRSAPrivateKey(keyData, out int bytesRead);
                if (bytesRead != keyData.Length)
                {
                    rsa.Dispose();
                    return false;
                }
                privateKey = new RsaPrivateKey(rsa);
                return true;
            }
            catch
            {
                rsa?.Dispose();
                return false;
            }
        }
    }
}
