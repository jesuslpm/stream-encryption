

using System;
using System.IO;
using System.Security.Cryptography;

namespace ProtectFile
{
    internal class Program
    {
        static int Main(string[] args)
        {
            if (args.Length != 1) 
            {
                Console.Error.WriteLine("Usage: ProtectFile <file to protect>");
                return 1;
            }
            var plainBytes = File.ReadAllBytes(args[0]);
            var entropy = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(entropy);
            }

            var cipherBytes = ProtectedData.Protect(plainBytes, entropy, DataProtectionScope.CurrentUser);

            using (var destFile = File.Create(args[0] + ".protected")) 
            { 
                destFile.Write(entropy, 0, entropy.Length);
                destFile.Write(cipherBytes, 0, cipherBytes.Length);
            }

            return 0;
        }
    }
}