using System;
using System.IO;
using System.Security.Cryptography;

namespace UnprotectFile
{
    internal class Program
    {
        static int Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.Error.WriteLine("Usage: UnprotectFile <file to unprotect>");
                return 1;
            }
            var sourcePath = args[0];
            var extension = Path.GetExtension(sourcePath);
            if (extension != ".protected")
            {
                Console.Error.WriteLine("protected files must have .protected extension");
                return 1;
            }
            var destPath = sourcePath.Substring(0, sourcePath.Length - extension.Length);
            var entropy = new byte[16];
            var encryptedBytes = File.ReadAllBytes(sourcePath);
            Array.Copy(encryptedBytes, 0, entropy, 0, 16);
            var cipherBytes = new byte[encryptedBytes.Length - 16];
            Array.Copy(encryptedBytes, 16, cipherBytes, 0, cipherBytes.Length);
            var plainBytes = ProtectedData.Unprotect(cipherBytes, entropy, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(destPath, plainBytes);
            return 0;
        }
    }
}