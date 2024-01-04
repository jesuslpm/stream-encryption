using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace StreamEncryption
{
    internal class Program
    {
        static void Main(string[] args)
        {
            
            var watch = Stopwatch.StartNew();
            // GenerateRsaKey();
            Encrypt();
            Decrypt();
            Console.WriteLine(watch.Elapsed.ToString());
        }

        static void GenerateRsaKey()
        {
            using (var rsa = new RSACng(8192))
            {
                var xml = rsa.ToXmlString(true);
                File.WriteAllText("rsa_key_pair.xml", xml);
            }
        }

        static void Encrypt()
        {
            var xml = File.ReadAllText("rsa_key_pair.xml");
            var factory = new StreamEncryptorFactory(xml);
            using (var cipher = factory.Create())
            using (var source = File.OpenRead("test.pdf"))
            using (var target = File.Create("test.pdf.encrypted"))
            {
                cipher.Encrypt(source, target);
            }
        }

        static void Decrypt()
        {
            var xml = File.ReadAllText("rsa_key_pair.xml");
            var factory = new StreamEncryptorFactory(xml);
            using (var cipher = factory.Create())
            using (var source = File.OpenRead("test.pdf.encrypted"))
            using (var target = File.Create("test.pdf"))
            {
                cipher.Decrypt(source, target);
            }
        }

    }
}