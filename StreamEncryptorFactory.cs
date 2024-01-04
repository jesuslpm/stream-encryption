using System;
using System.Security.Cryptography;

namespace StreamEncryption
{
    public class StreamEncryptorFactory
    {

        private readonly RSAParameters parameters;

        public StreamEncryptorFactory(string xml) 
        { 
            using (var rsa = new RSACng())
            {
                rsa.FromXmlString(xml);
                this.parameters = rsa.ExportParameters(true);
            }
        }

        public StreamEncryptor Create()
        {
            return new StreamEncryptor(parameters);
        }
    }
}
