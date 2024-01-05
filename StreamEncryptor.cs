using HkdfStandard;
using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace StreamEncryption
{
    public sealed class StreamEncryptor : IDisposable
    {
        private readonly RSA rsa;

        const int MAC_LEN = 48;
        const int HMACK_KEY_LEN = 64;
        const int AES_KEY_LEN = 32;
        const int AES_IV_LEN = 16;
        const int SALT_LEN = 32;
        const int INFO_LEN = 8;
        const int IKM_LEN = 64;
        const int PLAIN_BUFFER_SIZE = 1024 * 64 - 1;
        const int CIPHER_BUFFER_SIZE = PLAIN_BUFFER_SIZE + 1 + MAC_LEN + SALT_LEN + INFO_LEN;

        public StreamEncryptor(RSAParameters parameters)
        {
            this.rsa = new RSACng();
            rsa.ImportParameters(parameters);
        }

        public bool IsDisposed { get; private set; }

        public void Dispose()
        {
            if (IsDisposed) return;
            IsDisposed = true;
            rsa.Dispose();
        }

        static Aes CreateAesCbc256(byte[] ikm, byte[] salt, byte[] info)
        {
            var aes = Aes.Create();
            if (aes.KeySize != AES_KEY_LEN * 8) aes.KeySize = AES_KEY_LEN * 8;
            if (aes.Mode != CipherMode.CBC) aes.Mode = CipherMode.CBC;
            if (aes.Padding != PaddingMode.PKCS7) aes.Padding = PaddingMode.PKCS7;
            var keys = Hkdf.DeriveKey(HashAlgorithmName.SHA384, ikm, AES_KEY_LEN + AES_IV_LEN, salt, info);
            var key = new byte[AES_KEY_LEN];
            Array.Copy(keys, 0, key, 0, AES_KEY_LEN);
            var iv = new byte[AES_IV_LEN];
            Array.Copy(keys, AES_KEY_LEN, iv, 0, AES_IV_LEN);
            aes.Key = key;
            aes.IV = iv;
            return aes;
        }

        static byte[] GenerateRandomNumber(int size)
        {
            using (var generator = RandomNumberGenerator.Create())
            {
                var randomNumber = new byte[size];
                generator.GetBytes(randomNumber);
                return randomNumber;
            }
        }

        static byte[] Concatenate(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            return result;
        }


        static int AesEncrypt(Aes aes, byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
        {
            using (var transform = aes.CreateEncryptor())
            {
                int bytesWritten = 0;
                int blocks = inputCount / transform.InputBlockSize;
                int finalInputSize = inputCount - blocks * transform.InputBlockSize;
                if (blocks > 0)
                {
                    bytesWritten = transform.TransformBlock(input, inputOffset, blocks * transform.InputBlockSize, output, outputOffset);
                }
                var finalOutputBlock = transform.TransformFinalBlock(input, inputOffset + bytesWritten, finalInputSize);
                Array.Copy(finalOutputBlock, 0, output, outputOffset + bytesWritten, finalOutputBlock.Length);
                bytesWritten += finalOutputBlock.Length;
                return bytesWritten;
            }
        }

        static int AesDecrypt(Aes aes, byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
        {
            using (var transform = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                int blocks = inputCount / transform.InputBlockSize;
                int blockBytes = (blocks - 1) * transform.InputBlockSize;
                int bytesWritten = 0;
                if (blockBytes > 0)
                {
                    bytesWritten = transform.TransformBlock(input, inputOffset, blockBytes, output, outputOffset);
                }
                var finalOuputBlock = transform.TransformFinalBlock(input, inputOffset + (blocks - 1) * transform.InputBlockSize, inputCount - blockBytes);
                Array.Copy(finalOuputBlock, 0, output, bytesWritten, finalOuputBlock.Length);
                bytesWritten += finalOuputBlock.Length;
                return bytesWritten;
            }
        }

        private static byte[] emptyBlock = new byte[0];

        static void ComputeHash(HMACSHA384 hmac, byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
        {
            hmac.TransformBlock(input, inputOffset, inputCount, null, 0);
            hmac.TransformFinalBlock(emptyBlock, 0, 0);
            Array.Copy(hmac.Hash, 0, output, outputOffset, hmac.Hash.Length);
        }

        private static (byte[] aesikm, byte[] hmacKey) CreateKeys()
        {
            var ikm = GenerateRandomNumber(IKM_LEN);
            var salt = GenerateRandomNumber(SALT_LEN);
            var info = GenerateRandomNumber(INFO_LEN);
            var keys = Hkdf.DeriveKey(HashAlgorithmName.SHA384, ikm, IKM_LEN + HMACK_KEY_LEN, salt, info);
            var aesikm = new byte[IKM_LEN];
            Array.Copy(keys, 0, aesikm, 0, IKM_LEN);
            var hmacKey = new byte[HMACK_KEY_LEN];
            Array.Copy(keys, IKM_LEN, hmacKey, 0, HMACK_KEY_LEN);
            return (aesikm, hmacKey);
        }

        public void Encrypt(Stream clearSource, Stream cipherDestination)
        {
            var cipherBuffer = new byte[CIPHER_BUFFER_SIZE];
            var clearBuffer = new byte[PLAIN_BUFFER_SIZE];
            var (aesikm, hmacKey) = CreateKeys();
            using (var hmac = new HMACSHA384(hmacKey))
            {
                var header = Concatenate(hmacKey, aesikm);

                var cipherHeader = rsa.Encrypt(header, RSAEncryptionPadding.OaepSHA384);
                cipherDestination.Write(cipherHeader, 0, cipherHeader.Length);

                var headerSignature = rsa.SignData(header, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
                var signatureChunk = new byte[rsa.KeySize / 16];

                Array.Copy(headerSignature, 0, signatureChunk, 0, signatureChunk.Length);
                var encryptedSignatureChunk = rsa.Encrypt(signatureChunk, RSAEncryptionPadding.OaepSHA384);
                cipherDestination.Write(encryptedSignatureChunk, 0, encryptedSignatureChunk.Length);

                Array.Copy(headerSignature, signatureChunk.Length, signatureChunk, 0, signatureChunk.Length);
                encryptedSignatureChunk = rsa.Encrypt(signatureChunk, RSAEncryptionPadding.OaepSHA384);
                cipherDestination.Write(encryptedSignatureChunk, 0, encryptedSignatureChunk.Length);

                long chunkNumber = 1;

                while (true)
                {
                    var clearBytesRead = Read(clearSource, clearBuffer, 0, clearBuffer.Length);
                    if (clearBytesRead < clearBuffer.Length) chunkNumber = -chunkNumber;
                    var salt = GenerateRandomNumber(SALT_LEN);
                    byte[] info = new byte[INFO_LEN];
                    BinaryPrimitives.WriteInt64BigEndian(info, chunkNumber);
                    using (var aes = CreateAesCbc256(aesikm, salt, info))
                    {
                        var cipherBytes = AesEncrypt(aes, clearBuffer, 0, clearBytesRead, cipherBuffer, MAC_LEN + SALT_LEN + INFO_LEN);
                        Array.Copy(salt, 0, cipherBuffer, MAC_LEN, SALT_LEN);
                        Array.Copy(info, 0, cipherBuffer, MAC_LEN + SALT_LEN, INFO_LEN);
                        ComputeHash(hmac, cipherBuffer, MAC_LEN, cipherBytes + SALT_LEN + INFO_LEN, cipherBuffer, 0);
                        cipherDestination.Write(cipherBuffer, 0, cipherBytes + MAC_LEN + SALT_LEN + INFO_LEN);
                    }
                    if (chunkNumber < 0) return;
                    chunkNumber++;
                }
            }
        }

        static void RequiredRead(Stream stream, byte[] data)
        {
            int remainingBytes = data.Length;
            while (remainingBytes > 0)
            {
                var bytesRead = stream.Read(data, data.Length - remainingBytes, remainingBytes);
                if (bytesRead == 0)
                {
                    throw new EndOfStreamException("Unexpected end of stream");
                }
                remainingBytes -= bytesRead;
            }
        }

        static int Read(Stream stream, byte[] buffer, int offset, int count)
        {
            int remainingBytesToRead = count;
            int totalBytesRead = 0;
            while (remainingBytesToRead > 0)
            {
                var bytesRead = stream.Read(buffer, offset + totalBytesRead, remainingBytesToRead);
                remainingBytesToRead -= bytesRead;
                totalBytesRead += bytesRead;
                if (bytesRead == 0)  break; 
            }
            return totalBytesRead;
        }

        public void Decrypt(Stream encryptedSource, Stream clearDestination)
        {

            var cipherMsgLength = this.rsa.KeySize / 8;

            var encHeader = new byte[cipherMsgLength];
            RequiredRead(encryptedSource, encHeader);
            var header = this.rsa.Decrypt(encHeader, RSAEncryptionPadding.OaepSHA384);

            var signedData = new byte[cipherMsgLength];

            var cipherSignatureChunk = new byte[cipherMsgLength];
            RequiredRead(encryptedSource, cipherSignatureChunk);
            var signatureChunk = this.rsa.Decrypt(cipherSignatureChunk, RSAEncryptionPadding.OaepSHA384);
            Array.Copy(signatureChunk, 0, signedData, 0, signatureChunk.Length);

            RequiredRead(encryptedSource, cipherSignatureChunk);
            signatureChunk = this.rsa.Decrypt(cipherSignatureChunk, RSAEncryptionPadding.OaepSHA384);
            Array.Copy(signatureChunk, 0, signedData, signatureChunk.Length, signatureChunk.Length);

            if (rsa.VerifyData(header, signedData, HashAlgorithmName.SHA384, RSASignaturePadding.Pss) == false)
            {
                throw new CryptographicException("Header signature validation failed");
            }

            var hmacKey = new byte[HMACK_KEY_LEN];
            var aesikm = new byte[IKM_LEN];

            Array.Copy(header, 0, hmacKey, 0, HMACK_KEY_LEN);
            Array.Copy(header, HMACK_KEY_LEN, aesikm, 0, IKM_LEN);

            var cipherBuffer = new byte[CIPHER_BUFFER_SIZE];
            var plainBuffer = new byte[PLAIN_BUFFER_SIZE];
            var storedHmac = new byte[MAC_LEN];
            var calculatedHmac = new byte[MAC_LEN];
            var salt = new byte[SALT_LEN];
            var info = new byte[INFO_LEN];

            long chunkNumber = 1;
            bool isCompleted = false;

            using (var hmac = new HMACSHA384(hmacKey))
            {
                while (true)
                {
                    int bytesRead = Read(encryptedSource, cipherBuffer, 0, CIPHER_BUFFER_SIZE);
                    if (bytesRead == 0)
                    {
                        if (isCompleted == false)
                        {
                            throw new EndOfStreamException("Unexpected end of stream");
                        }
                        return;
                    }
                    else if (isCompleted)
                    {
                        throw new CryptographicException("Some data has been externally appended to the file");
                    }
                    
                    if (bytesRead < MAC_LEN + SALT_LEN + INFO_LEN) throw new EndOfStreamException("Unexpected end of stream");
                    Array.Copy(cipherBuffer, 0, storedHmac, 0, MAC_LEN);
                    ComputeHash(hmac, cipherBuffer, MAC_LEN, bytesRead - MAC_LEN, calculatedHmac, 0);
                    if (storedHmac.SequenceEqual(calculatedHmac) == false)
                    {
                        throw new CryptographicException("Message authentication code validation failed");
                    }
                    Array.Copy(cipherBuffer, MAC_LEN, salt, 0, SALT_LEN);
                    Array.Copy(cipherBuffer, MAC_LEN + SALT_LEN, info, 0, INFO_LEN);
                    var storedChunkNumber = BinaryPrimitives.ReadInt64BigEndian(info);
                    if (storedChunkNumber < 0)
                    {
                        storedChunkNumber = -storedChunkNumber;
                        isCompleted = true;
                    }
                    if (storedChunkNumber != chunkNumber)
                    {
                        throw new CryptographicException("File chunks are not in proper sequence");
                    }
                    using (var aes = CreateAesCbc256(aesikm, salt, info))
                    {
                        var plainBytes = AesDecrypt(aes, cipherBuffer, MAC_LEN + SALT_LEN + INFO_LEN, bytesRead - MAC_LEN - SALT_LEN - INFO_LEN, plainBuffer, 0);
                        clearDestination.Write(plainBuffer, 0, plainBytes);
                    }
                    chunkNumber++;
                }
            }
        }
    }
}
