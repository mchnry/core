namespace Mchnry.Core.Encryption
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    public class RSAHelper
    {

        public virtual byte[] GetPublicKey(RSACryptoServiceProvider csp)
        {
            byte[] toReturn = null;

            if (csp == null) throw new ArgumentNullException("csp", "CSP must be provided");

            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    //EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    //EncodeIntegerBigEndian(innerWriter, parameters.D);
                    //EncodeIntegerBigEndian(innerWriter, parameters.P);
                    //EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    //EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    //EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    //EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                toReturn = stream.ToArray();

                //var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                //outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
                //// Output as Base64 with lines chopped at 64 characters
                //for (var i = 0; i < base64.Length; i += 64) {
                //    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                //}
                //outputStream.WriteLine("-----END RSA PRIVATE KEY-----");
            }
            return toReturn;

        }

        public virtual byte[] GetPrivateKey(RSA csp)
        {

            byte[] toReturn = null;

            if (csp == null) throw new ArgumentNullException("csp", "CSP must be provided");

            //if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                toReturn = stream.ToArray();

                //var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                //outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
                //// Output as Base64 with lines chopped at 64 characters
                //for (var i = 0; i < base64.Length; i += 64) {
                //    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                //}
                //outputStream.WriteLine("-----END RSA PRIVATE KEY-----");
            }
            return toReturn;
        }

        public virtual string Encrypt(string toEncrypt, RSAParameters keyInfo, bool DoOAEPPadding)
        {

            string toReturn = null;
            if (string.IsNullOrEmpty(toEncrypt)) throw new ArgumentNullException("No value to encrypt");

            //RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)cert.PublicKey.Key;

            //convert toEncrypt to base64 string
            byte[] bytesToEncrypt = Encoding.UTF8.GetBytes(toEncrypt);
            byte[] toEncryptAsBase64 = Convert.FromBase64String(Convert.ToBase64String(bytesToEncrypt));

            using (RSACryptoServiceProvider publicKey = new RSACryptoServiceProvider())
            {
                publicKey.ImportParameters(keyInfo);

                byte[] encryptedBytes = publicKey.Encrypt(toEncryptAsBase64, DoOAEPPadding);

                toReturn = Convert.ToBase64String(encryptedBytes);
            }


            return toReturn;


        }

        public virtual string Decrypt(string toDecrypt, RSAParameters keyInfo, bool DoOAEPPadding)
        {

            string toReturn = null;

            if (string.IsNullOrEmpty(toDecrypt)) throw new ArgumentNullException("No value to encrypt");

            //RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)cert.PrivateKey;
            using (RSACryptoServiceProvider privateKey = new RSACryptoServiceProvider())
            {
                privateKey.ImportParameters(keyInfo);

                if (privateKey.PublicOnly)
                {
                    throw new ArgumentException("privateKey is public only");
                }

                byte[] decryptedBytes = privateKey.Decrypt(Convert.FromBase64String(toDecrypt), DoOAEPPadding);

                toReturn = Encoding.UTF8.GetString(decryptedBytes);
            }

            return toReturn;
        }

        public virtual byte[] Encrypt(byte[] toEncrypt, RSAParameters keyInfo, bool DoOAEPPadding)
        {

            byte[] encrypted;
            using (RSACryptoServiceProvider publicKey = new RSACryptoServiceProvider())
            {
                publicKey.ImportParameters(keyInfo);
                encrypted = publicKey.Encrypt(toEncrypt, DoOAEPPadding);

            }
            return encrypted;
        }

        public virtual byte[] Decrypt(byte[] toDecrypt, RSAParameters keyInfo, bool DoOAEPPadding)
        {

            byte[] decrypted;

            using (RSACryptoServiceProvider privateKey = new RSACryptoServiceProvider())
            {

                privateKey.ImportParameters(keyInfo);
                if (privateKey.PublicOnly)
                {
                    throw new ArgumentException("privateKey is public only");
                }
                decrypted = privateKey.Decrypt(toDecrypt, DoOAEPPadding);

            }


            return decrypted;
        }

        private void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

    }
}
