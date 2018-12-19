namespace Mchnry.Core.Encryption
{
    using System;
    using System.IO;
    using System.Security.Cryptography;


    public class RijndaelHelper
    {

        public virtual byte[] GenerateSalt()
        {

            byte[] salt = new byte[8];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }

        private byte[] GenerateKey(string passCode, byte[] salt)
        {
            Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(passCode, salt);
            return k1.GetBytes(16);
        }

        public virtual RijndaelEncryptedValue Encrypt(string passCode, string data)
        {

            byte[] iv = null;
            byte[] salt = this.GenerateSalt();

            try
            {

                using (var rijndael = new RijndaelManaged()
                {
                    Mode = CipherMode.CBC
                    ,
                    Padding = PaddingMode.PKCS7
                })
                {
                    rijndael.GenerateIV();
                    iv = rijndael.IV;
                    return this.Encrypt(passCode, data, salt, iv);
                }
            }
            catch (Exception)
            {

                throw;
            }
            finally
            {
                ClearBytes(salt);
                ClearBytes(iv);
            }

        }

        public virtual RijndaelEncryptedValue Encrypt(string passCode, string data, byte[] salt)
        {

            byte[] iv = null;

            try
            {

                using (var rijndael = new RijndaelManaged()
                {
                    Mode = CipherMode.CBC
                    ,
                    Padding = PaddingMode.PKCS7
                })
                {
                    rijndael.GenerateIV();
                    iv = rijndael.IV;
                    return this.Encrypt(passCode, data, salt, iv);
                }
            }
            catch (Exception)
            {

                throw;
            }
            finally
            {
                ClearBytes(salt);
                ClearBytes(iv);
            }

        }

        public virtual RijndaelEncryptedValue Encrypt(string passCode, string data, byte[] salt, byte[] iv)
        {

            if (string.IsNullOrEmpty(passCode)) throw new ArgumentNullException("passCode");
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException("data");

            byte[] key = null;

            try
            {

                key = this.GenerateKey(passCode, salt);
                RijndaelEncryptedValue toReturn = null;

                using (var rijndael = new RijndaelManaged()
                {
                    Mode = CipherMode.CBC
                    ,
                    Padding = PaddingMode.PKCS7
                    ,
                    Key = key
                    ,
                    IV = iv

                })
                {
                    using (var encryptor = rijndael.CreateEncryptor(key, iv))
                    using (var mem = new MemoryStream())
                    using (var crypt = new CryptoStream(mem, encryptor, CryptoStreamMode.Write))
                    using (var writer = new StreamWriter(crypt))
                    {

                        writer.Write(data);
                        writer.Flush();
                        crypt.Flush();
                        crypt.FlushFinalBlock();

                        byte[] encrypted = mem.ToArray();

                        toReturn = new RijndaelEncryptedValue(encrypted, iv, salt);
                    }
                }

                return toReturn;
            }
            finally
            {
                ClearBytes(salt);
                ClearBytes(iv);
                ClearBytes(key);
            }

        }

        public virtual string Decrypt(string passCode, RijndaelEncryptedValue data)
        {

            byte[] salt = null;
            byte[] iv = null;
            byte[] key = null;
            byte[] encrypted = null;

            try
            {

                salt = Convert.FromBase64String(data.Base64Salt);
                iv = Convert.FromBase64String(data.Base64IV);
                encrypted = Convert.FromBase64String(data.Base64Value);

                key = this.GenerateKey(passCode, salt);

                using (var rijndael = new RijndaelManaged()
                {
                    Mode = CipherMode.CBC
                    ,
                    IV = iv
                    ,
                    Key = key
                    ,
                    Padding = PaddingMode.PKCS7
                })
                {
                    using (var decryptor = rijndael.CreateDecryptor(key, iv))
                    using (var memoryStream = new MemoryStream(encrypted))
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (var writer = new StreamReader(cryptoStream))
                    {
                        //writer.Write(encrypted);
                        //writer.Flush();
                        //cryptoStream.Flush();
                        //cryptoStream.FlushFinalBlock();
                        //return Convert.ToBase64String(memoryStream.ToArray());
                        return writer.ReadToEnd();
                    }
                }

            }
            catch (Exception)
            {

                return string.Empty;

            }
            finally
            {
                ClearBytes(salt);
                ClearBytes(iv);
                ClearBytes(key);
                ClearBytes(encrypted);
            }

        }

        /// <summary>
        /// Clean up memory to which buffer points.
        /// </summary>
        /// <param name="buffer">Someone or something that buffs.</param>
        private static void ClearBytes(byte[] buffer)
        {
            // Check arguments.
            if (buffer == null)
            {
                throw new ArgumentException("buffer");
            }

            // Set each byte in the buffer to 0.
            for (int x = 0; x < buffer.Length; x++)
            {
                buffer[x] = 0;
            }
        }

    }
}
