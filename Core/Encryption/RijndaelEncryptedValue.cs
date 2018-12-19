namespace Mchnry.Core.Encryption
{
    using System;

    [Serializable]
    public class RijndaelEncryptedValue
    {


        private string value = string.Empty;
        private string iv = string.Empty;
        private string salt = string.Empty;

        public RijndaelEncryptedValue(byte[] encryptedValue, byte[] iv, byte[] salt)
        {

            this.value = Convert.ToBase64String(encryptedValue);
            this.salt = Convert.ToBase64String(salt);
            this.iv = Convert.ToBase64String(iv);

        }

        public RijndaelEncryptedValue(string base64StringValue)
        {

            this.iv = base64StringValue.Substring(0, 24);
            this.salt = base64StringValue.Substring(24, 12);
            this.value = base64StringValue.Substring(36, base64StringValue.Length - 36);



        }

        public string Base64Value { get { return this.value; } }
        public string Base64IV { get { return this.iv; } }
        public string Base64Salt { get { return this.salt; } }

        public String Base64StringValue {
            get {

                return this.Base64IV + this.Base64Salt + this.Base64Value;
            }
        }

    }
}
