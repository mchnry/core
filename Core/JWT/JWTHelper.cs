namespace Mchnry.Core.JWT
{
    using Newtonsoft.Json;
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Text;
    using Mchnry.Core.Encryption;
    using Mchnry.Core.JWT.Exception;


    public class JWTHelper
    {


        private HashProvider hashProvider = null;
        public JWTHelper()
        {
            this.hashProvider = new HashProvider();
        }

        public JWTHelper(HashProvider hashProvider)
        {
            this.hashProvider = hashProvider;
        }





        public virtual string Encode<H, T>(jwt<H, T> jwt, RSA key) where T : tokenBase where H : headerBase
        {


            RSAHelper rsaHelper = new RSAHelper();

            var segments = new List<string>();


            jwt.Header.exp = jwt.Token.exp;

            string plainTextToken = JsonConvert.SerializeObject(jwt.Token, Newtonsoft.Json.Formatting.None);
            

            string encryptedToken = rsaHelper.Encrypt(plainTextToken, key.ExportParameters(false), false);

            //string encryptedToken = rijndaelHelper.Encrypt(passCode, plainTextToken).Base64StringValue;
            //rsaHelper.Encrypt(plainTextToken, key.ExportParameters(false), false);

            string sHeader = System.Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwt.Header, Newtonsoft.Json.Formatting.None)));
            string sDetails = System.Convert.ToBase64String(Encoding.UTF8.GetBytes(encryptedToken));

            string sInput = sHeader + "." + sDetails;
            byte[] bInput = Encoding.UTF8.GetBytes(sInput);

    
            
           


            byte[] signature = hashProvider.GetHash(((headerBase)jwt.Header).Algorithm, rsaHelper.GetPrivateKey(key)).Algorithm.ComputeHash(bInput);

            return sInput + "." + System.Convert.ToBase64String(signature);
        }

        public virtual bool IsJWTExpired<H>(string token, out TimeSpan remaining) where H : headerBase
        {
            bool expired = true;


            if (string.IsNullOrEmpty(token))
                throw new ArgumentNullException("token");

            string[] parts = token.Split('.');
            if (parts.Length != 3)
            {
                throw new jwtCorruptedException();
            }

            string sHeader = Encoding.UTF8.GetString(System.Convert.FromBase64String(parts[0]));
            headerTest header = Newtonsoft.Json.JsonConvert.DeserializeObject<headerTest>(sHeader);

            remaining = DateTime.UtcNow - IntToDate(((headerBase)header).exp);
            expired = DateTime.UtcNow > IntToDate(((headerBase)header).exp);

            return expired;

        }

        public virtual jwt<H, T> Decode<H, T>(string token, RSA key, out bool expired) where T : tokenBase where H : headerBase
        {


            RSAHelper rsaHelper = new RSAHelper();

            expired = true;

            jwt<H, T> toReturn = new jwt<H, T>() { Header = null, Token = null };

            if (string.IsNullOrEmpty(token))
                throw new ArgumentNullException("token");

            string[] parts = token.Split('.');

            if (parts.Length != 3)
            {
                throw new jwtCorruptedException();
            }
    

            string sHeader, sDetails, encryptedDetails;
            try
            {
                sHeader = Encoding.UTF8.GetString(System.Convert.FromBase64String(parts[0]));
                encryptedDetails = Encoding.UTF8.GetString(System.Convert.FromBase64String(parts[1]));

                sDetails = rsaHelper.Decrypt(encryptedDetails, key.ExportParameters(true), false);

                //sDetails = rijndaelHelper.Decrypt(passCode, new RijndaelEncryptedValue(encryptedDetails));
                //rsaHelper.Decrypt(encryptedDetails, key.ExportParameters(true), false);
            }
            catch (System.Exception e)
            {
                throw new jwtCorruptedException("JWT From Client is Corrupt", e);
            }

            //H header = Newtonsoft.Json.Linq.JObject.Parse(sHeader);
            H header = Newtonsoft.Json.JsonConvert.DeserializeObject<H>(sHeader);
            T content = Newtonsoft.Json.JsonConvert.DeserializeObject<T>(sDetails);

            // validate
            byte[] bytes = Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);


            string signature = System.Convert.ToBase64String(hashProvider.GetHash(((headerBase)header).Algorithm, rsaHelper.GetPrivateKey(key)).Algorithm.ComputeHash(bytes));

            if (string.Compare(parts[2], signature, true) == 0)
            {



                //expired = DateTime.UtcNow > IntToDate((int)tokenHeader["exp"]);
                expired = DateTime.UtcNow > IntToDate(((tokenBase)content).exp);

                toReturn.Header = header;
                toReturn.Token = content;

            }
            else
            {
                throw new jwtCorruptedException();
            }

            return toReturn;
        }

        public virtual int[] DateToInt(TimeSpan offset)
        {
            var baseTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var issueTime = DateTime.UtcNow;

            return new[] {
                (int)issueTime.Subtract(baseTime).TotalSeconds,
                (int)issueTime.Subtract(baseTime).Add(offset).TotalSeconds
            };
        }

        public virtual DateTime IntToDate(int seconds)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(seconds);
        }

    }
}
