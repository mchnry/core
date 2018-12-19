namespace Mchnry.Core.Encryption
{
    using System;
    using System.Security.Cryptography;


    public class HashProvider
    {
        public virtual Hash GetHash(string algorithmName, byte[] key)
        {

            if (string.IsNullOrEmpty(algorithmName))
            {
                throw new ArgumentNullException("Caller did not provide a valid algorithm name");
            }
            if (key == null || key.Length == 0)
            {
                throw new ArgumentNullException("Caller did not provide a key");
            }

            switch (algorithmName.ToUpper())
            {
                case "HS256":
                    return new Hash()
                    {
                        Name = "HS256"
                        ,
                        Algorithm = new HMACSHA256(key)
                    };

                case "HS384":
                    return new Hash()
                    {
                        Name = "HS384"
                        ,
                        Algorithm = new HMACSHA384(key)
                    };
                case "HS512":
                    return new Hash()
                    {
                        Name = "HS512"
                        ,
                        Algorithm = new HMACSHA512(key)
                    };
                default:
                    throw new ArgumentOutOfRangeException("Provider does not support requested algorithm");

            }

        }
    }
}
