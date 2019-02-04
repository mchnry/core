namespace Mchnry.Core.Encryption
{
    using System.Security.Cryptography;

    public interface IRSAKeyProvider
    {

        RSA GetKey();

    }
}
