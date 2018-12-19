namespace Mchnry.Core.Encryption
{
    using System.Security.Cryptography.X509Certificates;

    public interface ICertificateProvider
    {

        /// <summary>
        /// Finds an x509 certificate within the provider's backing store
        /// </summary>
        /// <remarks><list type="bullet">
        ///     <item>if certificate is password protected, this should throw an exception. Caller should call overidded method that accepts a password</item>
        /// </list></remarks>
        /// <param name="certificateName">Identifies a certificate by a unique name within the Provider's backing store. 
        /// This is not a file path.  If the certificate does reside in a file, the implementation is responsible for managing a
        /// name pointer. Callers should not be aware of certificate paths!!!!</param>
        /// <returns></returns>
        X509Certificate2 GetCertificate(string certificateName);

        /// <summary>
        /// Overloads GetCertificate, but requires a password
        /// </summary>
        /// <param name="passCode"></param>
        /// <returns></returns>
        X509Certificate2 GetCertificate(string certificateName, string passCode);

    }
}
