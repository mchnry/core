namespace Mchnry.Core.Encryption
{
    //using System.Security.Cryptography;
    //using System.Security.Cryptography.X509Certificates;

    //public class LocalMachineCertProvider : IRSAKeyProvider
    //{
    //    private X509FindType findBy;
    //    private string certTP;

    //    public LocalMachineCertProvider(X509FindType findBy, string certTP)
    //    {
    //        this.findBy = findBy;
    //        this.certTP = certTP;
    //    }

    //    RSACryptoServiceProvider IRSAKeyProvider.GetKey()
    //    {

    //        X509Certificate2 cert = null;


    //        if (cert == null)
    //        {
    //            //Azure puts cert in my, currentuser
    //            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    //            store.Open(OpenFlags.ReadOnly);
    //            X509Certificate2Collection certs = store.Certificates.Find(findBy
    //                , certTP, false);


    //            if (certs.Count > 0)
    //            {
    //                cert = certs[0];
    //            }
    //            store.Close();
    //        }

    //        return (RSACryptoServiceProvider)cert.PrivateKey;
    //    }
    //}
}
