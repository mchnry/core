namespace Mchnry.Core.Encryption
{
    using System.Security.Cryptography;

    /// <summary>
    /// Helper class
    /// </summary>
    public class Hash
    {
        public string Name { get; set; }
        public HashAlgorithm Algorithm { get; set; }
    }
}
