namespace Mchnry.Core.JWT.Exception
{
    using System;

    public class jwtCorruptedException : System.Exception
    {
        public jwtCorruptedException() : base() { }
        public jwtCorruptedException(string message, Exception innerException) : base(message, innerException) { }
    }
}
