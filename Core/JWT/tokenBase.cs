namespace Mchnry.Core.JWT
{
    using Newtonsoft.Json;
    using System;

    public abstract class tokenBase
    {
        [JsonProperty(PropertyName = "iat")]
        public int iat { get; set; }
        [JsonProperty(PropertyName = "exp")]
        public int exp { get; set; }
    }
}
