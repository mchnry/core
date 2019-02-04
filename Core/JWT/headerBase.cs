namespace Mchnry.Core.JWT
{
    using System;
    using Newtonsoft.Json;

    public abstract class headerBase
    {
        [JsonProperty(PropertyName = "alg")]
        public string Algorithm { get; set; }
        [JsonProperty(PropertyName = "typ")]
        public string TokenName { get; set; }
        [JsonProperty(PropertyName = "exp")]
        public int exp { get; set; }
    }

    internal class headerTest : headerBase { }
}
