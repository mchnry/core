using Newtonsoft.Json;

namespace Mchnry.Core.JWT
{
    public class ApiToken : tokenBase
    {

        [JsonProperty(PropertyName = "jti")]
        public string JTI { get; set; }

        [JsonProperty(PropertyName = "sub")]
        public string Subject { get; set; }


        [JsonProperty(PropertyName = "ips")]
        public string[] IPS { get; set; }


    }

    public class ApiHeader : headerBase
    {

    }
}
