using Newtonsoft.Json; // Will need to install this as a nuget package
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace TIA_Example
{
    class Program
    {
        static void Main(string[] args)
        {
            string hostUrl = "https://threatintelligenceaggregator.org/api";
            string apiKey = "ABCDEF01234567";
            string vendorName = "Sophos";
            string searchQuery = "Troj/Zbot-LRN";

            searchQuery = WebUtility.UrlEncode(searchQuery);
            string url = $"{hostUrl}/v1/{vendorName}/?name={searchQuery}&ApiKey={apiKey}";

            string jsonResponse = Web.ApiCall(url);

            ThreatEntry responseObject = JsonConvert.DeserializeObject<ThreatEntry>(jsonResponse);

            Console.WriteLine(jsonResponse);
            Console.WriteLine();
            Console.WriteLine(responseObject.VendorName);
            Console.WriteLine(responseObject.DetectionName);
            Console.WriteLine(responseObject.URL);
            Console.WriteLine(responseObject.MalwareType);
        }
    }

    public partial class ThreatEntry
    {
        public string VendorName { get; set; }
        public string DetectionName { get; set; }
        public string URL { get; set; } = null;
        public string MalwareType { get; set; }
        public int? RiskScore { get; set; }
        public DateTime? DateCreated { get; set; }
        public DateTime? DateFirstSeen { get; set; }
        public DateTime? DateLastSeen { get; set; }
        public bool? Removed { get; set; }
        public int? ModifiedCount { get; set; }
        public int? Queue { get; set; }

        public ThreatEntry()
        { }
    }

    public class Web
    {
        public static string ApiCall(string requestUrl)
        {
            string result = "";

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            using (WebClient httpObject = new WebClient())
            {
                result = httpObject.DownloadString(requestUrl);
            }
            return result;
        }
    }
}
