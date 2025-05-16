using System.Net.Http.Headers;
using System.Text;
using System.Xml.Linq;
using System.Security.Cryptography.X509Certificates;

namespace ConsoleClient
{
    public class CesEnrollmentClient
    {
        private readonly string uri;
        private readonly string username;
        private readonly string password;
        private readonly HttpClient httpClient;

        public CesEnrollmentClient(string uri, string username, string password)
        {
            this.uri = uri ?? throw new ArgumentNullException(nameof(uri));
            this.username = username ?? throw new ArgumentNullException(nameof(username));
            this.password = password ?? throw new ArgumentNullException(nameof(password));
#if DEBUG
            httpClient = new HttpClient(new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true,
            });
#else
            httpClient = new HttpClient();
#endif
            var byteArray = Encoding.ASCII.GetBytes($"{username}:{password}");
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));
        }

        public CesEnrollmentClient(string uri, X509Certificate2 authCertificate)
        {
            this.uri = uri ?? throw new ArgumentNullException(nameof(uri));
#if DEBUG
            httpClient = new HttpClient(new HttpClientHandler
            {
                ClientCertificates = { authCertificate },
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true,
            });
#else
            httpClient = new HttpClient(new HttpClientHandler
            {
                ClientCertificates = { authCertificate },
            });
#endif
        }

        public async Task<byte[]> GetCertificateAsync(string csrBase64, string templateName)
        {
            string messageId = "urn:uuid:" + Guid.NewGuid().ToString();

            var soapEnvelope = $@"<?xml version=""1.0"" encoding=""utf-8""?>
<s:Envelope xmlns:a=""http://www.w3.org/2005/08/addressing"" xmlns:s=""http://www.w3.org/2003/05/soap-envelope"">
	<s:Header>
		<a:Action s:mustUnderstand=""1"">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
		<a:MessageID>{messageId}</a:MessageID>
		<a:To s:mustUnderstand=""1"">{uri}</a:To>
	</s:Header>
	<s:Body>
		<RequestSecurityToken PreferredLanguage=""en-GB"" xmlns=""http://docs.oasis-open.org/ws-sx/ws-trust/200512"">
			<TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</TokenType>
			<RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</RequestType>
			<BinarySecurityToken ValueType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7"" EncodingType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"" a:Id="""" xmlns:a=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" 
             xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">{csrBase64}</BinarySecurityToken>
		</RequestSecurityToken>
	</s:Body>
</s:Envelope>
";

            var content = new StringContent(soapEnvelope, Encoding.UTF8, "application/soap+xml");            
            var response = await httpClient.PostAsync(uri, content);
            var resultXml = await response.Content.ReadAsStringAsync();
            Console.WriteLine("Request to: " + uri);
            Console.WriteLine("Request: " + soapEnvelope);
            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine("Result: " + resultXml);
                Environment.Exit(1);
            }

            var doc = XDocument.Parse(resultXml);
            var certBase64 = doc
                .Descendants()
                .Where(e => e.Name.LocalName == "RequestedSecurityToken")
                .Descendants()
                .Where(e => e.Name.LocalName == "BinarySecurityToken")
                .Select(e => e.Value)
                .FirstOrDefault();

            if (string.IsNullOrEmpty(certBase64))
            {
                Console.WriteLine("Certificate not found in response.");
                Environment.Exit(1);
            }

            return Convert.FromBase64String(certBase64);
        }
    }
}