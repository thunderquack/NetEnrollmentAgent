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
<ns0:Envelope
xmlns:ns0=""http://www.w3.org/2003/05/soap-envelope""
xmlns:ns1=""http://www.w3.org/2005/08/addressing""
xmlns:ns3=""http://docs.oasis-open.org/ws-sx/ws-trust/200512""
xmlns:ns4=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""
xmlns:ns5=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd""
xmlns:ns6=""http://schemas.xmlsoap.org/ws/2006/12/authorization""
xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"">
	<ns0:Header>
		<ns1:Action ns0:mustUnderstand=""1"">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</ns1:Action>
		<ns1:MessageID>{messageId}</ns1:MessageID>
		<ns1:To ns0:mustUnderstand=""1"">{uri}</ns1:To>
	</ns0:Header>
	<ns0:Body>
		<ns3:RequestSecurityToken>
			<ns3:TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</ns3:TokenType>
			<ns3:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</ns3:RequestType>
			<ns4:BinarySecurityToken ValueType=""http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"" EncodingType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"" ns5:Id="""">{csrBase64}</ns4:BinarySecurityToken>
            <ns6:AdditionalContext/>
		</ns3:RequestSecurityToken>
	</ns0:Body>
</ns0:Envelope>
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
            XNamespace ns = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
            var certBase64 = doc.Root?.Descendants(ns + "Certificate")?.FirstOrDefault()?.Value;

            if (string.IsNullOrEmpty(certBase64))
            {
                throw new InvalidOperationException("Certificate not found in response.");
            }

            return Convert.FromBase64String(certBase64);
        }
    }
}