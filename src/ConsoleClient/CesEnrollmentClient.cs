using System.Security;
using System.Text;
using System.Xml.Linq;

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
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
            });
#else
            httpClient = new HttpClient();
#endif
        }

        public async Task<byte[]> GetCertificateAsync(string csrBase64, string templateName)
        {
            var soapEnvelope = $@"<?xml version=""1.0"" encoding=""utf-8""?>
<s:Envelope xmlns:s=""http://www.w3.org/2003/05/soap-envelope""
            xmlns:a=""http://www.w3.org/2005/08/addressing""
            xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">
  <s:Header>
    <a:Action s:mustUnderstand=""1"">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/ISecurityTokenService/Submit</a:Action>
    <a:To s:mustUnderstand=""1"">{uri}</a:To>
    <o:Security s:mustUnderstand=""1"" xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
      <o:UsernameToken>
        <o:Username>{SecurityElement.Escape(username)}</o:Username>
        <o:Password>{SecurityElement.Escape(password)}</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <Submit xmlns=""http://schemas.microsoft.com/windows/pki/2009/01/enrollment"">
      <request>
        <CertificateRequest>{csrBase64}</CertificateRequest>
        <RequestType>PKCS10</RequestType>
        <CertificateTemplateName>{templateName}</CertificateTemplateName>
      </request>
    </Submit>
  </s:Body>
</s:Envelope>";

            var content = new StringContent(soapEnvelope, Encoding.UTF8, "application/soap+xml");
            var response = await httpClient.PostAsync(uri, content);
            var resultXml = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException($"Server returned {response.StatusCode}: {resultXml}");
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