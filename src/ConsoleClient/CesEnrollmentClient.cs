using System;
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
            string messageId = "urn:uuid:" + Guid.NewGuid().ToString();

            var soapEnvelope = $@"""<?xml version=""1.0"" encoding=""utf-8""?>
<s:Envelope xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" 
            xmlns:a=""http://www.w3.org/2005/08/addressing"" 
            xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">
  <s:Header>
    <a:Action s:mustUnderstand=""1"">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
    <a:MessageID>{messageId}</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand=""1"">{uri}</a:To>
    <o:Security s:mustUnderstand=""1"" xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
      <o:UsernameToken>
        <o:Username>{SecurityElement.Escape(username)}</o:Username>
        <o:Password>{SecurityElement.Escape(password)}</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <RequestSecurityToken xmlns=""http://docs.oasis-open.org/ws-sx/ws-trust/200512"">
      <TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</TokenType>
      <RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</RequestType>
      <BinarySecurityToken 
        EncodingType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"" 
        ValueType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS10"" 
        xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
        {csrBase64}
      </BinarySecurityToken>
      <AdditionalContext xmlns=""http://schemas.microsoft.com/windows/pki/2009/01/enrollment"">
        <ContextItem>
          <ContextKey>CertificateTemplate</ContextKey>
          <ContextValue>{templateName}</ContextValue>
        </ContextItem>
      </AdditionalContext>
      <RequestID xmlns=""http://schemas.microsoft.com/windows/pki/2009/01/enrollment"" xsi:nil=""true""/>
    </RequestSecurityToken>
  </s:Body>
</s:Envelope>""";

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