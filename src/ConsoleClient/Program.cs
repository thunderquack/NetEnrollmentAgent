using ConsoleClient;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Formats.Asn1;
using System.Security.Cryptography.Pkcs;

class Program
{
    static async Task Main()
    {
        var config = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false)
            .AddJsonFile("appsettings.development.json", optional: true)
            .Build();

        var section = config.GetSection("CesEnrollment");
        string uri = section["Uri"];
        string username = section["Username"];
        string password = section["Password"];
        string templateName = section["TemplateName"];
        string csrPath = section["CsrPath"];
        string outputPath = section["OutputPath"];

        string csrBase64 = GenerateCsrBase64("TestCommonName");

        var client = new CesEnrollmentClient(uri, new X509Certificate2("ClientAuthentication.pfx", "12345678"));

        var agentCertificate = new X509Certificate2("AgentCertificate.pfx", "12345678");
        csrBase64 = SignByAgent(csrBase64, templateName, agentCertificate);

        var cert = await client.GetCertificateAsync(csrBase64, templateName);
        File.WriteAllBytes(outputPath, cert);

        Console.WriteLine($"Certificate saved to {outputPath}");
    }

    public static string GenerateCsrBase64(string commonName)
    {
        using RSA rsa = RSA.Create(4096);
        var req = new CertificateRequest($"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var csr = req.CreateSigningRequest();
        return Convert.ToBase64String(csr);
    }

    public static string SignByAgent(string csr, string templateName, X509Certificate2 agentCertificate)
    {
        byte[] csrBytes = Convert.FromBase64String(csr);
        ContentInfo contentInfo = new ContentInfo(csrBytes);
        SignedCms signedCms = new SignedCms(contentInfo, detached: false);
        CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, agentCertificate)
        {
            IncludeOption = X509IncludeOption.EndCertOnly
        };
        byte[] templateOidBytes = CreateCertificateTemplateAttribute(templateName);
        signer.SignedAttributes.Add(new Pkcs9AttributeObject(new Oid("1.3.6.1.4.1.311.20.2"), templateOidBytes));
        signedCms.ComputeSignature(signer);
        byte[] pkcs7Bytes = signedCms.Encode();
        string pkcs7Base64 = Convert.ToBase64String(pkcs7Bytes);
        return pkcs7Base64;
    }

    public static byte[] CreateCertificateTemplateAttribute(string templateName)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, templateName);
        return writer.Encode();        
    }
}
