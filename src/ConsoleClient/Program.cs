using ConsoleClient;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Formats.Asn1;
using System.Security.Cryptography.Pkcs;
using System.Runtime.ConstrainedExecution;

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

        // string csrBase64 = GenerateCsrBase64("TestCommonName");

        var client = new CesEnrollmentClient(uri, new X509Certificate2("ClientAuthentication.pfx", "12345678"));

        var agentCertificate = new X509Certificate2("AgentCertificate.pfx", "12345678");
        //csrBase64 = Convert.ToBase64String(CreateCmcRequest(csrBase64, agentCertificate));
        //csrBase64 = SignByAgent(csrBase64, templateName, agentCertificate);

        byte[] cmcRequest = GenerateCmcRequest("CN=TempSubject", templateName, 100, 3, agentCertificate);

        string cmcBase64 = Convert.ToBase64String(cmcRequest);

        var cert = await client.GetCertificateAsync(cmcBase64, templateName);
        File.WriteAllBytes(outputPath, cert);

        Console.WriteLine($"Certificate saved to {outputPath}");
    }

    public static string GenerateCsrBase64(string commonName)
    {
        using RSA rsa = RSA.Create(4096);
        var req = new CertificateRequest($"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);


        var extWriter = new AsnWriter(AsnEncodingRules.DER);
        extWriter.PushSequence();
        extWriter.WriteObjectIdentifier("1.3.6.1.4.1.311.21.8.661424.4972531.1133714.6327609.4286482.11.12499863.8032338");
        extWriter.WriteInteger(100);
        extWriter.WriteInteger(3);
        extWriter.PopSequence();

        req.OtherRequestAttributes.Add(new Pkcs9AttributeObject(new Oid("1.3.6.1.4.1.311.21.7"), extWriter.Encode()));
        
        var csr = req.CreateSigningRequest();
        return Convert.ToBase64String(csr);
    }

    public static byte[] GenerateCmcRequest(string subjectName, string templateName, int major, int minor, X509Certificate2 agentCertificate)
    {
        using RSA rsa = RSA.Create(2048);

        var req = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Add standard extensions
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection {
                new Oid("1.3.6.1.5.5.7.3.1"),
                new Oid("1.3.6.1.5.5.7.3.2")
            }, false));

        byte[] pkcs10 = req.CreateSigningRequest();
        byte[] tagged = WrapAsCmcTaggedRequest(pkcs10, 1);

        var contentInfo = new ContentInfo(new Oid("1.3.6.1.5.5.7.12.2"), tagged);
        var signedCms = new SignedCms(contentInfo, detached: false);

        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, agentCertificate)
        {
            //DigestAlgorithm = new Oid("1.3.6.1.4.1.311.2.1.4") // ecdsa-with-SHA512
        };

        signedCms.ComputeSignature(signer);
        return signedCms.Encode();
    }

    private static byte[] WrapAsCmcTaggedRequest(byte[] pkcs10, int bodyPartId)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteInteger(bodyPartId);

        var tag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
        writer.PushSequence(tag);
        writer.WriteEncodedValue(pkcs10);
        writer.PopSequence(tag);

        writer.PopSequence();
        return writer.Encode();
    }
}