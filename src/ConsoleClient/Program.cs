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

        string csrBase64 = GenerateCsrBase64("TestCommonName");

        var client = new CesEnrollmentClient(uri, new X509Certificate2("ClientAuthentication.pfx", "12345678"));

        var agentCertificate = new X509Certificate2("AgentCertificate.pfx", "12345678");
        //csrBase64 = Convert.ToBase64String(CreateCmcRequest(csrBase64, agentCertificate));
        //csrBase64 = SignByAgent(csrBase64, templateName, agentCertificate);

        byte[] cmcBytes = GenerateCmcRequest(
            subjectName: "TestCommonName",
            templateName: "Web Server via Enrollment Agent",
            majorVersion: 100,
            minorVersion: 3,
            agentCertificate: agentCertificate
        );
        string cmcBase64 = Convert.ToBase64String(cmcBytes);

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
        //signer.SignedAttributes.Add(new Pkcs9AttributeObject(new Oid("1.3.6.1.4.1.311.20.2"), templateOidBytes));
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

    public static byte[] CreateCmcRequest(string pkcs10CsrBase64, X509Certificate2 agentCert)
    {
        byte[] pkcs10Raw = Convert.FromBase64String(pkcs10CsrBase64);
        byte[] extensionBlock = BuildCertificateExtensionsWithTemplate("WebServerViaEnrollmentAgent", major: 100, minor: 3);
        var certRequestAttribute = new Pkcs9AttributeObject(new Oid("1.2.840.113549.1.9.14"), extensionBlock);

        var contentInfo = new ContentInfo(new Oid("1.3.6.1.5.5.7.12.2"), pkcs10Raw); // CMC request content type

        var signer = new CmsSigner(SubjectIdentifierType.SubjectKeyIdentifier, agentCert)
        {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1") // sha256
        };
        signer.SignedAttributes.Add(certRequestAttribute);

        var signedCms = new SignedCms(contentInfo, detached: false);
        signedCms.ComputeSignature(signer);

        return signedCms.Encode();
    }

    private static byte[] BuildCertificateExtensionsWithTemplate(string templateName, int major, int minor)
    {
        var extWriter = new AsnWriter(AsnEncodingRules.DER);
        extWriter.PushSequence();
        extWriter.WriteObjectIdentifier("1.3.6.1.4.1.311.21.8.661424.4972531.1133714.6327609.4286482.11.12499863.8032338");
        extWriter.WriteInteger(100);
        extWriter.WriteInteger(3);
        extWriter.PopSequence();

        return extWriter.Encode();
    }

    public static byte[] GenerateCmcRequest(string subjectName, string templateName, int majorVersion, int minorVersion, X509Certificate2 agentCertificate)
    {
        using RSA rsa = RSA.Create(2048);

        var request = new CertificateRequest($"CN={subjectName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection {
                new Oid("1.3.6.1.5.5.7.3.1"), // Server Authentication
                new Oid("1.3.6.1.5.5.7.3.2")  // Client Authentication
            }, false));

        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        byte[] csr = request.CreateSigningRequest();

        // === extensions ===
        byte[] extensionsBlock = BuildCertificateExtensionsWithTemplate(templateName, majorVersion, minorVersion);

        // === extensions as CMC attribute ===
        var attrExtensions = new Pkcs9AttributeObject("1.2.840.113549.1.9.14", extensionsBlock);

        // === PKCS#10 in CMC SignedData ===
        //ContentInfo contentInfo = new ContentInfo(new Oid("1.3.6.1.5.5.7.12.2"), csr);

        var taggedCsr = WrapAsCmcTaggedRequest(csr, 1);
        ContentInfo contentInfo = new ContentInfo(new Oid("1.3.6.1.5.5.7.12.2"), taggedCsr);

        SignedCms signedCms = new SignedCms(contentInfo, detached: false);

        CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, agentCertificate)
        {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1") // sha256
        };

        signer.SignedAttributes.Add(attrExtensions);
        signedCms.ComputeSignature(signer);

        return signedCms.Encode();
    }

    private static byte[] WrapAsCmcTaggedRequest(byte[] pkcs10, int bodyPartId)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence(); // top SEQUENCE
        writer.WriteInteger(bodyPartId); // BodyPartID = 1

        // TaggedRequest ::= CHOICE { tcr [0] CertificationRequest }
        var inner = new AsnWriter(AsnEncodingRules.DER);
        inner.WriteEncodedValue(pkcs10);

        var tagged = new AsnWriter(AsnEncodingRules.DER);
        tagged.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        tagged.WriteEncodedValue(inner.Encode());
        tagged.PopSequence();

        writer.WriteEncodedValue(tagged.Encode());
        writer.PopSequence();
        return writer.Encode();
    }
}
