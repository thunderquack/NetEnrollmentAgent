using ConsoleClient;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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

        var client = new CesEnrollmentClient(uri, new X509Certificate2("ClientAuthentication.pfx", "12345678"));

        var agentCertificate = new X509Certificate2("AgentCertificate.pfx", "12345678", X509KeyStorageFlags.Exportable);

        var simpleRequest = GenerateSimpleRequest();

        var cmc = CreateCsrPortable("CN=TestServer");
        var pkcs7 = SignCsrAsPkcs7(cmc, agentCertificate);
        var cmcBase64 = Convert.ToBase64String(pkcs7);

        Asn1InputStream asn1InputStream = new Asn1InputStream(pkcs7);
        while (asn1InputStream.ReadObject() is Asn1Sequence sequence)
        {
            foreach (Asn1Encodable item in sequence)
            {
                // Console.WriteLine(item.ToString());
            }
        }

        var cert = await client.GetCertificateAsync(cmcBase64, templateName);
        File.WriteAllBytes(outputPath, cert);

        Console.WriteLine($"Certificate saved to {outputPath}");
    }

    public static byte[] GenerateSimpleRequest()
    {
        using RSA rsa = RSA.Create(2048);

        var req = new CertificateRequest("CN=TestSubject", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Add standard extensions
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection {
                new Oid("1.3.6.1.5.5.7.3.1"),
                new Oid("1.3.6.1.5.5.7.3.2")
            }, false));

        byte[] pkcs10 = req.CreateSigningRequest();
        return pkcs10;
    }

    public static Pkcs10CertificationRequest CreateCsrPortable(string subjectName)
    {
        var keyPairGenerator = GeneratorUtilities.GetKeyPairGenerator("RSA");
        keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
        var publicKey = keyPair.Public;
        var privateKey = keyPair.Private;

        var subjectDn = new X509Name(subjectName);

        var request = new Pkcs10CertificationRequest(
            "SHA256withRSA",
            subjectDn,
            publicKey,
            null,
            privateKey
        );

        return request;
    }

    public static byte[] SignCsrAsPkcs7(Pkcs10CertificationRequest csr, X509Certificate2 signingCertificate)
    {
        if (csr == null) throw new ArgumentNullException(nameof(csr));
        if (signingCertificate == null) throw new ArgumentNullException(nameof(signingCertificate));
        if (!signingCertificate.HasPrivateKey) throw new ArgumentException("Сертификат Enrollment Agent не имеет приватного ключа.", nameof(signingCertificate));

        try
        {
            var generator = new CmsSignedDataGenerator();
            var bouncyCastleCert = new Org.BouncyCastle.X509.X509Certificate(signingCertificate.GetRawCertData());

            RSA rsa = signingCertificate.GetRSAPrivateKey();
            RSAParameters rsaParams = rsa.ExportParameters(true);
            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(rsaParams);

            var templateOid = new DerObjectIdentifier("1.3.6.1.4.1.311.21.7");
            var templateValue = new DerSequence(
                new DerObjectIdentifier("1.3.6.1.4.1.311.21.8.661424.4972531.1133714.6327609.4286482.11.12499863.8032338"),
                new DerInteger(100),
                new DerInteger(3));

            var extensionRequestSequence = new DerSequence(
                new DerSequence(
                    new DerObjectIdentifier("1.3.6.1.4.1.311.21.7"),
                    new DerOctetString(templateValue)
                ) as Asn1Encodable
            ) as Asn1Encodable;

            IDictionary<DerObjectIdentifier, object> dict = new Dictionary<DerObjectIdentifier, object>
            {
                {
                    PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                    new Org.BouncyCastle.Asn1.Cms.Attribute(
                        PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                        new DerSet(extensionRequestSequence)
                    )
                }
            };

            var attrSet = new Org.BouncyCastle.Asn1.Cms.AttributeTable(dict);

            var signedAttrGenerator = new DefaultSignedAttributeTableGenerator(attrSet);

            var signerInfoGenerator = new SignerInfoGeneratorBuilder()
                .WithSignedAttributeGenerator(signedAttrGenerator)
                .Build(new Asn1SignatureFactory("SHA256withRSA", keyPair.Private), bouncyCastleCert);

            generator.AddSignerInfoGenerator(signerInfoGenerator);

            //IX509Store certStore = X509StoreFactory.Create("CERTIFICATE/COLLECTION", new X509CollectionStoreParameters(new[] { bouncyCastleCert }));
            var certStore = Org.BouncyCastle.Utilities.Collections.CollectionUtilities.CreateStore([bouncyCastleCert]);
            generator.AddCertificates(certStore);

            var contentInfo = new CmsProcessableByteArray(csr.GetEncoded());
            var signedData = generator.Generate(contentInfo, true);

            return signedData.GetEncoded();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка при создании PKCS#7 подписи: {ex.Message}");
            return null;
        }
    }
}