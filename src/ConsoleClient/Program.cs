using ConsoleClient;
using Microsoft.Extensions.Configuration;
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

        // string csrBase64 = GenerateCsrBase64("TestCommonName");

        var client = new CesEnrollmentClient(uri, new X509Certificate2("ClientAuthentication.pfx", "12345678"));

        var agentCertificate = new X509Certificate2("AgentCertificate.pfx", "12345678");
        //byte[] cmcRequest = GenerateSimpleRequest();

        var simpleRequest = GenerateSimpleRequest();

        var cmc = CreateCsrPortable("CN=TestServer");
        var pkcs7 = SignCsrAsPkcs7(cmc, agentCertificate);
        var cmcBase64 = Convert.ToBase64String(pkcs7);


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

    /// <summary>
    /// Создает простой запрос на сертификат (CSR) с указанным субъектом, используя Portable Bouncy Castle.
    /// </summary>
    /// <param name="subjectName">Имя субъекта сертификата (например, "CN=TestSubject").</param>
    /// <returns>Запрос на сертификат в формате PKCS#10.</returns>
    public static Pkcs10CertificationRequest CreateCsrPortable(string subjectName)
    {
        // Создаем пару ключей RSA
        var keyPairGenerator = GeneratorUtilities.GetKeyPairGenerator("RSA");
        keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
        var publicKey = keyPair.Public;
        var privateKey = keyPair.Private;

        // Создаем имя субъекта
        var subjectDn = new X509Name(subjectName);

        // Создаем запрос на сертификат
        var request = new Pkcs10CertificationRequest(
            "SHA256withRSA",
            subjectDn,
            publicKey,
            null, // Атрибуты запроса (могут быть null для простого запроса)
            privateKey
        );

        return request;
    }

    /// <summary>
    /// Подписывает запрос на сертификат (CSR) сертификатом Enrollment Agent и формирует PKCS#7 Signed Data.
    /// </summary>
    /// <param name="csr">Запрос на сертификат (CSR) для подписи.</param>
    /// <param name="signingCertificate">Сертификат Enrollment Agent для подписи.</param>
    /// <returns>PKCS#7 Signed Data в виде массива байт.</returns>
    public static byte[] SignCsrAsPkcs7(Pkcs10CertificationRequest csr, X509Certificate2 signingCertificate)
    {
        if (csr == null) throw new ArgumentNullException(nameof(csr));
        if (signingCertificate == null) throw new ArgumentNullException(nameof(signingCertificate));
        if (!signingCertificate.HasPrivateKey) throw new ArgumentException("Сертификат Enrollment Agent не имеет приватного ключа.", nameof(signingCertificate));

        try
        {
            var generator = new CmsSignedDataGenerator();
            var bouncyCastleCert = new Org.BouncyCastle.X509.X509Certificate(signingCertificate.GetRawCertData());

            AsymmetricKeyParameter privateKeyParam = DotNetUtilities.GetKeyPair(signingCertificate.GetRSAPrivateKey()).Private;

            var signerInfoGenerator = new SignerInfoGeneratorBuilder()
                .Build(new Asn1SignatureFactory("SHA256withRSA", privateKeyParam), bouncyCastleCert);

            generator.AddSignerInfoGenerator(signerInfoGenerator);
            //generator.AddCertificates(bouncyCastleCert);

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