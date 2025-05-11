using ConsoleClient;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

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

        var csrBytes = new byte[] { 0x00, 0x01, 0x02 }; // File.ReadAllBytes(csrPath);
        var csrBase64 = Convert.ToBase64String(csrBytes);
        csrBase64 = GenerateCsrBase64("TestCommonName");

        var client = new CesEnrollmentClient(uri, username, password);
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
}
