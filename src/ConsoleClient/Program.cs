using ConsoleClient;
using Microsoft.Extensions.Configuration;

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
        csrBase64 = @"
MIIEDDCCAvQCAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANPk
/lAOEvYikbMJvabzapKyJkqLnaXWm2FvnO6UNCtXWf9WchbbumLqkIas9BUcMiSE
Eh4tVZNFugi3bahnjUjTG9MIvAZd3/C0YfuLX8yl9mcIVWZhyYZVwUeMh4GYS5ht
90NFZP0vXb7c0brSRyvhvWzq+kG7om24qMTZBgSIRsajcDVY+uGLdhixy4AtXNw5
pzzRdS/1QBF1wsDT3C0bceWy2uej2hsLYolyGdd0fHk1y/tOusoyjc3itw2o3P9j
k+bP4eDG2ukRjMMcjqxQ50OBze7hXQf2hrNEJRTd6pPIOdAub8Hz/DiPYaEY75XN
EQepc11nLmq2GQ9YghcCAwEAAaCCAcUwGgYKKwYBBAGCNw0CAzEMFgo2LjEuNzA1
My4yMGQGCSsGAQQBgjcVFDFXMFUCAQUMLzktMTM1MUMwNDA1QS5kOS0xMzUxQzA0
MDZBLm50dGVzdC5taWNyb3NvZnQuY29tDBJEOS0xMzUxQzA0MDZBXGFiYnkMC0Nl
c1Rlc3QuZXhlMHQGCisGAQQBgjcNAgIxZjBkAgEBHlwATQBpAGMAcgBvAHMAbwBm
AHQAIABFAG4AaABhAG4AYwBlAGQAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBj
ACAAUAByAG8AdgBpAGQAZQByACAAdgAxAC4AMAMBADCBygYJKoZIhvcNAQkOMYG8
MIG5MBcGCSsGAQQBgjcUAgQKHggAVQBzAGUAcjApBgNVHSUEIjAgBgorBgEEAYI3
CgMEBggrBgEFBQcDBAYIKwYBBQUHAwIwDgYDVR0PAQH/BAQDAgWgMEQGCSqGSIb3
DQEJDwQ3MDUwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAHBgUrDgMC
BzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUavblZB2QWG6vt+ag4T4jZMPFe3owDQYJ
KoZIhvcNAQEFBQADggEBAGId8Dv9gvCVNgnSHkNuTiErtwIacv609MnMt2WxhnAj
zGQZZS4bZ9JNH+CR49yswieFCS3zFiP5PxGL5CCogn2XHGs7LCCzHtrltAZBACTC
tzLF5Qcj0Ki/H5GRa4Q+Ze1UrcM1cSnD52zY+V1vFXXlXc2P5hTB0bq8GbZME/MW
84XE1sz75NqZeQ2vhO66ozAMywMtC26Q+7DOfBaPMxXrWgMQBm6qO/Yjj3vDY/U8
T9rpJqGHHTG7E7E+/3EcgPeKNExxf0n+VXRwLO9C5wOS6Xy/JNGfuipw+SzaRbPs
H5/6UiS+uqtSVzaJmAOa9vzxJQfgARCucr49wM3YUek=";

        var client = new CesEnrollmentClient(uri, username, password);
        var cert = await client.GetCertificateAsync(csrBase64, templateName);
        File.WriteAllBytes(outputPath, cert);

        Console.WriteLine($"Certificate saved to {outputPath}");
    }
}
