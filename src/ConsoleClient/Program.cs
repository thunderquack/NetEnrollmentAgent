using System.Security.Cryptography.X509Certificates;

X509Certificate2 agentCertificate = new X509Certificate2("AgentCertificate.pfx", "12345678");

Console.WriteLine(agentCertificate.Subject);