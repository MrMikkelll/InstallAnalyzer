using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace InstallAnalyzer.Windows;

[SupportedOSPlatform("windows")]
public static class AuthenticodeInspector
{
    public static string? GetSigner(string path)
    {
        if (!OperatingSystem.IsWindows())
            return null;
        try
        {
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            var name = certificate.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrWhiteSpace(name) ? null : name;
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
