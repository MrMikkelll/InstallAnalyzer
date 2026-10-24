using System.Xml.Linq;

namespace InstallAnalyzer.Core.Unpack;

public static class BurnManifestReader
{
    public static IReadOnlyList<ChainedPackage> Read(string path)
    {
        try
        {
            var document = XDocument.Load(path);
            var packages = new List<ChainedPackage>();
            foreach (var element in document.Descendants())
            {
                var name = element.Name.LocalName;
                if (name is not ("MsiPackage" or "MspPackage" or "ExePackage"))
                    continue;

                packages.Add(new ChainedPackage
                {
                    Name = Attribute(element, "DisplayName")
                        ?? Attribute(element, "Id")
                        ?? Attribute(element, "SourceFile"),
                    ProductCode = CommandLineText.FormatProductCode(Attribute(element, "ProductCode")),
                    Source = Attribute(element, "SourceFile") ?? Attribute(element, "CacheId")
                });
                if (packages.Count >= 32)
                    break;
            }

            return packages;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Xml.XmlException)
        {
            return [];
        }
    }

    private static string? Attribute(XElement element, string name) =>
        element.Attributes().FirstOrDefault(attribute =>
            attribute.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;
}
