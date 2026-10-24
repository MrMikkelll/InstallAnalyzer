using InstallAnalyzer.Core.Pe;

namespace InstallAnalyzer.Core.Unpack;

public sealed class BurnContainerSlice
{
    public required int Index { get; init; }
    public required string Role { get; init; }
    public required long Offset { get; init; }
    public required long Size { get; init; }
}

public static class BurnLayout
{
    public const uint Magic = 0x00f14300;
    public const uint Version = 2;
    public const string SectionName = ".wixburn";

    public static bool TryRead(
        PeFile pe,
        out Guid bundleId,
        out IReadOnlyList<BurnContainerSlice> containers)
    {
        bundleId = Guid.Empty;
        containers = [];
        var section = pe.ReadSection(SectionName);
        if (section is null || section.Length < 48 + 4)
            return false;
        if (BitConverter.ToUInt32(section, 0) != Magic || BitConverter.ToUInt32(section, 4) != Version)
            return false;

        bundleId = new Guid(section.AsSpan(8, 16));
        var stubSize = BitConverter.ToUInt32(section, 24);
        var originalSignatureOffset = BitConverter.ToUInt32(section, 32);
        var originalSignatureSize = BitConverter.ToUInt32(section, 36);
        var count = BitConverter.ToUInt32(section, 44);
        if (count == 0 || count > 8)
            return false;
        if (section.Length < 48 + (count * 4))
            return false;

        var sizes = new uint[count];
        for (var i = 0; i < count; i++)
            sizes[i] = BitConverter.ToUInt32(section, 48 + (i * 4));

        long engineSize;
        if (originalSignatureOffset != 0)
            engineSize = (long)originalSignatureOffset + originalSignatureSize;
        else if (pe.CertificateOffset != 0)
            engineSize = (long)pe.CertificateOffset + pe.CertificateSize;
        else
            engineSize = (long)stubSize + sizes[0];

        var slices = new List<BurnContainerSlice>();
        if (sizes[0] > 0 && stubSize + (long)sizes[0] <= pe.Length)
        {
            slices.Add(new BurnContainerSlice
            {
                Index = 0,
                Role = "UX",
                Offset = stubSize,
                Size = sizes[0]
            });
        }

        var offset = engineSize;
        for (var i = 1; i < sizes.Length; i++)
        {
            var size = sizes[i];
            if (size > 0 && offset >= 0 && offset + size <= pe.Length)
            {
                slices.Add(new BurnContainerSlice
                {
                    Index = i,
                    Role = "Attached",
                    Offset = offset,
                    Size = size
                });
            }

            offset += size;
        }

        containers = slices;
        return true;
    }
}
