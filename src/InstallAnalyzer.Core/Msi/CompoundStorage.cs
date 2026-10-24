namespace InstallAnalyzer.Core.Msi;

public static class CompoundStorage
{
    public static readonly Guid MsiClsid = new("000C1084-0000-0000-C000-000000000046");
    public static readonly Guid MspClsid = new("000C1086-0000-0000-C000-000000000046");

    public static bool LooksLikeOle(ReadOnlySpan<byte> header)
    {
        ReadOnlySpan<byte> magic = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        if (header.Length < 0x20 || !header.StartsWith(magic))
            return false;
        if (header[0x1C] != 0xFE || header[0x1D] != 0xFF)
            return false;
        var shift = BitConverter.ToUInt16(header[0x1E..]);
        return shift is 9 or 12;
    }

    public static bool TryGetClsid(string path, out Guid clsid)
    {
        clsid = Guid.Empty;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var header = new byte[512];
            if (stream.Read(header) < 0x4C || !LooksLikeOle(header))
                return false;

            var shift = BitConverter.ToUInt16(header, 0x1E);
            if (shift is not (9 or 12))
                return false;
            var sectorSize = 1 << shift;
            var directorySector = BitConverter.ToUInt32(header, 0x30);
            if (directorySector >= 0xFFFFFFFA)
                return false;

            var offset = (long)(directorySector + 1) * sectorSize;
            if (offset < 0 || offset + 128 > stream.Length)
                return false;

            var entry = new byte[128];
            stream.Position = offset;
            if (stream.Read(entry) < entry.Length || entry[66] != 5)
                return false;

            clsid = new Guid(entry.AsSpan(80, 16));
            return clsid != Guid.Empty;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }
}
