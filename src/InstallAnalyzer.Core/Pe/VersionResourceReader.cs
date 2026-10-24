using System.Text;

namespace InstallAnalyzer.Core.Pe;

public sealed class VersionStrings
{
    public string? FileVersion { get; init; }
    public string? ProductName { get; init; }
    public string? ProductVersion { get; init; }
    public string? CompanyName { get; init; }
    public string? FileDescription { get; init; }
    public string? OriginalFilename { get; init; }

    public static VersionStrings FromMap(IReadOnlyDictionary<string, string> map)
    {
        string? Get(string key) => map.TryGetValue(key, out var value) ? value : null;
        return new VersionStrings
        {
            FileVersion = Get("FileVersion"),
            ProductName = Get("ProductName"),
            ProductVersion = Get("ProductVersion"),
            CompanyName = Get("CompanyName"),
            FileDescription = Get("FileDescription"),
            OriginalFilename = Get("OriginalFilename")
        };
    }
}

public static class VersionResourceReader
{
    private static readonly HashSet<string> Containers = new(StringComparer.OrdinalIgnoreCase)
    {
        "VS_VERSION_INFO",
        "StringFileInfo",
        "VarFileInfo",
        "Var"
    };

    public static Dictionary<string, string> Read(ReadOnlySpan<byte> data)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        Walk(data, 0, map);
        return map;
    }

    private static void Walk(ReadOnlySpan<byte> data, int offset, Dictionary<string, string> map)
    {
        if ((uint)offset + 6 > (uint)data.Length)
            return;

        var length = BitConverter.ToUInt16(data[offset..]);
        var valueLength = BitConverter.ToUInt16(data[(offset + 2)..]);
        var type = BitConverter.ToUInt16(data[(offset + 4)..]);
        if (length < 6)
            return;

        var end = Math.Min(data.Length, offset + length);
        var keyEnd = offset + 6;
        while (keyEnd + 1 < end)
        {
            if (data[keyEnd] == 0 && data[keyEnd + 1] == 0)
                break;
            keyEnd += 2;
        }

        if (keyEnd + 1 >= end)
            return;

        var key = Encoding.Unicode.GetString(data[(offset + 6)..keyEnd]);
        var cursor = Align(keyEnd + 2);
        var valueBytes = type == 1 ? valueLength * 2 : valueLength;
        if (valueBytes < 0)
            return;

        var valueEnd = Math.Min(end, cursor + valueBytes);
        if (!IsContainer(key) && type == 1 && valueLength > 0 && cursor < valueEnd)
        {
            var text = Encoding.Unicode.GetString(data[cursor..valueEnd]).TrimEnd('\0').Trim();
            if (text.Length > 0 && !map.ContainsKey(key))
                map[key] = text;
        }

        var child = Align(cursor + Math.Max(valueBytes, 0));
        while (child + 6 <= end)
        {
            var childLength = BitConverter.ToUInt16(data[child..]);
            if (childLength < 6)
                break;
            Walk(data, child, map);
            var next = Align(child + childLength);
            if (next <= child)
                break;
            child = next;
        }
    }

    private static bool IsContainer(string key)
    {
        if (Containers.Contains(key))
            return true;
        if (key.Length != 8)
            return false;
        foreach (var ch in key)
        {
            var hex = ch is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
            if (!hex)
                return false;
        }
        return true;
    }

    private static int Align(int value) => (value + 3) & ~3;
}
