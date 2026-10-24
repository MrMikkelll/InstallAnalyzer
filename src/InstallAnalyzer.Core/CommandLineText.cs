using System.Text;

namespace InstallAnalyzer.Core;

public static class CommandLineText
{
    public static string WindowsCombine(string directory, string file)
    {
        var dir = directory.TrimEnd('\\', '/');
        return dir + "\\" + file.TrimStart('\\', '/');
    }

    public static string Quote(string value)
    {
        var builder = new StringBuilder(value.Length + 2);
        builder.Append('"');
        foreach (var ch in value)
        {
            if (ch == '"')
                builder.Append('\\');
            builder.Append(ch);
        }
        builder.Append('"');
        return builder.ToString();
    }

    public static string? FormatProductCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
            return null;

        var trimmed = code.Trim();
        if (Guid.TryParse(trimmed, out var guid))
            return guid.ToString("B").ToUpperInvariant();

        return trimmed;
    }
}
