using System.Text;
using System.Text.RegularExpressions;

namespace InstallAnalyzer.Core.Commands;

public sealed class InstallLocation
{
    public string? Directory { get; init; }
    public string? AlternateDirectory { get; init; }
    public string UninstallFileName { get; init; } = "uninstall.exe";
    public bool Embedded { get; init; }
    public string Evidence { get; init; } = "";
}

public static partial class InstallLocationFinder
{
    private const string ProgramFiles = @"C:\Program Files";
    private const string ProgramFilesX86 = @"C:\Program Files (x86)";

    public static InstallLocation Find(Stream stream, InstallerFamily family, string? productName, bool? is64Bit)
    {
        var uninstallNames = new List<string>();
        var candidates = new List<ScoredPath>();
        foreach (var text in ReadStrings(stream))
        {
            CollectUninstallName(text, uninstallNames);
            foreach (Match match in AbsolutePath().Matches(text))
                AddAbsolute(candidates, match.Value, productName);
            foreach (Match match in VariablePath().Matches(text))
                AddVariable(candidates, match.Value, productName, is64Bit);
            foreach (Match match in InnoPath().Matches(text))
                AddInno(candidates, match.Value, productName, is64Bit);
        }

        var best = candidates
            .OrderByDescending(item => item.Score)
            .ThenBy(item => item.Directory.Length)
            .FirstOrDefault();
        if (best is not null)
        {
            return new InstallLocation
            {
                Directory = best.Directory,
                AlternateDirectory = best.Alternate,
                UninstallFileName = ChooseUninstallFile(family, uninstallNames),
                Embedded = true,
                Evidence = best.Evidence
            };
        }

        var folder = FolderFromProduct(productName);
        if (folder is null || !UsesInstallFolder(family))
        {
            return new InstallLocation
            {
                UninstallFileName = ChooseUninstallFile(family, uninstallNames)
            };
        }

        var primary = family == InstallerFamily.Squirrel
            ? @"%LOCALAPPDATA%\" + folder
            : (is64Bit == false ? ProgramFilesX86 : ProgramFiles) + "\\" + folder;
        var alternate = family == InstallerFamily.Squirrel
            ? null
            : (is64Bit == false ? ProgramFiles : ProgramFilesX86) + "\\" + folder;
        return new InstallLocation
        {
            Directory = primary,
            AlternateDirectory = string.Equals(primary, alternate, StringComparison.OrdinalIgnoreCase) ? null : alternate,
            UninstallFileName = ChooseUninstallFile(family, uninstallNames),
            Embedded = false,
            Evidence = "The folder name comes from the product name."
        };
    }

    private static void AddAbsolute(List<ScoredPath> candidates, string raw, string? productName)
    {
        var path = Clean(raw);
        if (path is null || IsBlocked(path))
            return;
        var score = 12 + ProductBonus(path, productName);
        candidates.Add(new ScoredPath(path, null, score, raw.Trim()));
    }

    private static void AddVariable(List<ScoredPath> candidates, string raw, string? productName, bool? is64Bit)
    {
        var match = VariablePath().Match(raw);
        if (!match.Success)
            return;
        var token = match.Groups[1].Value;
        var rest = CleanRelative(match.Groups[2].Value);
        if (rest is null)
            return;

        string primary;
        string? alternate;
        var score = 8;
        if (token.Equals("PROGRAMFILES64", StringComparison.OrdinalIgnoreCase))
        {
            primary = ProgramFiles + "\\" + rest;
            alternate = null;
            score = 11;
        }
        else if (token.Equals("PROGRAMFILES32", StringComparison.OrdinalIgnoreCase))
        {
            primary = ProgramFilesX86 + "\\" + rest;
            alternate = null;
            score = 11;
        }
        else if (token.Equals("LOCALAPPDATA", StringComparison.OrdinalIgnoreCase))
        {
            primary = @"%LOCALAPPDATA%\" + rest;
            alternate = null;
            score = 9;
        }
        else if (token.Equals("APPDATA", StringComparison.OrdinalIgnoreCase))
        {
            primary = @"%APPDATA%\" + rest;
            alternate = null;
            score = 7;
        }
        else if (is64Bit == false)
        {
            primary = ProgramFilesX86 + "\\" + rest;
            alternate = ProgramFiles + "\\" + rest;
        }
        else
        {
            primary = ProgramFiles + "\\" + rest;
            alternate = ProgramFilesX86 + "\\" + rest;
        }

        if (IsBlocked(primary))
            return;
        candidates.Add(new ScoredPath(primary, alternate, score + ProductBonus(primary, productName), raw.Trim()));
    }

    private static void AddInno(List<ScoredPath> candidates, string raw, string? productName, bool? is64Bit)
    {
        var match = InnoPath().Match(raw);
        if (!match.Success)
            return;
        var token = match.Groups[1].Value;
        var rest = CleanRelative(match.Groups[2].Value);
        if (rest is null || rest.Contains('{', StringComparison.Ordinal))
            return;

        string primary;
        string? alternate = null;
        var score = 8;
        switch (token.ToLowerInvariant())
        {
            case "autopf64":
            case "commonpf64":
            case "pf64":
            case "pf":
                primary = ProgramFiles + "\\" + rest;
                score = 11;
                break;
            case "autopf32":
            case "commonpf32":
            case "pf32":
                primary = ProgramFilesX86 + "\\" + rest;
                score = 11;
                break;
            case "localappdata":
                primary = @"%LOCALAPPDATA%\" + rest;
                score = 9;
                break;
            case "userappdata":
                primary = @"%APPDATA%\" + rest;
                score = 7;
                break;
            default:
                if (is64Bit == false)
                {
                    primary = ProgramFilesX86 + "\\" + rest;
                    alternate = ProgramFiles + "\\" + rest;
                }
                else
                {
                    primary = ProgramFiles + "\\" + rest;
                    alternate = ProgramFilesX86 + "\\" + rest;
                }
                break;
        }

        if (IsBlocked(primary))
            return;
        candidates.Add(new ScoredPath(primary, alternate, score + ProductBonus(primary, productName), raw.Trim()));
    }

    private static void CollectUninstallName(string text, List<string> names)
    {
        foreach (Match match in UninstallFile().Matches(text))
        {
            var name = match.Groups[1].Value;
            if (names.Any(existing => existing.Equals(name, StringComparison.OrdinalIgnoreCase)))
                continue;
            names.Add(name);
            if (names.Count >= 8)
                return;
        }
    }

    private static string ChooseUninstallFile(InstallerFamily family, IReadOnlyList<string> found)
    {
        var preferred = family switch
        {
            InstallerFamily.InnoSetup => "unins000.exe",
            InstallerFamily.Squirrel => "Update.exe",
            InstallerFamily.QtInstallerFramework => "maintenancetool.exe",
            _ => "uninstall.exe"
        };
        if (family == InstallerFamily.InnoSetup)
        {
            var inno = found.FirstOrDefault(name => name.StartsWith("unins", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
            if (inno is not null)
                return inno;
        }

        var match = found.FirstOrDefault(name => name.Equals(preferred, StringComparison.OrdinalIgnoreCase));
        return match ?? preferred;
    }

    private static bool UsesInstallFolder(InstallerFamily family) => family is
        InstallerFamily.InnoSetup or
        InstallerFamily.Nsis or
        InstallerFamily.Squirrel or
        InstallerFamily.QtInstallerFramework or
        InstallerFamily.InstallAware;

    private static int ProductBonus(string path, string? productName)
    {
        var folder = FolderFromProduct(productName);
        if (folder is null)
            return 0;
        return path.Contains(folder, StringComparison.OrdinalIgnoreCase) ? 5 : 0;
    }

    private static string? FolderFromProduct(string? productName)
    {
        if (string.IsNullOrWhiteSpace(productName))
            return null;
        var trimmed = TrailingVersion().Replace(productName.Trim(), "").Trim().TrimEnd('.');
        if (trimmed.Length is < 2 or > 80)
            return null;
        if (trimmed.IndexOfAny(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) >= 0)
            return null;
        if (GenericName().IsMatch(trimmed))
            return null;
        return trimmed;
    }

    private static string? Clean(string raw)
    {
        var text = raw.Trim().Trim('"').TrimEnd('\\', '/');
        if (text.Length is < 4 or > 180)
            return null;
        if (FileEnding().IsMatch(text))
        {
            var slash = text.LastIndexOf('\\');
            if (slash <= 2)
                return null;
            text = text[..slash];
        }

        return text;
    }

    private static string? CleanRelative(string raw)
    {
        var text = raw.Trim().Trim('"').Trim('\\', '/');
        if (text.Length is < 1 or > 120 || text.Contains('{', StringComparison.Ordinal))
            return null;
        if (FileEnding().IsMatch(text))
        {
            var slash = text.LastIndexOf('\\');
            text = slash < 0 ? "" : text[..slash];
        }

        if (text.Length == 0 || text.Split('\\').Any(part => part is "" or "." or ".."))
            return null;
        return text;
    }

    private static bool IsBlocked(string path)
    {
        var parts = path.Split('\\');
        foreach (var part in parts)
        {
            if (part.Equals("Windows", StringComparison.OrdinalIgnoreCase)
                || part.Equals("WindowsApps", StringComparison.OrdinalIgnoreCase)
                || part.Equals("Common Files", StringComparison.OrdinalIgnoreCase)
                || part.Equals("Internet Explorer", StringComparison.OrdinalIgnoreCase)
                || part.Equals("ModifiableWindowsApps", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static IEnumerable<string> ReadStrings(Stream stream)
    {
        stream.Position = 0;
        var length = stream.Length;
        if (length > 96L * 1024 * 1024)
        {
            foreach (var text in ReadRange(stream, 0, 64L * 1024 * 1024))
                yield return text;
            foreach (var text in ReadRange(stream, Math.Max(0, length - 32L * 1024 * 1024), 32L * 1024 * 1024))
                yield return text;
            yield break;
        }

        foreach (var text in ReadRange(stream, 0, length))
            yield return text;
    }

    private static IEnumerable<string> ReadRange(Stream stream, long start, long count)
    {
        stream.Position = start;
        var overlap = 512;
        var buffer = new byte[1024 * 1024 + overlap];
        var carry = 0;
        long remaining = count;
        while (remaining > 0)
        {
            var want = (int)Math.Min(buffer.Length - carry, remaining);
            var read = stream.Read(buffer, carry, want);
            if (read == 0)
                break;
            remaining -= read;
            var total = carry + read;
            foreach (var text in StringsIn(buffer, total))
                yield return text;
            carry = Math.Min(overlap, total);
            Buffer.BlockCopy(buffer, total - carry, buffer, 0, carry);
        }
    }

    private static List<string> StringsIn(byte[] data, int count)
    {
        var found = new List<string>();
        var ascii = new StringBuilder();
        for (var i = 0; i < count; i++)
        {
            var value = data[i];
            if (value is >= 32 and <= 126)
            {
                ascii.Append((char)value);
                continue;
            }

            if (ascii.Length >= 8)
                found.Add(ascii.ToString());
            ascii.Clear();
        }

        if (ascii.Length >= 8)
            found.Add(ascii.ToString());

        var utf = new StringBuilder();
        for (var i = 0; i + 1 < count; i += 2)
        {
            var value = data[i];
            if (data[i + 1] == 0 && value is >= 32 and <= 126)
            {
                utf.Append((char)value);
                continue;
            }

            if (utf.Length >= 8)
                found.Add(utf.ToString());
            utf.Clear();
            if (data[i + 1] != 0)
                i--;
        }

        if (utf.Length >= 8)
            found.Add(utf.ToString());
        return found;
    }

    private sealed record ScoredPath(string Directory, string? Alternate, int Score, string Evidence);

    [GeneratedRegex(@"(?i)[A-Za-z]:\\Program Files(?: \(x86\))?\\[^\\/:*?""<>|\r\n]{1,60}(?:\\[^\\/:*?""<>|\r\n]{1,40})?")]
    private static partial Regex AbsolutePath();

    [GeneratedRegex(@"(?i)\$(PROGRAMFILES64|PROGRAMFILES32|PROGRAMFILES|LOCALAPPDATA|APPDATA)\\([^\\$""\r\n]{1,80})")]
    private static partial Regex VariablePath();

    [GeneratedRegex(@"(?i)\{(autopf64|autopf32|autopf|commonpf64|commonpf32|commonpf|pf64|pf32|pf|localappdata|userappdata)\}\\([^\\{}""\r\n]{1,80})")]
    private static partial Regex InnoPath();

    [GeneratedRegex(@"(?i)(?:^|[^A-Za-z])((?:uninstall|uninst|unins\d{3}|maintenancetool|update)\.exe)")]
    private static partial Regex UninstallFile();

    [GeneratedRegex(@"(?i)\.(?:exe|dll|msi|sys|mui)$")]
    private static partial Regex FileEnding();

    [GeneratedRegex(@"(?i)\s+v?\d+(?:\.\d+){0,3}\s*$")]
    private static partial Regex TrailingVersion();

    [GeneratedRegex(@"^(?i)(setup|installer|install|application|app|unknown|program|software)$")]
    private static partial Regex GenericName();
}
