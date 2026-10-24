using System.Text.RegularExpressions;

namespace InstallAnalyzer.Core.Help;

public static partial class HelpTextParser
{
    private static readonly HashSet<string> Triggers = new(StringComparer.OrdinalIgnoreCase)
    {
        "/VERYSILENT",
        "/SILENT",
        "/S",
        "/silent",
        "/quiet",
        "/qn",
        "/qb",
        "/qb!",
        "/qr",
        "/passive",
        "/exenoui",
        "/Q",
        "--silent",
        "--quiet"
    };

    private static readonly HashSet<string> Companions = new(StringComparer.OrdinalIgnoreCase)
    {
        "/NORESTART",
        "/SUPPRESSMSGBOXES",
        "/norestart"
    };

    private static readonly string[] TriggerPreference =
    [
        "/VERYSILENT",
        "/SILENT",
        "/quiet",
        "--quiet",
        "/qn",
        "/passive",
        "/exenoui",
        "/S",
        "--silent",
        "/Q",
        "/qb",
        "/qb!",
        "/qr",
        "/silent"
    ];

    [GeneratedRegex(@"(?<=^|[\s""'=,;(])(/[A-Za-z?][A-Za-z0-9?_-]*|--[A-Za-z][A-Za-z0-9_-]*)")]
    private static partial Regex SwitchPattern();

    public static IReadOnlyList<string> Extract(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return [];

        var found = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in SwitchPattern().Matches(text))
        {
            var token = match.Value;
            if (token.Length < 2 || !seen.Add(token))
                continue;
            found.Add(token);
            if (found.Count >= 40)
                break;
        }

        return found;
    }

    public static bool IsSilentTrigger(string flag) => Triggers.Contains(flag);

    public static bool IsSilentCompanion(string flag) => Companions.Contains(flag);

    public static bool IsKnownSilent(string flag) => IsSilentTrigger(flag) || IsSilentCompanion(flag);

    public static bool LooksLikeHelp(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return false;
        if (text.Contains("/?", StringComparison.Ordinal)
            || text.Contains("usage", StringComparison.OrdinalIgnoreCase)
            || text.Contains("command line", StringComparison.OrdinalIgnoreCase)
            || text.Contains("options:", StringComparison.OrdinalIgnoreCase))
            return true;
        var switches = Extract(text);
        return switches.Count >= 2 || switches.Any(IsKnownSilent);
    }

    public static bool LooksLikeWizard(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || LooksLikeHelp(text))
            return false;
        return WizardMarkers().IsMatch(text);
    }

    [GeneratedRegex(@"(?i)\b(next\s*>|i agree|license agreement|install now|destination folder|choose components|welcome to the)\b")]
    private static partial Regex WizardMarkers();

    public static string? BestTrigger(IEnumerable<string> flags)
    {
        var list = flags.ToList();
        foreach (var preferred in TriggerPreference)
        {
            var found = list.FirstOrDefault(flag => flag.Equals(preferred, StringComparison.OrdinalIgnoreCase));
            if (found != null)
                return found;
        }

        return null;
    }
}
