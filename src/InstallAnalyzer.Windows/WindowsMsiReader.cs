using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using InstallAnalyzer.Core;
using InstallAnalyzer.Core.Msi;

namespace InstallAnalyzer.Windows;

[SupportedOSPlatform("windows")]
public sealed class WindowsMsiReader : IMsiReader
{
    private const uint ErrorSuccess = 0;
    private const uint ErrorMoreData = 234;
    private const uint ErrorNoMoreItems = 259;

    private static readonly HashSet<string> IdentityKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "ProductCode",
        "ProductName",
        "ProductVersion",
        "Manufacturer",
        "UpgradeCode"
    };

    public bool IsAvailable => OperatingSystem.IsWindows();

    public MsiFacts Read(string path)
    {
        if (!OperatingSystem.IsWindows())
            return new MsiFacts { ReadError = "Reading MSI tables runs on Windows." };

        var database = IntPtr.Zero;
        var view = IntPtr.Zero;
        try
        {
            var opened = Native.MsiOpenDatabaseW(path, IntPtr.Zero, out database);
            if (opened != ErrorSuccess)
                return new MsiFacts { ReadError = "Windows Installer could not open this package (" + opened + ")." };

            var queried = Native.MsiDatabaseOpenViewW(database, "SELECT `Property`, `Value` FROM `Property`", out view);
            if (queried != ErrorSuccess)
                return new MsiFacts { ReadError = "The Property table could not be read (" + queried + ")." };

            var executed = Native.MsiViewExecute(view, IntPtr.Zero);
            if (executed != ErrorSuccess)
                return new MsiFacts { ReadError = "The Property table could not be read (" + executed + ")." };

            var properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            while (true)
            {
                var fetched = Native.MsiViewFetch(view, out var record);
                if (fetched == ErrorNoMoreItems)
                    break;
                if (fetched != ErrorSuccess)
                    break;
                try
                {
                    var name = GetString(record, 1);
                    var value = GetString(record, 2);
                    if (name.Length > 0)
                        properties[name] = value;
                }
                finally
                {
                    Native.MsiCloseHandle(record);
                }
            }

            string? Value(string key) => properties.TryGetValue(key, out var value) ? value : null;
            var publics = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var pair in properties)
            {
                if (!IsPublic(pair.Key) || IdentityKeys.Contains(pair.Key) || pair.Value.Length > 200)
                    continue;
                publics[pair.Key] = pair.Value;
                if (publics.Count >= 30)
                    break;
            }

            return new MsiFacts
            {
                ProductCode = Value("ProductCode"),
                ProductName = Value("ProductName"),
                ProductVersion = Value("ProductVersion"),
                Manufacturer = Value("Manufacturer"),
                UpgradeCode = Value("UpgradeCode"),
                PublicProperties = publics
            };
        }
        finally
        {
            if (view != IntPtr.Zero)
                Native.MsiCloseHandle(view);
            if (database != IntPtr.Zero)
                Native.MsiCloseHandle(database);
        }
    }

    private static bool IsPublic(string name) =>
        name.Any(char.IsLetter) && name.All(ch => !char.IsLetter(ch) || char.IsUpper(ch));

    private static string GetString(IntPtr record, uint field)
    {
        var buffer = new char[512];
        var size = (uint)buffer.Length;
        var result = Native.MsiRecordGetStringW(record, field, buffer, ref size);
        if (result == ErrorMoreData)
        {
            buffer = new char[size + 1];
            size = (uint)buffer.Length;
            result = Native.MsiRecordGetStringW(record, field, buffer, ref size);
        }

        return result == ErrorSuccess ? new string(buffer, 0, (int)Math.Min(size, buffer.Length)) : "";
    }

    private static class Native
    {
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint MsiOpenDatabaseW(string path, IntPtr persist, out IntPtr database);

        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint MsiDatabaseOpenViewW(IntPtr database, string query, out IntPtr view);

        [DllImport("msi.dll", ExactSpelling = true)]
        internal static extern uint MsiViewExecute(IntPtr view, IntPtr record);

        [DllImport("msi.dll", ExactSpelling = true)]
        internal static extern uint MsiViewFetch(IntPtr view, out IntPtr record);

        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint MsiRecordGetStringW(IntPtr record, uint field, char[] buffer, ref uint size);

        [DllImport("msi.dll", ExactSpelling = true)]
        internal static extern uint MsiCloseHandle(IntPtr handle);
    }
}
