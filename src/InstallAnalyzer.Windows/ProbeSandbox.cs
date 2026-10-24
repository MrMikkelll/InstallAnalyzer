using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace InstallAnalyzer.Windows;

[SupportedOSPlatform("windows")]
internal sealed class ProbeSandbox : IDisposable
{
    private const int AlreadyExists = unchecked((int)0x800700B7);
    private const uint SeFileObject = 1;
    private const uint SeWindowObject = 3;
    private const uint DaclSecurityInformation = 0x4;
    private const uint GrantAccess = 1;
    private const uint FileGenericReadExecute = 0x001200A9;
    private const uint DesktopRights = 0x01FF;
    private const string ContainerName = "InstallAnalyzerProbe";

    private ProbeSandbox(IntPtr sid, string sidString, string? packageFolder, IntPtr desktop, string? desktopName)
    {
        Sid = sid;
        SidString = sidString;
        PackageFolder = packageFolder;
        Desktop = desktop;
        DesktopName = desktopName;
    }

    public IntPtr Sid { get; }
    public string SidString { get; }
    public string? PackageFolder { get; }
    public IntPtr Desktop { get; }
    public string? DesktopName { get; }

    public static bool TryCreate(out ProbeSandbox? sandbox, out string? error)
    {
        sandbox = null;
        error = null;
        var hr = Native.CreateAppContainerProfile(ContainerName, "Install Analyzer", "Help probe", IntPtr.Zero, 0, out var sid);
        if (hr == AlreadyExists)
        {
            if (sid != IntPtr.Zero)
                Native.FreeSid(sid);
            hr = Native.DeriveAppContainerSidFromAppContainerName(ContainerName, out sid);
        }
        if (hr != 0 || sid == IntPtr.Zero)
        {
            error = "Help query was not started because the sandbox could not be created (" + hr.ToString("X8") + "). The installer was not run.";
            return false;
        }

        if (!Native.ConvertSidToStringSid(sid, out var sidPtr) || sidPtr == IntPtr.Zero)
        {
            Native.FreeSid(sid);
            error = "Help query was not started because the sandbox identity could not be read. The installer was not run.";
            return false;
        }

        var sidString = Marshal.PtrToStringUni(sidPtr) ?? "";
        Native.LocalFree(sidPtr);
        if (sidString.Length == 0)
        {
            Native.FreeSid(sid);
            error = "Help query was not started because the sandbox identity was empty. The installer was not run.";
            return false;
        }

        string? package = null;
        if (Native.GetAppContainerFolderPath(sidString, out var folder) == 0 && folder != IntPtr.Zero)
        {
            package = Marshal.PtrToStringUni(folder);
            Native.CoTaskMemFree(folder);
        }

        var desktopName = "InstallAnalyzerProbe";
        var desktop = Native.CreateDesktop(desktopName, null, IntPtr.Zero, 0, DesktopRights, IntPtr.Zero);
        string? startupDesktop = null;
        if (desktop != IntPtr.Zero && Grant(@"WinSta0\" + desktopName, SeWindowObject, sid, DesktopRights, inherit: false))
            startupDesktop = "winsta0\\" + desktopName;
        else if (desktop != IntPtr.Zero)
        {
            Native.CloseDesktop(desktop);
            desktop = IntPtr.Zero;
        }

        sandbox = new ProbeSandbox(sid, sidString, package, desktop, startupDesktop);
        return true;
    }

    public static void GrantReadExecute(string path, IntPtr sid, bool directory) =>
        Grant(path, SeFileObject, sid, FileGenericReadExecute, directory);

    public void Dispose()
    {
        if (Desktop != IntPtr.Zero)
            Native.CloseDesktop(Desktop);
        if (Sid != IntPtr.Zero)
            Native.FreeSid(Sid);
        Native.DeleteAppContainerProfile(ContainerName);
    }

    private static bool Grant(string name, uint objectType, IntPtr sid, uint rights, bool inherit)
    {
        if (Native.GetNamedSecurityInfo(name, objectType, DaclSecurityInformation, out _, out _, out var dacl, out _, out var descriptor) != 0)
            return false;

        var entry = new Native.ExplicitAccess
        {
            grfAccessPermissions = rights,
            grfAccessMode = GrantAccess,
            grfInheritance = inherit ? 0x3u : 0u,
            Trustee = new Native.Trustee
            {
                TrusteeForm = 0,
                TrusteeType = 0,
                ptstrName = sid
            }
        };
        var built = Native.SetEntriesInAcl(1, ref entry, dacl, out var replacement);
        if (descriptor != IntPtr.Zero)
            Native.LocalFree(descriptor);
        if (built != 0 || replacement == IntPtr.Zero)
            return false;

        var applied = Native.SetNamedSecurityInfo(name, objectType, DaclSecurityInformation, IntPtr.Zero, IntPtr.Zero, replacement, IntPtr.Zero);
        Native.LocalFree(replacement);
        return applied == 0;
    }

    private static class Native
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct Trustee
        {
            public IntPtr pMultipleTrustee;
            public int MultipleTrusteeOperation;
            public int TrusteeForm;
            public int TrusteeType;
            public IntPtr ptstrName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct ExplicitAccess
        {
            public uint grfAccessPermissions;
            public uint grfAccessMode;
            public uint grfInheritance;
            public Trustee Trustee;
        }

        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        internal static extern int CreateAppContainerProfile(
            string name,
            string display,
            string description,
            IntPtr capabilities,
            uint capabilityCount,
            out IntPtr sid);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        internal static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        internal static extern int DeleteAppContainerProfile(string name);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        internal static extern int GetAppContainerFolderPath(string sid, out IntPtr path);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr text);

        [DllImport("advapi32.dll")]
        internal static extern IntPtr FreeSid(IntPtr sid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint GetNamedSecurityInfo(
            string name,
            uint objectType,
            uint securityInfo,
            out IntPtr owner,
            out IntPtr group,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr descriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint SetNamedSecurityInfo(
            string name,
            uint objectType,
            uint securityInfo,
            IntPtr owner,
            IntPtr group,
            IntPtr dacl,
            IntPtr sacl);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint SetEntriesInAcl(int count, ref ExplicitAccess entry, IntPtr oldAcl, out IntPtr newAcl);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr LocalFree(IntPtr memory);

        [DllImport("ole32.dll")]
        internal static extern void CoTaskMemFree(IntPtr memory);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CreateDesktop(string name, string? device, IntPtr devmode, uint flags, uint access, IntPtr security);

        [DllImport("user32.dll", SetLastError = true)]
        internal static extern bool CloseDesktop(IntPtr desktop);
    }
}
