using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using InstallAnalyzer.Core.Help;
using Microsoft.Win32.SafeHandles;

namespace InstallAnalyzer.Windows;

[SupportedOSPlatform("windows")]
public sealed class WindowsHelpQuery : IHelpQueryRunner
{
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateNoWindow = 0x08000000;
    private const int StartfUseStdHandles = 0x00000100;
    private const int StartfUseShowWindow = 0x00000001;
    private const short SwHide = 0;
    private const uint HandleFlagInherit = 0x00000001;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint KillOnJobClose = 0x2000;
    private const uint WaitTimeout = 0x00000102;
    private const int ErrorElevationRequired = 740;
    private const int MaxOutput = 256 * 1024;

    public Task<HelpQueryResult> RunAsync(HelpQueryRequest request, CancellationToken cancellationToken) =>
        Task.Run(() => Run(request, cancellationToken), cancellationToken);

    private static HelpQueryResult Run(HelpQueryRequest request, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return HelpQueryResult.Failed("Help query runs on Windows.");
        if (!File.Exists(request.FilePath))
            return HelpQueryResult.Failed("File was not found.");

        var job = IntPtr.Zero;
        var process = IntPtr.Zero;
        var thread = IntPtr.Zero;
        var stdin = IntPtr.Zero;
        var stdoutRead = IntPtr.Zero;
        var stdoutWrite = IntPtr.Zero;
        var stderrRead = IntPtr.Zero;
        var stderrWrite = IntPtr.Zero;
        Task<string>? stdoutTask = null;
        Task<string>? stderrTask = null;

        try
        {
            job = Native.CreateJobObject(IntPtr.Zero, null);
            if (job != IntPtr.Zero)
                ConfigureJob(job);

            var security = new Native.SecurityAttributes
            {
                nLength = Marshal.SizeOf<Native.SecurityAttributes>(),
                bInheritHandle = 1
            };
            if (!Native.CreatePipe(out stdoutRead, out stdoutWrite, ref security, 0)
                || !Native.CreatePipe(out stderrRead, out stderrWrite, ref security, 0))
                return HelpQueryResult.Failed("Could not capture installer output (" + Marshal.GetLastWin32Error() + ").");

            Native.SetHandleInformation(stdoutRead, HandleFlagInherit, 0);
            Native.SetHandleInformation(stderrRead, HandleFlagInherit, 0);
            stdin = Native.CreateFile("NUL", GenericRead, FileShareRead, ref security, OpenExisting, 0, IntPtr.Zero);

            var startup = new Native.StartupInfo
            {
                cb = Marshal.SizeOf<Native.StartupInfo>(),
                dwFlags = StartfUseStdHandles | StartfUseShowWindow,
                wShowWindow = SwHide,
                hStdInput = stdin,
                hStdOutput = stdoutWrite,
                hStdError = stderrWrite
            };

            var commandLine = CommandLine(request.FilePath, request.Arguments);
            var directory = Path.GetDirectoryName(request.FilePath);
            if (!Native.CreateProcess(request.FilePath, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                    CreateSuspended | CreateNoWindow, IntPtr.Zero, directory, ref startup, out var info))
            {
                var error = Marshal.GetLastWin32Error();
                var message = error == ErrorElevationRequired
                    ? "Windows asked for administrator approval, so the help query was not started."
                    : "The installer could not be started (" + error + ").";
                return HelpQueryResult.Failed(message);
            }

            process = info.hProcess;
            thread = info.hThread;
            if (job != IntPtr.Zero)
                Native.AssignProcessToJobObject(job, process);

            var stdoutHandle = stdoutRead;
            var stderrHandle = stderrRead;
            stdoutTask = Task.Run(() => ReadPipe(stdoutHandle));
            stderrTask = Task.Run(() => ReadPipe(stderrHandle));
            stdoutRead = IntPtr.Zero;
            stderrRead = IntPtr.Zero;
            Close(ref stdoutWrite);
            Close(ref stderrWrite);
            Close(ref stdin);

            Native.ResumeThread(thread);
            var timeout = request.Timeout <= TimeSpan.Zero ? TimeSpan.FromSeconds(12) : request.Timeout;
            var waitMs = (uint)Math.Clamp((long)timeout.TotalMilliseconds, 1, int.MaxValue);
            var waited = Native.WaitForSingleObject(process, waitMs);
            var timedOut = waited == WaitTimeout || cancellationToken.IsCancellationRequested;
            if (timedOut)
            {
                if (job != IntPtr.Zero)
                    Native.TerminateJobObject(job, 1);
                Native.TerminateProcess(process, 1);
                Native.WaitForSingleObject(process, 2000);
            }

            var stdout = WaitText(stdoutTask);
            var stderr = WaitText(stderrTask);
            int? exit = null;
            if (Native.GetExitCodeProcess(process, out var code))
                exit = unchecked((int)code);

            return new HelpQueryResult
            {
                StandardOutput = stdout,
                StandardError = stderr,
                TimedOut = timedOut,
                ExitCode = exit
            };
        }
        finally
        {
            Close(ref stdoutWrite);
            Close(ref stderrWrite);
            Close(ref stdin);
            Close(ref stdoutRead);
            Close(ref stderrRead);
            Close(ref thread);
            Close(ref process);
            if (job != IntPtr.Zero)
            {
                Native.CloseHandle(job);
            }
        }
    }

    private static void ConfigureJob(IntPtr job)
    {
        var info = new Native.JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new Native.JobObjectBasicLimitInformation
            {
                LimitFlags = KillOnJobClose
            }
        };
        var size = Marshal.SizeOf<Native.JobObjectExtendedLimitInformation>();
        var pointer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(info, pointer, false);
            Native.SetInformationJobObject(job, JobObjectExtendedLimitInformation, pointer, (uint)size);
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }
    }

    private static string CommandLine(string path, string arguments)
    {
        var command = "\"" + path.Replace("\"", "\\\"") + "\"";
        if (!string.IsNullOrWhiteSpace(arguments))
            command += " " + arguments.Trim();
        return command;
    }

    private static string ReadPipe(IntPtr handle)
    {
        using var stream = new FileStream(new SafeFileHandle(handle, ownsHandle: true), FileAccess.Read);
        using var memory = new MemoryStream();
        var buffer = new byte[4096];
        while (memory.Length < MaxOutput)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
                break;
            memory.Write(buffer, 0, read);
        }

        return Decode(memory.ToArray());
    }

    private static string WaitText(Task<string>? task)
    {
        if (task is null)
            return "";
        try
        {
            return task.Wait(TimeSpan.FromSeconds(3)) ? task.Result : "";
        }
        catch (AggregateException)
        {
            return "";
        }
    }

    private static string Decode(byte[] data)
    {
        if (data.Length == 0)
            return "";
        if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE)
            return Encoding.Unicode.GetString(data, 2, data.Length - 2).Trim();
        return Encoding.UTF8.GetString(data).Trim();
    }

    private static void Close(ref IntPtr handle)
    {
        if (handle == IntPtr.Zero)
            return;
        Native.CloseHandle(handle);
        handle = IntPtr.Zero;
    }

    private static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct SecurityAttributes
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct StartupInfo
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JobObjectBasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public nuint MinimumWorkingSetSize;
            public nuint MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public nuint Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JobObjectExtendedLimitInformation
        {
            public JobObjectBasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public nuint ProcessMemoryLimit;
            public nuint JobMemoryLimit;
            public nuint PeakProcessMemoryUsed;
            public nuint PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CreateProcess(
            string application,
            string commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            uint flags,
            IntPtr environment,
            string? directory,
            ref StartupInfo startup,
            out ProcessInformation information);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SecurityAttributes security, uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CreateFile(
            string name,
            uint access,
            uint share,
            ref SecurityAttributes security,
            uint disposition,
            uint flags,
            IntPtr template);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CreateJobObject(IntPtr attributes, string? name);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    }
}
