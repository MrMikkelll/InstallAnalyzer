using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using InstallAnalyzer.Core.Help;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace InstallAnalyzer.Windows;

[SupportedOSPlatform("windows")]
public sealed class WindowsHelpQuery : IHelpQueryRunner
{
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateNoWindow = 0x08000000;
    private const uint ExtendedStartupInfo = 0x00080000;
    private const int StartfUseStdHandles = 0x00000100;
    private const int StartfUseShowWindow = 0x00000001;
    private const short SwHide = 0;
    private const uint HandleFlagInherit = 0x00000001;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const int JobObjectExtendedLimitInformation = 9;
    private const int JobObjectBasicProcessIdList = 3;
    private const int JobObjectNetRateControlInformation = 32;
    private const uint KillOnJobClose = 0x2000;
    private const uint ActiveProcessLimit = 0x00000008;
    private const uint WaitTimeout = 0x00000102;
    private const int ErrorElevationRequired = 740;
    private const int ErrorIllegalDllRelocation = 623;
    private const uint TokenAdjustDefault = 0x0080;
    private const uint TokenQuery = 0x0008;
    private const int TokenIntegrityLevel = 25;
    private const uint SeGroupIntegrity = 0x20;
    private const int MaxOutput = 256 * 1024;
    private const int ProcThreadAttributeSecurityCapabilities = 0x00020009;
    private const int ProcThreadAttributeHandleList = 0x00020002;

    public Task<HelpQueryResult> RunAsync(HelpQueryRequest request, CancellationToken cancellationToken) =>
        Task.Run(() => Run(request, cancellationToken), cancellationToken);

    private static HelpQueryResult Run(HelpQueryRequest request, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return HelpQueryResult.Failed("Help query runs on Windows.");
        if (!File.Exists(request.FilePath))
            return HelpQueryResult.Failed("File was not found.");

        var switches = (request.Arguments.Count > 0 ? request.Arguments : HelpSwitches.Candidates(request.Family))
            .Where(HelpSwitches.IsSafeProbe)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (switches.Count == 0)
            return HelpQueryResult.Failed("Refused to start the installer. None of the requested switches are help switches, so nothing was run.");

        request.Progress?.Report("Preparing a sandbox…");
        if (!ProbeSandbox.TryCreate(out var sandbox, out var sandboxError) || sandbox is null)
            return HelpQueryResult.Failed(sandboxError ?? "Help query was not started because the sandbox could not be created. The installer was not run.");

        using (sandbox)
        {
            var chunks = new List<string>();
            var stopped = false;
            var timedOut = false;
            var relaxed = false;
            string? startError = null;
            var timeout = request.Timeout <= TimeSpan.Zero ? TimeSpan.FromSeconds(3) : request.Timeout;
            foreach (var flag in switches)
            {
                cancellationToken.ThrowIfCancellationRequested();
                request.Progress?.Report("Trying " + flag + " without installing…");
                var attempt = ProbeOnce(request.FilePath, flag, timeout, sandbox, cancellationToken);
                if (attempt.RelaxedSandbox)
                    relaxed = true;
                if (attempt.StoppedInstaller)
                    stopped = true;
                if (attempt.TimedOut)
                    timedOut = true;
                if (attempt.StartFailed)
                {
                    startError = attempt.Error;
                    break;
                }

                if (!string.IsNullOrWhiteSpace(attempt.Text) && HelpTextParser.LooksLikeHelp(attempt.Text))
                {
                    chunks.Add(flag + "\n" + attempt.Text.Trim());
                    break;
                }
            }

            if (chunks.Count == 0 && startError is not null)
            {
                return new HelpQueryResult
                {
                    Error = startError,
                    InstallerWasStopped = stopped,
                    RelaxedSandbox = relaxed,
                    Attempted = string.Join(" ", switches)
                };
            }

            return new HelpQueryResult
            {
                StandardOutput = string.Join("\n\n", chunks).Trim(),
                TimedOut = timedOut && chunks.Count == 0,
                InstallerWasStopped = stopped,
                RelaxedSandbox = relaxed,
                Attempted = string.Join(" ", switches)
            };
        }
    }

    private enum LaunchMode
    {
        ContainerDesktop,
        Container,
        LowIntegrity
    }

    private static Attempt ProbeOnce(string filePath, string flag, TimeSpan timeout, ProbeSandbox sandbox, CancellationToken cancellationToken)
    {
        Attempt? last = null;
        foreach (var mode in new[] { LaunchMode.ContainerDesktop, LaunchMode.Container, LaunchMode.LowIntegrity })
        {
            last = Launch(filePath, flag, timeout, sandbox, cancellationToken, mode);
            if (!last.StartFailed || last.Win32Error != ErrorIllegalDllRelocation)
                return last;
        }

        return last ?? Attempt.Failed("The sandboxed help process could not be started. The installer was not run.");
    }

    private static Attempt Launch(string filePath, string flag, TimeSpan timeout, ProbeSandbox sandbox, CancellationToken cancellationToken, LaunchMode mode)
    {
        string executable;
        string? copyDirectory = null;
        var lowIntegrity = mode == LaunchMode.LowIntegrity;
        try
        {
            executable = lowIntegrity
                ? Path.GetFullPath(filePath)
                : PrepareExecutable(filePath, sandbox, ref copyDirectory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            DeleteCopy(copyDirectory);
            return Attempt.Failed("The installer could not be copied into the sandbox. It was not started. " + ex.Message);
        }

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
        var attributeList = IntPtr.Zero;
        var capabilities = IntPtr.Zero;
        var desktopPointer = IntPtr.Zero;
        var environment = IntPtr.Zero;
        var attributesReady = false;
        string? probeTemp = null;
        GCHandle handles = default;

        try
        {
            probeTemp = CreateProbeTemp(lowIntegrity, sandbox);
            environment = EnvironmentWithTemp(probeTemp);
            job = Native.CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero || !ConfigureJob(job))
                return Attempt.Failed("Help query was not started because the process job could not be created. The installer was not run.");

            var security = new Native.SecurityAttributes
            {
                nLength = Marshal.SizeOf<Native.SecurityAttributes>(),
                bInheritHandle = 1
            };
            if (!Native.CreatePipe(out stdoutRead, out stdoutWrite, ref security, 0)
                || !Native.CreatePipe(out stderrRead, out stderrWrite, ref security, 0))
                return Attempt.Failed("Could not capture installer output. The installer was not run.");

            Native.SetHandleInformation(stdoutRead, HandleFlagInherit, 0);
            Native.SetHandleInformation(stderrRead, HandleFlagInherit, 0);
            stdin = Native.CreateFile("NUL", GenericRead, FileShareRead, ref security, OpenExisting, 0, IntPtr.Zero);
            if (stdin == IntPtr.Zero || stdin == new IntPtr(-1))
                return Attempt.Failed("Could not redirect installer input. The installer was not run.");

            var inherited = new[] { stdin, stdoutWrite, stderrWrite };
            handles = GCHandle.Alloc(inherited, GCHandleType.Pinned);
            if (!lowIntegrity && mode == LaunchMode.ContainerDesktop && sandbox.DesktopName is not null)
                desktopPointer = Marshal.StringToHGlobalUni(sandbox.DesktopName);
            if (lowIntegrity)
            {
                if (sandbox.Desktop != IntPtr.Zero && MarkLowIntegrityObject(sandbox.Desktop) && sandbox.DesktopName is not null)
                    desktopPointer = Marshal.StringToHGlobalUni(sandbox.DesktopName);
                var plain = new Native.StartupInfo
                {
                    cb = Marshal.SizeOf<Native.StartupInfo>(),
                    dwFlags = StartfUseStdHandles | StartfUseShowWindow,
                    wShowWindow = SwHide,
                    hStdInput = stdin,
                    hStdOutput = stdoutWrite,
                    hStdError = stderrWrite,
                    lpDesktop = desktopPointer
                };
                var plainCommand = new StringBuilder("\"" + executable.Replace("\"", "\\\"") + "\" " + flag);
                if (!Native.CreateProcessSimple(executable, plainCommand, IntPtr.Zero, IntPtr.Zero, true,
                        CreateSuspended | CreateNoWindow | CreateUnicodeEnvironment, environment, probeTemp, ref plain, out var plainInfo)
                    && desktopPointer != IntPtr.Zero)
                {
                    plain.lpDesktop = IntPtr.Zero;
                    if (!Native.CreateProcessSimple(executable, plainCommand, IntPtr.Zero, IntPtr.Zero, true,
                            CreateSuspended | CreateNoWindow | CreateUnicodeEnvironment, environment, probeTemp, ref plain, out plainInfo))
                    {
                        var plainError = Marshal.GetLastWin32Error();
                        return Attempt.Failed(StartError(plainError), plainError);
                    }
                }
                else if (plainInfo.hProcess == IntPtr.Zero)
                {
                    var plainError = Marshal.GetLastWin32Error();
                    return Attempt.Failed(StartError(plainError), plainError);
                }

                process = plainInfo.hProcess;
                thread = plainInfo.hThread;
                var plainId = plainInfo.dwProcessId;
                if (!Native.AssignProcessToJobObject(job, process) || !LowerIntegrity(process))
                {
                    Native.TerminateProcess(process, 1);
                    return Attempt.Failed("The low-integrity probe could not be contained, so it was stopped before it ran. Nothing was installed.");
                }

                var plainOut = stdoutRead;
                var plainErr = stderrRead;
                stdoutTask = Task.Run(() => ReadPipe(plainOut));
                stderrTask = Task.Run(() => ReadPipe(plainErr));
                stdoutRead = IntPtr.Zero;
                stderrRead = IntPtr.Zero;
                Close(ref stdoutWrite);
                Close(ref stderrWrite);
                Close(ref stdin);
                var plainKeys = UninstallKeyCount();
                Native.ResumeThread(thread);
                var plainAttempt = Watch(job, process, plainId, sandbox, timeout, cancellationToken, stdoutTask, stderrTask, plainKeys);
                return CopyRelaxed(plainAttempt);
            }

            capabilities = Marshal.AllocHGlobal(Marshal.SizeOf<Native.SecurityCapabilities>());
            Marshal.StructureToPtr(new Native.SecurityCapabilities
            {
                AppContainerSid = sandbox.Sid,
                Capabilities = IntPtr.Zero,
                CapabilityCount = 0
            }, capabilities, false);

            var bytes = IntPtr.Zero;
            Native.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref bytes);
            if (bytes == IntPtr.Zero)
                return Attempt.Failed("Could not prepare the sandbox. The installer was not run.");
            attributeList = Marshal.AllocHGlobal(bytes);
            if (!Native.InitializeProcThreadAttributeList(attributeList, 2, 0, ref bytes))
                return Attempt.Failed("Could not prepare the sandbox (" + Marshal.GetLastWin32Error() + "). The installer was not run.");
            attributesReady = true;

            var updated = Native.UpdateProcThreadAttribute(attributeList, 0, (IntPtr)ProcThreadAttributeSecurityCapabilities, capabilities, (IntPtr)Marshal.SizeOf<Native.SecurityCapabilities>(), IntPtr.Zero, IntPtr.Zero)
                && Native.UpdateProcThreadAttribute(attributeList, 0, (IntPtr)ProcThreadAttributeHandleList, handles.AddrOfPinnedObject(), (IntPtr)(inherited.Length * IntPtr.Size), IntPtr.Zero, IntPtr.Zero);
            if (!updated)
                return Attempt.Failed("Could not apply the sandbox (" + Marshal.GetLastWin32Error() + "). The installer was not run.");

            var startup = new Native.StartupInfoEx
            {
                StartupInfo = new Native.StartupInfo
                {
                    cb = Marshal.SizeOf<Native.StartupInfoEx>(),
                    dwFlags = StartfUseStdHandles | StartfUseShowWindow,
                    wShowWindow = SwHide,
                    hStdInput = stdin,
                    hStdOutput = stdoutWrite,
                    hStdError = stderrWrite,
                    lpDesktop = desktopPointer
                },
                lpAttributeList = attributeList
            };

            var commandLine = new StringBuilder("\"" + executable.Replace("\"", "\\\"") + "\" " + flag);
            if (!Native.CreateProcess(executable, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                    CreateSuspended | CreateNoWindow | CreateUnicodeEnvironment | ExtendedStartupInfo, environment, probeTemp, ref startup, out var info))
            {
                var error = Marshal.GetLastWin32Error();
                return Attempt.Failed(StartError(error), error);
            }

            process = info.hProcess;
            thread = info.hThread;
            var processId = info.dwProcessId;
            if (!Native.AssignProcessToJobObject(job, process))
            {
                Native.TerminateProcess(process, 1);
                return Attempt.Failed("The process could not be contained, so it was stopped before it ran. Nothing was installed.");
            }

            var stdoutHandle = stdoutRead;
            var stderrHandle = stderrRead;
            stdoutTask = Task.Run(() => ReadPipe(stdoutHandle));
            stderrTask = Task.Run(() => ReadPipe(stderrHandle));
            stdoutRead = IntPtr.Zero;
            stderrRead = IntPtr.Zero;
            Close(ref stdoutWrite);
            Close(ref stderrWrite);
            Close(ref stdin);

            var uninstallKeys = UninstallKeyCount();
            Native.ResumeThread(thread);
            return Watch(job, process, processId, sandbox, timeout, cancellationToken, stdoutTask, stderrTask, uninstallKeys);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Attempt.Failed("The probe temp folder could not be created. The installer was not run. " + ex.Message);
        }
        finally
        {
            if (job != IntPtr.Zero)
                Native.TerminateJobObject(job, 1);
            if (process != IntPtr.Zero)
                Native.TerminateProcess(process, 1);
            Close(ref stdoutWrite);
            Close(ref stderrWrite);
            Close(ref stdin);
            Close(ref stdoutRead);
            Close(ref stderrRead);
            if (attributeList != IntPtr.Zero)
            {
                if (attributesReady)
                    Native.DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }

            if (capabilities != IntPtr.Zero)
                Marshal.FreeHGlobal(capabilities);
            if (handles.IsAllocated)
                handles.Free();
            Close(ref thread);
            Close(ref process);
            if (job != IntPtr.Zero)
                Native.CloseHandle(job);
            if (desktopPointer != IntPtr.Zero)
                Marshal.FreeHGlobal(desktopPointer);
            if (environment != IntPtr.Zero)
                Marshal.FreeHGlobal(environment);
            DeleteCopy(copyDirectory);
            DeleteCopy(probeTemp);
        }
    }

    private static string CreateProbeTemp(bool lowIntegrity, ProbeSandbox sandbox)
    {
        var root = lowIntegrity
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow", "InstallAnalyzer")
            : !string.IsNullOrWhiteSpace(sandbox.PackageFolder)
                ? sandbox.PackageFolder!
                : Path.Combine(Path.GetTempPath(), "InstallAnalyzer", "probe");
        var directory = Path.Combine(root, Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(directory);
        if (lowIntegrity)
            MarkLowIntegrity(directory);
        else if (sandbox.Sid != IntPtr.Zero)
            ProbeSandbox.GrantFull(directory, sandbox.Sid);
        return directory;
    }

    private static IntPtr EnvironmentWithTemp(string temp)
    {
        var entries = new List<string>();
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            var key = entry.Key?.ToString();
            if (string.IsNullOrEmpty(key))
                continue;
            if (key.Equals("TEMP", StringComparison.OrdinalIgnoreCase) || key.Equals("TMP", StringComparison.OrdinalIgnoreCase))
                continue;
            var value = entry.Value?.ToString() ?? "";
            if (value.Contains('\0'))
                continue;
            entries.Add(key + "=" + value);
        }

        entries.Add("TEMP=" + temp);
        entries.Add("TMP=" + temp);
        return Marshal.StringToHGlobalUni(string.Join('\0', entries) + "\0\0");
    }

    private static void MarkLowIntegrity(string path)
    {
        if (!Native.ConvertStringSidToSid("S-1-16-4096", out var sid))
            return;
        try
        {
            ApplyLowLabel(sid, acl => Native.SetNamedSecurityInfo(path, 1, 0x10, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, acl));
        }
        finally
        {
            Native.LocalFree(sid);
        }
    }

    private static bool MarkLowIntegrityObject(IntPtr handle)
    {
        if (!Native.ConvertStringSidToSid("S-1-16-4096", out var sid))
            return false;
        try
        {
            var applied = false;
            ApplyLowLabel(sid, acl =>
            {
                applied = Native.SetSecurityInfo(handle, 3, 0x10, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, acl) == 0;
            });
            return applied;
        }
        finally
        {
            Native.LocalFree(sid);
        }
    }

    private static void ApplyLowLabel(IntPtr sid, Action<IntPtr> apply)
    {
        var aclSize = 256 + (int)Native.GetLengthSid(sid);
        var acl = Marshal.AllocHGlobal(aclSize);
        try
        {
            if (!Native.InitializeAcl(acl, (uint)aclSize, 2) || !Native.AddMandatoryAce(acl, 2, 0x3, 0x1, sid))
                return;
            apply(acl);
        }
        finally
        {
            Marshal.FreeHGlobal(acl);
        }
    }

    private static void DeleteCopy(string? copyDirectory)
    {
        if (copyDirectory is null)
            return;
        try
        {
            if (Directory.Exists(copyDirectory))
                Directory.Delete(copyDirectory, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static Attempt Watch(
        IntPtr job,
        IntPtr process,
        int processId,
        ProbeSandbox sandbox,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        Task<string> stdoutTask,
        Task<string> stderrTask,
        int uninstallKeys)
    {
        var deadline = Environment.TickCount64 + Math.Clamp((long)timeout.TotalMilliseconds, 500, 5000);
        long? windowSince = null;
        var stopped = false;
        var sawHelp = false;
        var uiText = "";
        var timedOut = false;

        while (Environment.TickCount64 < deadline && !cancellationToken.IsCancellationRequested)
        {
            var waited = Native.WaitForSingleObject(process, 50);
            var scan = ScanWindows(job, processId, sandbox.Desktop);
            if (!string.IsNullOrWhiteSpace(scan.Text))
                uiText = scan.Text;

            if (HelpTextParser.LooksLikeHelp(scan.Text))
            {
                sawHelp = true;
                break;
            }

            if (HelpTextParser.LooksLikeWizard(scan.Text) || UninstallKeyCount() > uninstallKeys)
            {
                stopped = true;
                break;
            }

            if (scan.OnUserDesktop || scan.AnyWindow)
            {
                windowSince ??= Environment.TickCount64;
                var grace = scan.OnUserDesktop ? 200 : 500;
                if (Environment.TickCount64 - windowSince > grace)
                {
                    stopped = true;
                    break;
                }
            }

            if (waited != WaitTimeout)
                break;
        }

        if (Environment.TickCount64 >= deadline || cancellationToken.IsCancellationRequested)
            timedOut = true;

        Native.TerminateJobObject(job, 1);
        Native.TerminateProcess(process, 1);
        Native.WaitForSingleObject(process, 2000);

        var stdout = WaitText(stdoutTask);
        var stderr = WaitText(stderrTask);
        var combined = string.Join("\n", new[] { stdout, stderr, uiText }.Where(part => !string.IsNullOrWhiteSpace(part))).Trim();
        if (!sawHelp && HelpTextParser.LooksLikeHelp(combined))
            sawHelp = true;
        if (!sawHelp && (stopped || HelpTextParser.LooksLikeWizard(combined)))
        {
            return new Attempt { StoppedInstaller = true, TimedOut = timedOut };
        }

        return new Attempt
        {
            Text = sawHelp ? combined : "",
            StoppedInstaller = stopped,
            TimedOut = timedOut && !sawHelp
        };
    }

    private static string PrepareExecutable(string filePath, ProbeSandbox sandbox, ref string? copyDirectory)
    {
        var full = Path.GetFullPath(filePath);
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrEmpty(windows) && full.StartsWith(windows, StringComparison.OrdinalIgnoreCase))
            return full;

        var root = sandbox.PackageFolder;
        if (string.IsNullOrWhiteSpace(root))
            root = Path.Combine(Path.GetTempPath(), "InstallAnalyzer", "probe");
        copyDirectory = Path.Combine(root, Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(copyDirectory);
        var destination = Path.Combine(copyDirectory, Path.GetFileName(full));
        File.Copy(full, destination, overwrite: true);
        ProbeSandbox.GrantReadExecute(copyDirectory, sandbox.Sid, directory: true);
        ProbeSandbox.GrantReadExecute(destination, sandbox.Sid, directory: false);
        return destination;
    }

    private static bool ConfigureJob(IntPtr job)
    {
        var info = new Native.JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new Native.JobObjectBasicLimitInformation
            {
                LimitFlags = KillOnJobClose | ActiveProcessLimit,
                ActiveProcessLimit = 4
            }
        };
        var size = Marshal.SizeOf<Native.JobObjectExtendedLimitInformation>();
        var pointer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(info, pointer, false);
            if (!Native.SetInformationJobObject(job, JobObjectExtendedLimitInformation, pointer, (uint)size))
                return false;
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }

        var rate = new Native.NetRateControl
        {
            MaxBandwidth = 0,
            ControlFlags = 0x1 | 0x2
        };
        var rateSize = Marshal.SizeOf<Native.NetRateControl>();
        var ratePointer = Marshal.AllocHGlobal(rateSize);
        try
        {
            Marshal.StructureToPtr(rate, ratePointer, false);
            Native.SetInformationJobObject(job, JobObjectNetRateControlInformation, ratePointer, (uint)rateSize);
        }
        finally
        {
            Marshal.FreeHGlobal(ratePointer);
        }

        return true;
    }

    private static WindowScan ScanWindows(IntPtr job, int processId, IntPtr desktop)
    {
        var ids = JobProcessIds(job);
        if (!ids.Contains(processId))
            ids.Add(processId);
        var text = new StringBuilder();
        var any = false;
        var onUser = false;
        Collect(desktop, ids, text, ref any);
        if (desktop != IntPtr.Zero)
        {
            var userAny = false;
            Collect(IntPtr.Zero, ids, text, ref userAny);
            onUser = userAny;
            any |= userAny;
        }
        else
        {
            onUser = any;
        }

        return new WindowScan(text.ToString(), any, onUser);
    }

    private static void Collect(IntPtr desktop, HashSet<int> ids, StringBuilder text, ref bool any)
    {
        var idsCopy = ids;
        var builder = text;
        var found = false;
        Native.EnumProc callback = (hwnd, _) =>
        {
            Native.GetWindowThreadProcessId(hwnd, out var pid);
            if (!idsCopy.Contains((int)pid))
                return true;
            found = true;
            AppendWindow(hwnd, builder);
            Native.EnumChildWindows(hwnd, (child, _) =>
            {
                AppendWindow(child, builder);
                return true;
            }, IntPtr.Zero);
            return true;
        };
        if (desktop == IntPtr.Zero)
            Native.EnumWindows(callback, IntPtr.Zero);
        else
            Native.EnumDesktopWindows(desktop, callback, IntPtr.Zero);
        GC.KeepAlive(callback);
        any = found;
    }

    private static void AppendWindow(IntPtr hwnd, StringBuilder text)
    {
        var title = new StringBuilder(512);
        if (Native.GetWindowText(hwnd, title, title.Capacity) > 0 && text.Length < 16000)
        {
            text.AppendLine(title.ToString());
        }
    }

    private static HashSet<int> JobProcessIds(IntPtr job)
    {
        var ids = new HashSet<int>();
        var buffer = Marshal.AllocHGlobal(512);
        try
        {
            if (!Native.QueryInformationJobObject(job, JobObjectBasicProcessIdList, buffer, 512, out _))
                return ids;
            var count = Marshal.ReadInt32(buffer, 4);
            for (var i = 0; i < count && i < 32; i++)
            {
                var value = IntPtr.Size == 8
                    ? Marshal.ReadInt64(buffer, 8 + (i * 8))
                    : Marshal.ReadInt32(buffer, 8 + (i * 4));
                ids.Add((int)value);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return ids;
    }

    private static int UninstallKeyCount()
    {
        var count = 0;
        foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            foreach (var path in new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            })
            {
                try
                {
                    using var key = hive.OpenSubKey(path);
                    count += key?.SubKeyCount ?? 0;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                {
                }
            }
        }

        return count;
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
            return task.Wait(TimeSpan.FromSeconds(2)) ? task.Result : "";
        }
        catch (AggregateException)
        {
            return "";
        }
    }

    private static string StartError(int error) => error switch
    {
        ErrorElevationRequired => "Windows asked for administrator approval, so the help query was not started.",
        ErrorIllegalDllRelocation => "Windows refused to load this installer in the AppContainer because it has no relocation table. The low-integrity probe also failed. The installer was not run.",
        _ => "The sandboxed help process could not be started (" + error + "). The installer was not run outside the sandbox."
    };

    private static bool LowerIntegrity(IntPtr process)
    {
        if (!Native.OpenProcessToken(process, TokenAdjustDefault | TokenQuery, out var token))
            return false;
        try
        {
            if (!Native.ConvertStringSidToSid("S-1-16-4096", out var sid))
                return false;
            try
            {
                var label = new Native.MandatoryLabel
                {
                    Sid = sid,
                    Attributes = SeGroupIntegrity
                };
                var size = Marshal.SizeOf<Native.MandatoryLabel>();
                var memory = Marshal.AllocHGlobal(size);
                try
                {
                    Marshal.StructureToPtr(label, memory, false);
                    return Native.SetTokenInformation(token, TokenIntegrityLevel, memory, (uint)size);
                }
                finally
                {
                    Marshal.FreeHGlobal(memory);
                }
            }
            finally
            {
                Native.LocalFree(sid);
            }
        }
        finally
        {
            Native.CloseHandle(token);
        }
    }

    private static Attempt CopyRelaxed(Attempt attempt) => new()
    {
        Text = attempt.Text,
        Error = attempt.Error,
        StartFailed = attempt.StartFailed,
        StoppedInstaller = attempt.StoppedInstaller,
        TimedOut = attempt.TimedOut,
        Win32Error = attempt.Win32Error,
        RelaxedSandbox = true
    };

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
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            handle = IntPtr.Zero;
            return;
        }

        Native.CloseHandle(handle);
        handle = IntPtr.Zero;
    }

    private sealed class Attempt
    {
        public string Text { get; init; } = "";
        public string? Error { get; init; }
        public bool StartFailed { get; init; }
        public bool StoppedInstaller { get; init; }
        public bool TimedOut { get; init; }
        public bool RelaxedSandbox { get; init; }
        public int Win32Error { get; init; }

        public static Attempt Failed(string error, int win32 = 0) => new() { StartFailed = true, Error = error, Win32Error = win32 };
    }

    private readonly record struct WindowScan(string Text, bool AnyWindow, bool OnUserDesktop);

    private static class Native
    {
        internal delegate bool EnumProc(IntPtr hwnd, IntPtr lparam);

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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct StartupInfoEx
        {
            public StartupInfo StartupInfo;
            public IntPtr lpAttributeList;
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
        internal struct MandatoryLabel
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecurityCapabilities
        {
            public IntPtr AppContainerSid;
            public IntPtr Capabilities;
            public uint CapabilityCount;
            public uint Reserved;
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

        [StructLayout(LayoutKind.Sequential)]
        internal struct NetRateControl
        {
            public ulong MaxBandwidth;
            public uint ControlFlags;
            public byte DscpTag;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateProcessW", SetLastError = true)]
        internal static extern bool CreateProcessSimple(
            string application,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            uint flags,
            IntPtr environment,
            string? directory,
            ref StartupInfo startup,
            out ProcessInformation information);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool SetTokenInformation(IntPtr token, int informationClass, IntPtr information, uint length);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool ConvertStringSidToSid(string sid, out IntPtr sidPointer);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern uint GetLengthSid(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool InitializeAcl(IntPtr acl, uint length, uint revision);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool AddMandatoryAce(IntPtr acl, uint revision, uint flags, uint policy, IntPtr sid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint SetNamedSecurityInfo(string name, uint objectType, uint securityInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern uint SetSecurityInfo(IntPtr handle, uint objectType, uint securityInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr LocalFree(IntPtr memory);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CreateProcess(
            string application,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            uint flags,
            IntPtr environment,
            string? directory,
            ref StartupInfoEx startup,
            out ProcessInformation information);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

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
        internal static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length, out uint returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount, int flags, ref IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

        [DllImport("user32.dll")]
        internal static extern bool EnumWindows(EnumProc callback, IntPtr lparam);

        [DllImport("user32.dll")]
        internal static extern bool EnumDesktopWindows(IntPtr desktop, EnumProc callback, IntPtr lparam);

        [DllImport("user32.dll")]
        internal static extern bool EnumChildWindows(IntPtr parent, EnumProc callback, IntPtr lparam);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        internal static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int max);

        [DllImport("user32.dll")]
        internal static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);
    }
}
