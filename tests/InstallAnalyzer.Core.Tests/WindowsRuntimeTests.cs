using System.Diagnostics;
using System.Runtime.InteropServices;
using InstallAnalyzer.Core.Analysis;
using InstallAnalyzer.Core.Help;
using InstallAnalyzer.Windows;

namespace InstallAnalyzer.Core.Tests;

public class WindowsRuntimeTests
{
    [Fact]
    public void Reads_msi_properties_and_builds_uninstall_command()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("n") + ".msi");
        try
        {
            CreateDatabase(path);
            var report = new InstallerAnalyzer(new AnalyzerOptions { MsiReader = new WindowsMsiReader() }).Analyze(path);
            Assert.Equal(InstallerFamily.Msi, report.Family);
            Assert.Equal("Northwind Desktop", report.Msi!.ProductName);
            Assert.Contains("{4F2A9C1E-7B33-4D18-9A60-1C8E5D27AA01}", report.Uninstall!.Text, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("INSTALLDIR=C:\\Program Files\\Northwind", report.Switches.Select(item => item.Flag));
        }
        finally
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    [Fact]
    public async Task Help_query_captures_output_and_stops_a_long_process()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var runner = new WindowsHelpQuery();
        var refused = await runner.RunAsync(new HelpQueryRequest
        {
            FilePath = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            Arguments = ["/S", "/c ping -n 30 127.0.0.1"],
            Timeout = TimeSpan.FromSeconds(2)
        }, CancellationToken.None);

        Assert.NotNull(refused.Error);
        Assert.Contains("nothing was run", refused.Error, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Process.GetProcessesByName("PING"), process => !process.HasExited);

        var echo = await runner.RunAsync(new HelpQueryRequest
        {
            FilePath = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            Arguments = ["/?"] ,
            Timeout = TimeSpan.FromSeconds(8)
        }, CancellationToken.None);

        Assert.True(echo.Error is null, echo.Error ?? "");
        Assert.Contains("CMD", echo.StandardOutput, StringComparison.OrdinalIgnoreCase);

        Thread.Sleep(300);
        Assert.DoesNotContain(Process.GetProcessesByName("PING"), process => !process.HasExited);
    }

    private static void CreateDatabase(string path)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var type = Type.GetTypeFromProgID("WindowsInstaller.Installer");
                Assert.NotNull(type);
                dynamic installer = Activator.CreateInstance(type!)!;
                dynamic database = installer.OpenDatabase(path, 3);
                Exec(database, "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE PRIMARY KEY `Property`)");
                Exec(database, "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'Northwind Desktop')");
                Exec(database, "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductVersion', '2.4.1')");
                Exec(database, "INSERT INTO `Property` (`Property`, `Value`) VALUES ('Manufacturer', 'Northwind Labs')");
                Exec(database, "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '{4F2A9C1E-7B33-4D18-9A60-1C8E5D27AA01}')");
                Exec(database, "INSERT INTO `Property` (`Property`, `Value`) VALUES ('UpgradeCode', '{8B1D6E20-1111-4222-8333-555555555555}')");
                Exec(database, "INSERT INTO `Property` (`Property`, `Value`) VALUES ('INSTALLDIR', 'C:\\Program Files\\Northwind')");
                Exec(database, "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ALLUSERS', '1')");
                database.Commit();
                Marshal.ReleaseComObject(database);
                Marshal.ReleaseComObject(installer);
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null)
            throw failure;
    }

    private static void Exec(dynamic database, string sql)
    {
        dynamic view = database.OpenView(sql);
        view.Execute();
        view.Close();
    }
}
