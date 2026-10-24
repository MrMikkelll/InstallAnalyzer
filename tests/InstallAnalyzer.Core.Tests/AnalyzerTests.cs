using System.IO.Compression;
using System.Text;
using InstallAnalyzer.Core.Analysis;
using InstallAnalyzer.Core.Commands;
using InstallAnalyzer.Core.Inspection;
using InstallAnalyzer.Core.Help;
using InstallAnalyzer.Core.Msi;
using InstallAnalyzer.Core.Pe;
using InstallAnalyzer.Core.Unpack;

namespace InstallAnalyzer.Core.Tests;

public class AnalyzerTests
{
    [Fact]
    public void Nsis_uninstall_uses_the_program_files_folder()
    {
        var plan = CommandBuilder.Build(new CommandInput
        {
            FilePath = @"C:\Installers\npp.exe",
            Family = InstallerFamily.Nsis,
            Confidence = Confidence.High,
            InstallDirectory = @"C:\Program Files\Notepad++",
            AlternateInstallDirectory = @"C:\Program Files (x86)\Notepad++",
            UninstallFileName = "uninstall.exe",
            InstallDirectoryEmbedded = true
        });

        Assert.Equal("\"C:\\Program Files\\Notepad++\\uninstall.exe\" /S", plan.Uninstall!.Text);
        Assert.Contains("\"C:\\Program Files (x86)\\Notepad++\\uninstall.exe\" /S", plan.Uninstall.Note);
        Assert.Equal(Confidence.High, plan.Uninstall.Confidence);
    }

    [Fact]
    public void Embedded_install_dir_becomes_the_uninstall_path()
    {
        using var dir = new TempDir();
        var bytes = Prefix("NullsoftInst").Concat(Encoding.Unicode.GetBytes("$PROGRAMFILES64\\Northwind\0")).ToArray();
        var path = dir.Write("Northwind.exe", bytes);
        var report = new InstallerAnalyzer(new AnalyzerOptions { WorkingDirectory = dir.Work }).Analyze(path);
        Assert.Equal(InstallerFamily.Nsis, report.Family);
        Assert.Equal("\"C:\\Program Files\\Northwind\\uninstall.exe\" /S", report.Uninstall!.Text);
        Assert.True(report.InstallDirectoryEmbedded);
    }

    [Fact]
    public void Product_name_fills_a_program_files_uninstall_path()
    {
        var location = InstallLocationFinder.Find(new MemoryStream([0, 0, 0, 0]), InstallerFamily.Nsis, "Notepad++", is64Bit: true);
        Assert.Equal(@"C:\Program Files\Notepad++", location.Directory);
        Assert.Equal(@"C:\Program Files (x86)\Notepad++", location.AlternateDirectory);
        Assert.False(location.Embedded);
        Assert.Equal("uninstall.exe", location.UninstallFileName);

        var x86 = InstallLocationFinder.Find(new MemoryStream([0, 0, 0, 0]), InstallerFamily.Nsis, "Notepad++", is64Bit: false);
        Assert.Equal(@"C:\Program Files (x86)\Notepad++", x86.Directory);
    }

    [Fact]
    public void Help_probe_rejects_install_switches()
    {
        Assert.False(HelpSwitches.IsSafeProbe(""));
        Assert.False(HelpSwitches.IsSafeProbe("/S"));
        Assert.False(HelpSwitches.IsSafeProbe("/silent"));
        Assert.False(HelpSwitches.IsSafeProbe("/quiet"));
        Assert.False(HelpSwitches.IsSafeProbe("/VERYSILENT"));
        Assert.False(HelpSwitches.IsSafeProbe("/qn"));
        Assert.False(HelpSwitches.IsSafeProbe("/c echo /VERYSILENT"));
        Assert.True(HelpSwitches.IsSafeProbe("/?"));
        Assert.True(HelpSwitches.IsSafeProbe("--help"));
        foreach (InstallerFamily family in Enum.GetValues<InstallerFamily>())
        {
            var candidates = HelpSwitches.Candidates(family);
            Assert.NotEmpty(candidates);
            Assert.All(candidates, flag => Assert.True(HelpSwitches.IsSafeProbe(flag)));
            Assert.DoesNotContain(candidates, HelpTextParser.IsKnownSilent);
        }
    }

    [Fact]
    public void Recommends_inno_commands()
    {
        var plan = CommandBuilder.Build(Input(InstallerFamily.InnoSetup, Confidence.High));
        Assert.Equal("\"C:\\Installers\\Setup.exe\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART", plan.Install!.Text);
        Assert.Contains("/LOG=\"%TEMP%\\InstallAnalyzer\\install.log\"", plan.Install.TextWithLog);
        Assert.Equal("unins000.exe /VERYSILENT /NORESTART", plan.Uninstall!.Text);
        Assert.Contains("Try this in a VM.", plan.Install.Note);
    }

    [Fact]
    public void Recommends_msi_commands_with_product_code()
    {
        var plan = CommandBuilder.Build(Input(InstallerFamily.Msi, Confidence.High, productCode: "{4F2A9C1E-7B33-4D18-9A60-1C8E5D27AA01}"));
        Assert.Equal("msiexec /i \"C:\\Installers\\Setup.exe\" /qn /norestart", plan.Install!.Text);
        Assert.Contains("/l*v \"%TEMP%\\InstallAnalyzer\\install.log\"", plan.Install.TextWithLog);
        Assert.Equal("msiexec /x {4F2A9C1E-7B33-4D18-9A60-1C8E5D27AA01} /qn /norestart", plan.Uninstall!.Text);
    }

    [Theory]
    [InlineData(InstallerFamily.Nsis, "/S")]
    [InlineData(InstallerFamily.WixBurn, "/install /quiet /norestart")]
    [InlineData(InstallerFamily.Squirrel, "--silent")]
    [InlineData(InstallerFamily.AdvancedInstaller, "/exenoui /qn /norestart")]
    [InlineData(InstallerFamily.SevenZipSfx, "/S")]
    [InlineData(InstallerFamily.IExpress, "/Q")]
    public void Recommends_family_install_switch(InstallerFamily family, string expected)
    {
        var plan = CommandBuilder.Build(Input(family, Confidence.High));
        Assert.Contains(expected, plan.Install!.Text);
        Assert.Contains("Try this in a VM.", plan.Install.Note);
    }

    [Fact]
    public void Burn_uninstall_uses_the_same_file()
    {
        var plan = CommandBuilder.Build(Input(InstallerFamily.WixBurn, Confidence.High, productCode: "{4F2A9C1E-7B33-4D18-9A60-1C8E5D27AA01}"));
        Assert.Contains("/uninstall /quiet /norestart", plan.Uninstall!.Text);
        Assert.Contains("{4F2A9C1E-7B33-4D18-9A60-1C8E5D27AA01}", plan.Uninstall.Note);
    }

    [Fact]
    public void Recognizes_the_7zip_application_installer()
    {
        using var dir = new TempDir();
        var path = dir.Write("7zip.exe", Prefix("7-Zip Shell Extension"));
        var report = new InstallerAnalyzer().Analyze(path);
        Assert.Equal(InstallerFamily.SevenZipSfx, report.Family);
        Assert.Contains("/S", report.Install!.Text);
        Assert.Contains(@"C:\Program Files\7-Zip\Uninstall.exe", report.Uninstall!.Text);
    }

    [Fact]
    public void Product_name_7zip_gets_silent_commands_without_a_family_signature()
    {
        var plan = CommandBuilder.Build(new CommandInput
        {
            FilePath = @"C:\Installers\7zip.exe",
            Family = InstallerFamily.Unknown,
            Confidence = Confidence.None,
            ProductName = "7-Zip"
        });
        Assert.Contains("/S", plan.Install!.Text);
        Assert.Contains(@"C:\Program Files\7-Zip\Uninstall.exe", plan.Uninstall!.Text);
    }

    [Fact]
    public void Recognizes_sumatra_silent_switches()
    {
        using var dir = new TempDir();
        var path = dir.Write("sumatra.exe", Prefix("SumatraPDF uninstall.exe [/s]"));
        var report = new InstallerAnalyzer().Analyze(path);
        Assert.Contains("-s", report.Install!.Text);
        Assert.Contains(@"SumatraPDF\uninstall.exe", report.Uninstall!.Text);
    }

    [Fact]
    public void Firefox_sfx_uses_the_helper_uninstaller()
    {
        using var dir = new TempDir();
        var path = dir.Write("firefox.exe", Prefix(";!@Install@!UTF-8! Title=\"Mozilla Firefox\""));
        var report = new InstallerAnalyzer().Analyze(path);
        Assert.Equal(InstallerFamily.SevenZipSfx, report.Family);
        Assert.Contains(@"Mozilla Firefox\uninstall\helper.exe", report.Uninstall!.Text);
    }

    [Fact]
    public void Unknown_file_has_no_silent_command()
    {
        using var dir = new TempDir();
        var path = dir.Write("VendorSetup.exe", [0x4D, 0x5A, 0x00, 0x01, 0x02]);
        var report = new InstallerAnalyzer().Analyze(path);
        Assert.Equal(InstallerFamily.Unknown, report.Family);
        Assert.Null(report.Install);
        Assert.Contains("No reliable silent command", report.Advisory);
        Assert.True(report.CanQueryHelp);
    }

    [Fact]
    public void Detects_inno_and_nsis_signatures()
    {
        using var dir = new TempDir();
        var inno = dir.Write("Northwind Setup.exe", Prefix("Inno Setup Setup Data"));
        var nsis = dir.Write("Tool.exe", Prefix("NullsoftInst"));
        var analyzer = new InstallerAnalyzer();
        Assert.Equal(InstallerFamily.InnoSetup, analyzer.Analyze(inno).Family);
        Assert.Equal(InstallerFamily.Nsis, analyzer.Analyze(nsis).Family);
    }

    [Fact]
    public void InstallScript_without_msi_engine_asks_for_a_response_file()
    {
        using var dir = new TempDir();
        var path = dir.Write("setup.exe", Prefix("InstallShield InstallScript"));
        var report = new InstallerAnalyzer().Analyze(path);
        Assert.Equal(InstallerFamily.InstallShield, report.Family);
        Assert.Null(report.Install);
        Assert.Contains("setup.iss", report.Advisory);
    }

    [Fact]
    public void InstallShield_msi_engine_uses_silent_msi_switches()
    {
        using var dir = new TempDir();
        var path = dir.Write("setup.exe", Prefix("InstallShield ISSetup.dll"));
        var report = new InstallerAnalyzer().Analyze(path);
        Assert.Contains("/s /v\"/qn /norestart\"", report.Install!.Text);
    }

    [Fact]
    public void Reads_an_msix_manifest()
    {
        using var dir = new TempDir();
        var path = Path.Combine(dir.Path, "Northwind.msix");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("AppxManifest.xml");
            using var writer = new StreamWriter(entry.Open());
            writer.Write("""
                <?xml version="1.0" encoding="utf-8"?>
                <Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
                  <Identity Name="Northwind" Version="2.4.1.0" Publisher="CN=Northwind" />
                </Package>
                """);
        }

        var report = new InstallerAnalyzer().Analyze(path);
        Assert.Equal(InstallerFamily.Msix, report.Family);
        Assert.Contains("Add-AppxPackage -Path", report.Install!.Text);
        Assert.Contains("Get-AppxPackage -Name \"Northwind\"", report.Uninstall!.Text);
    }

    [Fact]
    public void Carves_an_embedded_msi()
    {
        using var dir = new TempDir();
        var msi = CompoundFileBytes();
        var prefix = new byte[64];
        prefix[0] = (byte)'M';
        prefix[1] = (byte)'Z';
        Encoding.ASCII.GetBytes("Inno Setup Setup Data").CopyTo(prefix, 8);
        var outer = dir.Write("Northwind Setup.exe", prefix.Concat(msi).ToArray());

        var report = new InstallerAnalyzer(new AnalyzerOptions { WorkingDirectory = dir.Work }).Analyze(outer);
        Assert.Equal(InstallerFamily.InnoSetup, report.Family);
        Assert.Contains(report.Payloads, payload => payload.Family == InstallerFamily.Msi);
        Assert.Contains("msiexec /i", report.Payloads[0].Install!.Text);
    }

    [Fact]
    public void Depth_limit_skips_carving()
    {
        using var dir = new TempDir();
        var prefix = new byte[64];
        prefix[0] = (byte)'M';
        prefix[1] = (byte)'Z';
        Encoding.ASCII.GetBytes("Inno Setup Setup Data").CopyTo(prefix, 8);
        var outer = dir.Write("setup.exe", prefix.Concat(CompoundFileBytes()).ToArray());
        var report = new InstallerAnalyzer(new AnalyzerOptions { MaxDepth = 0, WorkingDirectory = dir.Work }).Analyze(outer);
        Assert.Empty(report.Payloads);
    }

    [Fact]
    public void Extracts_a_burn_manifest_from_an_attached_cabinet()
    {
        using var dir = new TempDir();
        var manifest = """
            <?xml version="1.0" encoding="utf-8"?>
            <Bundle>
              <Chain>
                <MsiPackage DisplayName="Northwind" ProductCode="{4F2A9C1E-7B33-4D18-9A60-1C8E5D27AA01}" SourceFile="northwind.msi" />
              </Chain>
            </Bundle>
            """;
        var cab = Cabinet("manifest.xml", Encoding.UTF8.GetBytes(manifest));
        var header = BurnHeader(0x200 + 52, (uint)cab.Length);
        Assert.Equal(52, header.Length);
        var pe = Pe(".wixburn", header);
        var path = dir.Write("bundle.exe", pe.Concat(cab).ToArray());

        var report = new InstallerAnalyzer(new AnalyzerOptions { WorkingDirectory = dir.Work }).Analyze(path);
        Assert.Equal(InstallerFamily.WixBurn, report.Family);
        Assert.Contains("/install /quiet /norestart", report.Install!.Text);
        Assert.Contains("/uninstall /quiet /norestart", report.Uninstall!.Text);
        Assert.Contains(report.Chain, package => package.ProductCode == "{4F2A9C1E-7B33-4D18-9A60-1C8E5D27AA01}");
    }

    [Fact]
    public void Extracts_an_uncompressed_cabinet_file()
    {
        using var dir = new TempDir();
        var cabPath = dir.Write("payload.cab", Cabinet("hi.txt", "hello"u8.ToArray()));
        var extracted = CabExtractor.Extract(cabPath, Path.Combine(dir.Path, "out"), 1024 * 1024);
        Assert.Null(extracted.Error);
        var file = Assert.Single(extracted.Files);
        Assert.Equal("hello", File.ReadAllText(file));
    }

    [Fact]
    public void Parses_help_text_and_promotes_only_a_known_silent_switch()
    {
        var tokens = HelpTextParser.Extract("Usage:\n  /VERYSILENT /DIR=\"C:\\App\" --not-silent /FOO\n");
        Assert.Contains("/VERYSILENT", tokens);
        Assert.Contains("/DIR", tokens);
        Assert.Contains("/FOO", tokens);
        Assert.True(HelpTextParser.IsKnownSilent("/VERYSILENT"));
        Assert.False(HelpTextParser.IsKnownSilent("/DIR"));

        using var dir = new TempDir();
        var path = dir.Write("VendorSetup.exe", [0x4D, 0x5A, 0x10]);
        var report = new InstallerAnalyzer().Analyze(path);
        var updated = InstallerAnalyzer.ApplyHelp(report, new HelpQueryResult
        {
            StandardOutput = "Switches: /VERYSILENT /NORESTART /DIR"
        });
        Assert.Contains("/VERYSILENT", updated.Install!.Text);
        Assert.Contains("/NORESTART", updated.Install.Text);
        Assert.DoesNotContain("/DIR", updated.Install.Text);
        Assert.Equal(Confidence.Low, updated.Install.Confidence);
    }

    [Fact]
    public void Help_text_does_not_replace_a_known_family_command()
    {
        using var dir = new TempDir();
        var path = dir.Write("setup.exe", Prefix("Inno Setup Setup Data"));
        var report = new InstallerAnalyzer().Analyze(path);
        var updated = InstallerAnalyzer.ApplyHelp(report, new HelpQueryResult { StandardOutput = "/S" });
        Assert.Contains("/VERYSILENT", updated.Install!.Text);
        Assert.Contains(updated.Switches, item => item.Flag == "/S" && item.Source == SwitchSource.HelpText);
    }

    [Fact]
    public void Reads_version_strings()
    {
        var blob = VersionBlob();
        var map = VersionResourceReader.Read(blob);
        Assert.Equal("Northwind Desktop", map["ProductName"]);
        Assert.Equal("2.4.1", map["ProductVersion"]);
        Assert.Equal("Northwind Labs", map["CompanyName"]);
    }

    [Fact]
    public void Reads_version_resource_through_a_pe()
    {
        var blob = VersionBlob();
        var resource = ResourceSection(blob);
        var pe = Pe(".rsrc", resource, resourceRva: 0x1000, resourceSize: (uint)resource.Length);
        using var parsed = PeFile.TryParse(pe);
        Assert.NotNull(parsed);
        var data = parsed!.ReadVersionResource();
        Assert.NotNull(data);
        var map = VersionResourceReader.Read(data);
        Assert.Equal("Northwind Desktop", map["ProductName"]);
    }

    private static CommandInput Input(InstallerFamily family, Confidence confidence, string? productCode = null) => new()
    {
        FilePath = @"C:\Installers\Setup.exe",
        Family = family,
        Confidence = confidence,
        ProductCodes = productCode is null ? [] : [productCode],
        Msix = family == InstallerFamily.Msix ? new MsixFacts { Name = "Northwind" } : null
    };

    private static byte[] Prefix(string signature)
    {
        var bytes = new byte[64];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        Encoding.ASCII.GetBytes(signature).CopyTo(bytes, 8);
        return bytes;
    }

    private static byte[] CompoundFileBytes()
    {
        var file = new byte[1024];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(file, 0);
        file[0x1A] = 3;
        file[0x1C] = 0xFE;
        file[0x1D] = 0xFF;
        file[0x1E] = 9;
        file[0x20] = 6;
        var entry = 512;
        Encoding.Unicode.GetBytes("Root Entry").CopyTo(file, entry);
        file[entry + 64] = 22;
        file[entry + 66] = 5;
        CompoundStorage.MsiClsid.ToByteArray().CopyTo(file, entry + 80);
        return file;
    }

    private static byte[] Cabinet(string name, byte[] content)
    {
        var nameBytes = Encoding.ASCII.GetBytes(name);
        var fileStart = 36 + 8;
        var dataStart = fileStart + 16 + nameBytes.Length + 1;
        var total = dataStart + 8 + content.Length;
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(Encoding.ASCII.GetBytes("MSCF"));
        writer.Write(0);
        writer.Write(total);
        writer.Write(0);
        writer.Write(fileStart);
        writer.Write(0);
        writer.Write((byte)3);
        writer.Write((byte)1);
        writer.Write((ushort)1);
        writer.Write((ushort)1);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write(dataStart);
        writer.Write((ushort)1);
        writer.Write((ushort)0);
        writer.Write(content.Length);
        writer.Write(0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write(nameBytes);
        writer.Write((byte)0);
        writer.Write(0);
        writer.Write((ushort)content.Length);
        writer.Write((ushort)content.Length);
        writer.Write(content);
        return stream.ToArray();
    }

    private static byte[] BurnHeader(uint stub, uint containerSize)
    {
        var bytes = new byte[52];
        BitConverter.GetBytes(BurnLayout.Magic).CopyTo(bytes, 0);
        BitConverter.GetBytes(BurnLayout.Version).CopyTo(bytes, 4);
        Guid.Parse("4F2A9C1E-7B33-4D18-9A60-1C8E5D27AA01").ToByteArray().CopyTo(bytes, 8);
        BitConverter.GetBytes(stub).CopyTo(bytes, 24);
        BitConverter.GetBytes(1u).CopyTo(bytes, 40);
        BitConverter.GetBytes(1u).CopyTo(bytes, 44);
        BitConverter.GetBytes(containerSize).CopyTo(bytes, 48);
        return bytes;
    }

    private static byte[] Pe(string sectionName, byte[] section, uint resourceRva = 0, uint resourceSize = 0)
    {
        const int lfanew = 0x80;
        const int optionalSize = 0xE0;
        var sectionTable = lfanew + 24 + optionalSize;
        const int raw = 0x200;
        var file = new byte[raw + section.Length];
        file[0] = (byte)'M';
        file[1] = (byte)'Z';
        BitConverter.GetBytes(lfanew).CopyTo(file, 0x3C);
        file[lfanew] = (byte)'P';
        file[lfanew + 1] = (byte)'E';
        BitConverter.GetBytes((ushort)0x14C).CopyTo(file, lfanew + 4);
        BitConverter.GetBytes((ushort)1).CopyTo(file, lfanew + 6);
        BitConverter.GetBytes((ushort)optionalSize).CopyTo(file, lfanew + 20);
        var optional = lfanew + 24;
        BitConverter.GetBytes((ushort)0x10B).CopyTo(file, optional);
        BitConverter.GetBytes(16u).CopyTo(file, optional + 92);
        if (resourceRva != 0)
        {
            BitConverter.GetBytes(resourceRva).CopyTo(file, optional + 112);
            BitConverter.GetBytes(resourceSize).CopyTo(file, optional + 116);
        }

        var name = new byte[8];
        Encoding.ASCII.GetBytes(sectionName).CopyTo(name, 0);
        name.CopyTo(file, sectionTable);
        BitConverter.GetBytes((uint)section.Length).CopyTo(file, sectionTable + 8);
        BitConverter.GetBytes(0x1000u).CopyTo(file, sectionTable + 12);
        BitConverter.GetBytes((uint)section.Length).CopyTo(file, sectionTable + 16);
        BitConverter.GetBytes((uint)raw).CopyTo(file, sectionTable + 20);
        section.CopyTo(file, raw);
        return file;
    }

    private static byte[] VersionBlob()
    {
        var product = StringEntry("ProductName", "Northwind Desktop");
        var version = StringEntry("ProductVersion", "2.4.1");
        var company = StringEntry("CompanyName", "Northwind Labs");
        var table = Block("040904B0", 1, [], product, version, company);
        var info = Block("StringFileInfo", 1, [], table);
        return Block("VS_VERSION_INFO", 0, new byte[52], info);
    }

    private static byte[] ResourceSection(byte[] blob)
    {
        var section = new byte[0x58 + blob.Length];
        WriteU16(section, 12, 0);
        WriteU16(section, 14, 1);
        WriteU32(section, 16, 16);
        WriteU32(section, 20, 0x80000018);
        WriteU16(section, 0x18 + 14, 1);
        WriteU32(section, 0x28, 1);
        WriteU32(section, 0x2C, 0x80000030);
        WriteU16(section, 0x30 + 14, 1);
        WriteU32(section, 0x40, 0x409);
        WriteU32(section, 0x44, 0x48);
        WriteU32(section, 0x48, 0x1000 + 0x58);
        WriteU32(section, 0x4C, (uint)blob.Length);
        blob.CopyTo(section, 0x58);
        return section;
    }

    private static byte[] StringEntry(string key, string value) =>
        Block(key, 1, Encoding.Unicode.GetBytes(value + "\0"));

    private static byte[] Block(string key, ushort type, byte[] value, params byte[][] children)
    {
        var keyBytes = Encoding.Unicode.GetBytes(key + "\0");
        var valueStart = Align(6 + keyBytes.Length);
        var childAt = Align(valueStart + value.Length);
        var offsets = new int[children.Length];
        for (var i = 0; i < children.Length; i++)
        {
            offsets[i] = childAt;
            childAt = Align(childAt + children[i].Length);
        }

        var length = children.Length == 0 ? Math.Max(valueStart + value.Length, 6) : childAt;
        var buffer = new byte[length];
        WriteU16(buffer, 0, (ushort)length);
        WriteU16(buffer, 2, type == 1 ? (ushort)(value.Length / 2) : (ushort)value.Length);
        WriteU16(buffer, 4, type);
        keyBytes.CopyTo(buffer, 6);
        value.CopyTo(buffer, valueStart);
        for (var i = 0; i < children.Length; i++)
            children[i].CopyTo(buffer, offsets[i]);
        return buffer;
    }

    private static int Align(int value) => (value + 3) & ~3;

    private static void WriteU16(byte[] buffer, int offset, ushort value) =>
        BitConverter.GetBytes(value).CopyTo(buffer, offset);

    private static void WriteU32(byte[] buffer, int offset, uint value) =>
        BitConverter.GetBytes(value).CopyTo(buffer, offset);

    private sealed class TempDir : IDisposable
    {
        public TempDir()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ia-tests", Guid.NewGuid().ToString("n"));
            Work = System.IO.Path.Combine(Path, "work");
            Directory.CreateDirectory(Work);
        }

        public string Path { get; }
        public string Work { get; }

        public string Write(string name, byte[] bytes)
        {
            var path = System.IO.Path.Combine(Path, name);
            File.WriteAllBytes(path, bytes);
            return path;
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}
