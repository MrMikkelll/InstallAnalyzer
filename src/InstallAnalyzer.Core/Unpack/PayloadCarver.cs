using System.IO.Compression;
using InstallAnalyzer.Core.Inspection;
using InstallAnalyzer.Core.Msi;

namespace InstallAnalyzer.Core.Unpack;

public sealed class CarvedFile
{
    public required string Path { get; init; }
    public required string Kind { get; init; }
}

public static class PayloadCarver
{
    private static readonly byte[] Eocd = [0x50, 0x4B, 0x05, 0x06];

    public static IReadOnlyList<CarvedFile> Carve(
        string sourcePath,
        string destinationDirectory,
        FileInspection inspection,
        ref long budget)
    {
        Directory.CreateDirectory(destinationDirectory);
        var carved = new List<CarvedFile>();
        var covered = new List<(long Start, long End)>();
        var index = 0;

        foreach (var container in inspection.BurnContainers)
        {
            if (container.Size <= 0 || container.Size > budget)
                continue;
            var copy = Path.Combine(destinationDirectory, $"burn-{container.Role.ToLowerInvariant()}-{index++}.bin");
            try
            {
                FileRange.Copy(sourcePath, container.Offset, container.Size, copy);
                budget -= container.Size;
                covered.Add((container.Offset, container.Offset + container.Size));
                Absorb(copy, destinationDirectory, carved, ref budget, ref index);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                TryDelete(copy);
            }
        }

        foreach (var offset in inspection.OleOffsets)
        {
            if (offset <= 0 || Inside(offset, covered) || budget < 512)
                continue;
            var length = new FileInfo(sourcePath).Length;
            var size = Math.Min(budget, length - offset);
            if (size < 512)
                continue;
            var header = Read(sourcePath, offset, 512);
            if (!CompoundStorage.LooksLikeOle(header))
                continue;

            var copy = Path.Combine(destinationDirectory, $"embedded-{index++}.msi");
            try
            {
                FileRange.Copy(sourcePath, offset, size, copy);
                if (!CompoundStorage.TryGetClsid(copy, out var clsid)
                    || (clsid != CompoundStorage.MsiClsid && clsid != CompoundStorage.MspClsid))
                {
                    TryDelete(copy);
                    continue;
                }

                if (clsid == CompoundStorage.MspClsid)
                    copy = MoveWithExtension(copy, ".msp");
                budget -= new FileInfo(copy).Length;
                covered.Add((offset, offset + size));
                carved.Add(new CarvedFile { Path = copy, Kind = "installer" });
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                TryDelete(copy);
            }
        }

        var zipAttempts = 0;
        foreach (var offset in inspection.ZipOffsets)
        {
            if (offset <= 0 || Inside(offset, covered) || zipAttempts >= 8 || budget < 64)
                continue;
            zipAttempts++;
            TryCarveZip(sourcePath, offset, destinationDirectory, carved, ref budget, ref index);
        }

        return carved;
    }

    private static void Absorb(string path, string directory, List<CarvedFile> carved, ref long budget, ref int index)
    {
        var header = Read(path, 0, 8);
        if (CabExtractor.IsCabinet(header))
        {
            var extracted = CabExtractor.Extract(path, Path.Combine(directory, $"cab-{index}"), budget);
            foreach (var file in extracted.Files)
            {
                var length = new FileInfo(file).Length;
                if (length > budget)
                {
                    TryDelete(file);
                    continue;
                }

                budget -= length;
                var kind = KindFor(file);
                if (kind is null)
                {
                    TryDelete(file);
                    continue;
                }

                carved.Add(new CarvedFile { Path = file, Kind = kind });
            }

            TryDelete(path);
            return;
        }

        if (CompoundStorage.LooksLikeOle(header)
            && CompoundStorage.TryGetClsid(path, out var clsid)
            && clsid is var _
            && (clsid == CompoundStorage.MsiClsid || clsid == CompoundStorage.MspClsid))
        {
            carved.Add(new CarvedFile { Path = path, Kind = "installer" });
            return;
        }

        TryDelete(path);
    }

    private static void TryCarveZip(
        string source,
        long offset,
        string directory,
        List<CarvedFile> carved,
        ref long budget,
        ref int index)
    {
        var length = new FileInfo(source).Length;
        var window = (int)Math.Min(Math.Min(budget, 64L * 1024 * 1024), length - offset);
        if (window < 22)
            return;

        var buffer = new byte[window];
        using (var stream = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            stream.Position = offset;
            var read = stream.Read(buffer, 0, window);
            if (read < 22)
                return;
            if (read != window)
                buffer = buffer[..read];
        }

        var search = 0;
        var attempts = 0;
        while (attempts < 6)
        {
            var relative = buffer.AsSpan(search).IndexOf(Eocd);
            if (relative < 0 || search + relative + 22 > buffer.Length)
                break;
            var at = search + relative;
            var comment = BitConverter.ToUInt16(buffer, at + 20);
            var end = at + 22 + comment;
            if (end > buffer.Length || end > budget)
            {
                search = at + 1;
                attempts++;
                continue;
            }

            var slice = Path.Combine(directory, $"zip-{index}.zip");
            try
            {
                File.WriteAllBytes(slice, buffer[..end]);
                using var zip = ZipFile.OpenRead(slice);
                var interesting = zip.Entries.Where(IsInterestingEntry).Take(8).ToList();
                if (interesting.Count == 0)
                {
                    TryDelete(slice);
                    search = at + 1;
                    attempts++;
                    continue;
                }

                var outDir = Path.Combine(directory, $"zip-{index}-files");
                Directory.CreateDirectory(outDir);
                foreach (var entry in interesting)
                {
                    if (entry.Length > budget)
                        continue;
                    var name = Path.GetFileName(entry.FullName);
                    if (string.IsNullOrWhiteSpace(name))
                        continue;
                    var target = Path.Combine(outDir, name);
                    entry.ExtractToFile(target, overwrite: true);
                    budget -= new FileInfo(target).Length;
                    var kind = KindFor(target);
                    if (kind is null)
                    {
                        TryDelete(target);
                        continue;
                    }

                    carved.Add(new CarvedFile { Path = target, Kind = kind });
                }

                index++;
                TryDelete(slice);
                return;
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
            {
                TryDelete(slice);
                search = at + 1;
                attempts++;
            }
        }
    }

    private static bool IsInterestingEntry(ZipArchiveEntry entry)
    {
        var name = entry.Name;
        if (string.IsNullOrEmpty(name) || entry.Length <= 0)
            return false;
        if (name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".msp", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".msix", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".appx", StringComparison.OrdinalIgnoreCase)
            || name.Equals("AppxManifest.xml", StringComparison.OrdinalIgnoreCase)
            || name.Equals("AppxBundleManifest.xml", StringComparison.OrdinalIgnoreCase))
            return true;
        return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && entry.Length <= 64L * 1024 * 1024;
    }

    private static string? KindFor(string path)
    {
        var name = Path.GetFileName(path);
        var extension = Path.GetExtension(path);
        if (extension.Equals(".xml", StringComparison.OrdinalIgnoreCase)
            || name.Equals("AppxManifest.xml", StringComparison.OrdinalIgnoreCase)
            || name.Equals("AppxBundleManifest.xml", StringComparison.OrdinalIgnoreCase))
            return "xml";
        if (extension.Equals(".msi", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".msp", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".msix", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".appx", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".msixbundle", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".appxbundle", StringComparison.OrdinalIgnoreCase))
            return "installer";
        return null;
    }

    private static bool Inside(long offset, List<(long Start, long End)> ranges) =>
        ranges.Any(range => offset >= range.Start && offset < range.End);

    private static byte[] Read(string path, long offset, int count)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (offset >= stream.Length)
            return [];
        stream.Position = offset;
        var size = (int)Math.Min(count, stream.Length - offset);
        var buffer = new byte[size];
        stream.ReadExactly(buffer);
        return buffer;
    }

    private static string MoveWithExtension(string path, string extension)
    {
        var target = Path.ChangeExtension(path, extension);
        if (!string.Equals(path, target, StringComparison.OrdinalIgnoreCase))
            File.Move(path, target, overwrite: true);
        return target;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (IOException)
        {
        }
    }
}
