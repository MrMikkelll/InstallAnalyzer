using System.IO.Compression;
using System.Text;

namespace InstallAnalyzer.Core.Unpack;

public sealed class CabExtraction
{
    public required IReadOnlyList<string> Files { get; init; }
    public string? Error { get; init; }
}

public static class CabExtractor
{
    public static bool IsCabinet(ReadOnlySpan<byte> header) =>
        header.Length >= 4
        && header[0] == (byte)'M'
        && header[1] == (byte)'S'
        && header[2] == (byte)'C'
        && header[3] == (byte)'F';

    public static CabExtraction Extract(string cabPath, string destinationDirectory, long maxBytes)
    {
        try
        {
            using var stream = File.OpenRead(cabPath);
            return Extract(stream, destinationDirectory, maxBytes);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return new CabExtraction { Files = [], Error = ex.Message };
        }
    }

    public static CabExtraction Extract(Stream stream, string destinationDirectory, long maxBytes)
    {
        var files = new List<string>();
        try
        {
            if (!stream.CanSeek)
                return new CabExtraction { Files = files, Error = "Cabinet stream cannot be read." };

            Span<byte> header = stackalloc byte[36];
            stream.Position = 0;
            if (stream.Read(header) < header.Length || !IsCabinet(header))
                return new CabExtraction { Files = files, Error = "Not a cabinet." };

            var fileTable = BitConverter.ToUInt32(header[16..]);
            var minor = header[24];
            var major = header[25];
            var folderCount = BitConverter.ToUInt16(header[26..]);
            var fileCount = BitConverter.ToUInt16(header[28..]);
            var flags = BitConverter.ToUInt16(header[30..]);
            if (major != 1 || minor is not 3 and not 1 || folderCount > 64 || fileCount > 4096)
                return new CabExtraction { Files = files, Error = "Unsupported cabinet header." };

            var reservedHeader = 0;
            byte reservedFolder = 0;
            byte reservedData = 0;
            var cursor = 36;
            if ((flags & 0x0004) != 0)
            {
                Span<byte> reserve = stackalloc byte[4];
                if (!ReadExactly(stream, cursor, reserve))
                    return new CabExtraction { Files = files, Error = "Truncated cabinet reserve header." };
                reservedHeader = BitConverter.ToUInt16(reserve);
                reservedFolder = reserve[2];
                reservedData = reserve[3];
                cursor += 4 + reservedHeader;
            }

            if ((flags & 0x0001) != 0 || (flags & 0x0002) != 0)
                return new CabExtraction { Files = files, Error = "Spanned cabinets are not extracted." };

            var folders = new List<CabFolder>(folderCount);
            for (var i = 0; i < folderCount; i++)
            {
                var folderBytes = new byte[8 + reservedFolder];
                if (!ReadExactly(stream, cursor, folderBytes))
                    return new CabExtraction { Files = files, Error = "Truncated cabinet folder." };
                folders.Add(new CabFolder(
                    BitConverter.ToUInt32(folderBytes, 0),
                    BitConverter.ToUInt16(folderBytes, 4),
                    BitConverter.ToUInt16(folderBytes, 6)));
                cursor += folderBytes.Length;
            }

            if (fileTable > cursor)
                cursor = (int)fileTable;

            var entries = new List<CabFile>(fileCount);
            for (var i = 0; i < fileCount; i++)
            {
                var fixedPart = new byte[16];
                if (!ReadExactly(stream, cursor, fixedPart))
                    return new CabExtraction { Files = files, Error = "Truncated cabinet file entry." };
                cursor += 16;
                var name = ReadCString(stream, ref cursor);
                if (string.IsNullOrWhiteSpace(name))
                    continue;
                entries.Add(new CabFile(
                    BitConverter.ToUInt32(fixedPart, 0),
                    BitConverter.ToUInt32(fixedPart, 4),
                    BitConverter.ToUInt16(fixedPart, 8),
                    Path.GetFileName(name.Replace('\\', '/'))));
            }

            var folderData = new Dictionary<int, byte[]>();
            long written = 0;
            Directory.CreateDirectory(destinationDirectory);
            foreach (var entry in entries)
            {
                if (entry.FolderIndex >= 0xFFFD || entry.FolderIndex >= folders.Count)
                    continue;
                if (!folderData.TryGetValue(entry.FolderIndex, out var data))
                {
                    data = InflateFolder(stream, folders[entry.FolderIndex], reservedData);
                    folderData[entry.FolderIndex] = data;
                }

                if (entry.Offset > data.Length || entry.Size > data.Length - entry.Offset)
                    continue;
                if (entry.Size > maxBytes || written + entry.Size > maxBytes)
                    continue;

                var safeName = string.IsNullOrWhiteSpace(entry.Name) ? "payload.bin" : entry.Name;
                var target = UniquePath(destinationDirectory, safeName);
                File.WriteAllBytes(target, data.AsSpan((int)entry.Offset, (int)entry.Size).ToArray());
                written += entry.Size;
                files.Add(target);
            }

            return new CabExtraction { Files = files };
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or ArgumentException)
        {
            return new CabExtraction { Files = files, Error = ex.Message };
        }
    }

    private static byte[] InflateFolder(Stream stream, CabFolder folder, byte reservedData)
    {
        using var output = new MemoryStream();
        var cursor = (long)folder.DataOffset;
        for (var i = 0; i < folder.DataBlocks; i++)
        {
            var prefix = new byte[8 + reservedData];
            if (!ReadExactly(stream, cursor, prefix))
                break;
            var compressed = BitConverter.ToUInt16(prefix, 4);
            var uncompressed = BitConverter.ToUInt16(prefix, 6);
            cursor += prefix.Length;
            var payload = new byte[compressed];
            if (!ReadExactly(stream, cursor, payload))
                break;
            cursor += compressed;

            if (folder.Compression == 0)
            {
                output.Write(payload);
                continue;
            }

            if (folder.Compression == 1)
            {
                output.Write(InflateMsZip(payload, uncompressed));
                continue;
            }

            throw new InvalidDataException($"Cabinet compression {folder.Compression} is not supported.");
        }

        return output.ToArray();
    }

    private static byte[] InflateMsZip(byte[] payload, int expected)
    {
        if (payload.Length < 2 || payload[0] != (byte)'C' || payload[1] != (byte)'K')
            throw new InvalidDataException("MSZIP block is missing its signature.");

        using var input = new MemoryStream(payload, 2, payload.Length - 2, writable: false);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream(expected > 0 ? expected : 0);
        deflate.CopyTo(output);
        return output.ToArray();
    }

    private static string ReadCString(Stream stream, ref int cursor)
    {
        var bytes = new List<byte>();
        while (cursor < stream.Length)
        {
            stream.Position = cursor++;
            var value = stream.ReadByte();
            if (value <= 0)
                break;
            bytes.Add((byte)value);
            if (bytes.Count > 512)
                break;
        }

        return Encoding.ASCII.GetString(bytes.ToArray());
    }

    private static bool ReadExactly(Stream stream, long offset, Span<byte> buffer)
    {
        if (offset < 0 || offset + buffer.Length > stream.Length)
            return false;
        stream.Position = offset;
        var read = 0;
        while (read < buffer.Length)
        {
            var n = stream.Read(buffer[read..]);
            if (n == 0)
                return false;
            read += n;
        }

        return true;
    }

    private static bool ReadExactly(Stream stream, long offset, byte[] buffer) =>
        ReadExactly(stream, offset, buffer.AsSpan());

    private static string UniquePath(string directory, string name)
    {
        var candidate = Path.Combine(directory, name);
        if (!File.Exists(candidate))
            return candidate;
        var stem = Path.GetFileNameWithoutExtension(name);
        var ext = Path.GetExtension(name);
        for (var i = 2; i < 1000; i++)
        {
            candidate = Path.Combine(directory, $"{stem}-{i}{ext}");
            if (!File.Exists(candidate))
                return candidate;
        }

        return Path.Combine(directory, Guid.NewGuid().ToString("n") + ext);
    }

    private readonly record struct CabFolder(uint DataOffset, ushort DataBlocks, ushort Compression);
    private readonly record struct CabFile(uint Size, uint Offset, ushort FolderIndex, string Name);
}
