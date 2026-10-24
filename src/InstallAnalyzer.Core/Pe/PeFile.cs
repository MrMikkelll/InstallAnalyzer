using System.Text;

namespace InstallAnalyzer.Core.Pe;

public sealed class PeSection
{
    public required string Name { get; init; }
    public uint VirtualSize { get; init; }
    public uint VirtualAddress { get; init; }
    public uint RawSize { get; init; }
    public uint RawPointer { get; init; }
}

public sealed class PeFile : IDisposable
{
    private readonly Stream _stream;
    private readonly bool _ownsStream;

    private PeFile(Stream stream, bool ownsStream)
    {
        _stream = stream;
        _ownsStream = ownsStream;
    }

    public IReadOnlyList<PeSection> Sections { get; private init; } = [];
    public uint ResourceRva { get; private init; }
    public uint ResourceSize { get; private init; }
    public uint CertificateOffset { get; private init; }
    public uint CertificateSize { get; private init; }
    public long Length => _stream.Length;

    public static PeFile? TryOpen(string path)
    {
        FileStream? stream = null;
        try
        {
            stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (TryParse(stream, ownsStream: true, out var pe))
                return pe;
            stream.Dispose();
            return null;
        }
        catch (IOException)
        {
            stream?.Dispose();
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            stream?.Dispose();
            return null;
        }
    }

    public static PeFile? TryParse(byte[] data)
    {
        var stream = new MemoryStream(data, writable: false);
        if (TryParse(stream, ownsStream: true, out var pe))
            return pe;
        stream.Dispose();
        return null;
    }

    public byte[]? ReadSection(string name)
    {
        var section = Sections.FirstOrDefault(item =>
            item.Name.Equals(name, StringComparison.Ordinal));
        if (section is null || section.RawSize == 0)
            return null;
        return ReadAt(section.RawPointer, (int)section.RawSize);
    }

    public byte[]? ReadVersionResource()
    {
        if (ResourceRva == 0)
            return null;

        var root = RvaToOffset(ResourceRva);
        if (root is null)
            return null;

        var data = FindResourceData(root.Value, 16);
        if (data is null || data.Value.Size == 0 || data.Value.Size > 1_000_000)
            return null;

        var offset = RvaToOffset(data.Value.Rva);
        if (offset is null)
            return null;

        return ReadAt(offset.Value, (int)data.Value.Size);
    }

    public void Dispose()
    {
        if (_ownsStream)
            _stream.Dispose();
    }

    private static bool TryParse(Stream stream, bool ownsStream, out PeFile? pe)
    {
        pe = null;
        if (!stream.CanSeek || stream.Length < 0x40)
            return false;

        Span<byte> dos = stackalloc byte[0x40];
        stream.Position = 0;
        if (stream.Read(dos) < dos.Length)
            return false;
        if (dos[0] != (byte)'M' || dos[1] != (byte)'Z')
            return false;

        var lfanew = BitConverter.ToInt32(dos[0x3C..]);
        if (lfanew <= 0 || lfanew > stream.Length - 24)
            return false;

        Span<byte> peSig = stackalloc byte[24];
        stream.Position = lfanew;
        if (stream.Read(peSig) < peSig.Length)
            return false;
        if (peSig[0] != (byte)'P' || peSig[1] != (byte)'E' || peSig[2] != 0 || peSig[3] != 0)
            return false;

        var sectionCount = BitConverter.ToUInt16(peSig[6..]);
        var optionalSize = BitConverter.ToUInt16(peSig[20..]);
        if (sectionCount > 96 || optionalSize > 1024)
            return false;

        var optional = new byte[optionalSize];
        if (optionalSize > 0 && stream.Read(optional) != optional.Length)
            return false;

        uint resourceRva = 0;
        uint resourceSize = 0;
        uint certificateOffset = 0;
        uint certificateSize = 0;
        if (optional.Length >= 2)
        {
            var magic = BitConverter.ToUInt16(optional);
            var dataDirectory = magic switch
            {
                0x10B => 96,
                0x20B => 112,
                _ => -1
            };
            var countOffset = dataDirectory - 4;
            if (dataDirectory > 0 && countOffset >= 0 && optional.Length >= countOffset + 4)
            {
                var directoryCount = BitConverter.ToUInt32(optional, countOffset);
                if (directoryCount > 2 && dataDirectory + (3 * 8) <= optional.Length)
                    ReadDirectory(optional, dataDirectory + (2 * 8), out resourceRva, out resourceSize);
                if (directoryCount > 4 && dataDirectory + (5 * 8) <= optional.Length)
                    ReadDirectory(optional, dataDirectory + (4 * 8), out certificateOffset, out certificateSize);
            }
        }

        var sections = new List<PeSection>(sectionCount);
        var sectionHeader = new byte[40];
        for (var i = 0; i < sectionCount; i++)
        {
            if (stream.Read(sectionHeader) != sectionHeader.Length)
                break;
            var nameBytes = sectionHeader.AsSpan(0, 8);
            var nameLength = nameBytes.IndexOf((byte)0);
            if (nameLength < 0)
                nameLength = 8;
            var name = Encoding.ASCII.GetString(nameBytes[..nameLength]);
            sections.Add(new PeSection
            {
                Name = name,
                VirtualSize = BitConverter.ToUInt32(sectionHeader, 8),
                VirtualAddress = BitConverter.ToUInt32(sectionHeader, 12),
                RawSize = BitConverter.ToUInt32(sectionHeader, 16),
                RawPointer = BitConverter.ToUInt32(sectionHeader, 20)
            });
        }

        pe = new PeFile(stream, ownsStream)
        {
            Sections = sections,
            ResourceRva = resourceRva,
            ResourceSize = resourceSize,
            CertificateOffset = certificateOffset,
            CertificateSize = certificateSize
        };
        return true;
    }

    private static void ReadDirectory(byte[] optional, int offset, out uint rva, out uint size)
    {
        rva = BitConverter.ToUInt32(optional, offset);
        size = BitConverter.ToUInt32(optional, offset + 4);
    }

    private (uint Rva, uint Size)? FindResourceData(long rootFileOffset, ushort typeId)
    {
        var type = FindEntry(rootFileOffset, typeId);
        if (type is null)
            return null;
        return Descend(rootFileOffset, type.Value);
    }

    private (uint Rva, uint Size)? Descend(long rootFileOffset, ResourceEntry entry)
    {
        if (!entry.IsDirectory)
            return ReadDataEntry(rootFileOffset + entry.Offset);

        var directory = rootFileOffset + entry.Offset;
        Span<byte> header = stackalloc byte[16];
        if (!TryRead(directory, header))
            return null;

        var named = BitConverter.ToUInt16(header[12..]);
        var ids = BitConverter.ToUInt16(header[14..]);
        var count = named + ids;
        if (count == 0)
            return null;

        var first = ReadEntry(directory + 16);
        if (first is null)
            return null;
        return Descend(rootFileOffset, first.Value);
    }

    private ResourceEntry? FindEntry(long directoryOffset, ushort id)
    {
        Span<byte> header = stackalloc byte[16];
        if (!TryRead(directoryOffset, header))
            return null;

        var named = BitConverter.ToUInt16(header[12..]);
        var ids = BitConverter.ToUInt16(header[14..]);
        var entrySize = 8;
        var idStart = directoryOffset + 16 + (named * entrySize);
        for (var i = 0; i < ids; i++)
        {
            var entry = ReadEntry(idStart + (i * entrySize));
            if (entry is null)
                return null;
            if (!entry.Value.Named && entry.Value.Id == id)
                return entry;
        }

        return null;
    }

    private ResourceEntry? ReadEntry(long offset)
    {
        Span<byte> bytes = stackalloc byte[8];
        if (!TryRead(offset, bytes))
            return null;

        var name = BitConverter.ToUInt32(bytes);
        var data = BitConverter.ToUInt32(bytes[4..]);
        return new ResourceEntry(
            Named: (name & 0x80000000) != 0,
            Id: (ushort)(name & 0xFFFF),
            IsDirectory: (data & 0x80000000) != 0,
            Offset: data & 0x7FFFFFFF);
    }

    private (uint Rva, uint Size)? ReadDataEntry(long offset)
    {
        Span<byte> bytes = stackalloc byte[16];
        if (!TryRead(offset, bytes))
            return null;
        return (BitConverter.ToUInt32(bytes), BitConverter.ToUInt32(bytes[4..]));
    }

    private uint? RvaToOffset(uint rva)
    {
        foreach (var section in Sections)
        {
            var span = Math.Max(section.VirtualSize, section.RawSize);
            if (rva < section.VirtualAddress || rva >= section.VirtualAddress + span)
                continue;
            var delta = rva - section.VirtualAddress;
            if (delta >= section.RawSize)
                return null;
            return section.RawPointer + delta;
        }

        return null;
    }

    private byte[]? ReadAt(long offset, int size)
    {
        if (offset < 0 || size < 0 || offset > _stream.Length)
            return null;
        if (offset + size > _stream.Length)
            size = (int)(_stream.Length - offset);
        if (size == 0)
            return null;

        var buffer = new byte[size];
        _stream.Position = offset;
        var read = 0;
        while (read < size)
        {
            var n = _stream.Read(buffer, read, size - read);
            if (n == 0)
                break;
            read += n;
        }

        return read == size ? buffer : buffer[..read];
    }

    private bool TryRead(long offset, Span<byte> buffer)
    {
        if (offset < 0 || offset + buffer.Length > _stream.Length)
            return false;
        _stream.Position = offset;
        return _stream.Read(buffer) == buffer.Length;
    }

    private readonly record struct ResourceEntry(bool Named, ushort Id, bool IsDirectory, uint Offset);
}
