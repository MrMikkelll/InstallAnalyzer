namespace InstallAnalyzer.Core.Unpack;

public static class FileRange
{
    public static void Copy(string source, long offset, long count, string destination)
    {
        using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.Read);
        input.Position = offset;
        var buffer = new byte[128 * 1024];
        var left = count;
        while (left > 0)
        {
            var read = input.Read(buffer, 0, (int)Math.Min(buffer.Length, left));
            if (read == 0)
                break;
            output.Write(buffer, 0, read);
            left -= read;
        }
    }
}
