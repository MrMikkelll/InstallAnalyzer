namespace InstallAnalyzer.Core.Scanning;

public sealed class Pattern
{
    public required string Id { get; init; }
    public required byte[] Bytes { get; init; }
}

public sealed class ScanResult
{
    public required IReadOnlyList<string> MatchedPatternIds { get; init; }
    public required IReadOnlyDictionary<string, IReadOnlyList<long>> MarkerOffsets { get; init; }
}

public static class PatternScanner
{
    public static ScanResult Scan(
        Stream stream,
        IReadOnlyList<Pattern> patterns,
        IReadOnlyList<Pattern> markers,
        int maxMarkerHits)
    {
        var matched = new HashSet<string>(StringComparer.Ordinal);
        var markerHits = markers.ToDictionary(m => m.Id, _ => new List<long>(), StringComparer.Ordinal);
        var all = new List<Pattern>(patterns.Count + markers.Count);
        all.AddRange(patterns);
        all.AddRange(markers);
        var markerIds = markers.Select(m => m.Id).ToHashSet(StringComparer.Ordinal);

        var maxLength = 1;
        foreach (var pattern in all)
            maxLength = Math.Max(maxLength, pattern.Bytes.Length);

        var keep = maxLength - 1;
        var buffer = new byte[1024 * 1024 + keep];
        var carry = 0;
        long baseOffset = 0;

        while (true)
        {
            var read = stream.Read(buffer, carry, buffer.Length - carry);
            var count = carry + read;
            if (count == 0)
                break;

            var span = buffer.AsSpan(0, count);
            foreach (var pattern in all)
            {
                if (pattern.Bytes.Length == 0 || pattern.Bytes.Length > count)
                    continue;

                var isMarker = markerIds.Contains(pattern.Id);
                if (!isMarker && matched.Contains(pattern.Id))
                    continue;

                var searchFrom = 0;
                while (true)
                {
                    var relative = span[searchFrom..].IndexOf(pattern.Bytes);
                    if (relative < 0)
                        break;

                    var index = searchFrom + relative;
                    if (index >= carry || baseOffset == 0 && carry == 0)
                    {
                        if (isMarker)
                        {
                            var list = markerHits[pattern.Id];
                            if (list.Count < maxMarkerHits)
                                list.Add(baseOffset + index);
                        }
                        else
                        {
                            matched.Add(pattern.Id);
                            break;
                        }
                    }

                    if (!isMarker)
                        break;

                    searchFrom = index + 1;
                    if (searchFrom >= count)
                        break;
                }
            }

            if (read == 0)
                break;

            if (count > keep)
            {
                Buffer.BlockCopy(buffer, count - keep, buffer, 0, keep);
                baseOffset += count - keep;
                carry = keep;
            }
            else
            {
                carry = count;
            }
        }

        return new ScanResult
        {
            MatchedPatternIds = matched.ToList(),
            MarkerOffsets = markerHits.ToDictionary(
                pair => pair.Key,
                pair => (IReadOnlyList<long>)pair.Value,
                StringComparer.Ordinal)
        };
    }
}
