namespace BinaryAdvisor.Models;

public sealed class FileMetadata
{
    public string FullPath { get; init; } = string.Empty;
    public string FileName { get; init; } = string.Empty;
    public string Directory { get; init; } = string.Empty;
    public string FileStem { get; init; } = string.Empty;
    public string Extension { get; init; } = string.Empty;
    public long SizeBytes { get; init; }
    public string FormattedSize { get; init; } = string.Empty;
    public string Md5 { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public string FileType { get; set; } = "Unknown";

    public static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        int unitIndex = 0;
        while (value >= 1024 && unitIndex < units.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }

        return unitIndex == 0
            ? $"{bytes:N0} B"
            : $"{value:F2} {units[unitIndex]} ({bytes:N0} bytes)";
    }
}

public sealed class DieDetectionItem
{
    public string Type { get; init; } = "Signature";
    public string Name { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
    public string Info { get; init; } = string.Empty;
    public string RawString { get; init; } = string.Empty;

    public string DisplayLabel
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(Name))
                parts.Add(Name);
            if (!string.IsNullOrWhiteSpace(Version))
                parts.Add($"v{Version}");
            if (!string.IsNullOrWhiteSpace(Info))
                parts.Add($"[{Info}]");

            return parts.Count > 0 ? string.Join(" ", parts) : RawString;
        }
    }
}

public sealed class DieDetectionGroup
{
    public string FilePart { get; init; } = "Header";
    public string FileType { get; init; } = string.Empty;
    public List<DieDetectionItem> Items { get; init; } = new();

    public string HeaderDisplay => string.IsNullOrWhiteSpace(FileType)
        ? FilePart
        : $"{FileType} — {FilePart}";
}

public sealed class SectionEntropy
{
    public string Name { get; init; } = string.Empty;
    public long Offset { get; init; }
    public long Size { get; init; }
    public double Entropy { get; init; }
    public string Status { get; init; } = "not packed";

    public bool IsHighEntropy => Entropy > 7.2;

    public bool IsPackedStatus =>
        !string.IsNullOrWhiteSpace(Status) &&
        Status.Contains("packed", StringComparison.OrdinalIgnoreCase) &&
        !Status.Contains("not packed", StringComparison.OrdinalIgnoreCase);

    public bool IsWarning => IsHighEntropy || IsPackedStatus;

    public double EntropyPercentage => Math.Clamp(Entropy / 8.0 * 100.0, 0.0, 100.0);

    public string EntropyFormatted => $"{Entropy:F2} / 8.00";

    public string SizeFormatted => FileMetadata.FormatBytes(Size);

    public string StatusBadge => IsHighEntropy
        ? "CAO (> 7.2)"
        : IsPackedStatus
            ? "NÉN / PACKED"
            : Entropy >= 6.8
                ? "ĐÁNG CHÚ Ý"
                : "BÌNH THƯỜNG";
}

public sealed class ScanResult
{
    public required FileMetadata File { get; init; }
    public List<DieDetectionGroup> DetectionGroups { get; init; } = new();
    public double TotalEntropy { get; set; }
    public string OverallPackStatus { get; set; } = "not packed";
    public List<SectionEntropy> Sections { get; init; } = new();
    public bool UsedNativeFallback { get; set; }
    public string ScannerNotice { get; set; } = string.Empty;
    public TimeSpan ScanDuration { get; set; }

    public IEnumerable<DieDetectionItem> AllDetections =>
        DetectionGroups.SelectMany(g => g.Items);
}
