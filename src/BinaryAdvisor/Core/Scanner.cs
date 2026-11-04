using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BinaryAdvisor.Models;

namespace BinaryAdvisor.Core;

public sealed class Scanner
{
    public async Task<ScanResult> ScanFileAsync(
        string filePath,
        string? diecPath,
        IProgress<string>? statusProgress = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("Đường dẫn tệp không được để trống.", nameof(filePath));

        string fullPath = Path.GetFullPath(filePath);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException("Không tìm thấy tệp cần phân tích.", fullPath);

        var sw = Stopwatch.StartNew();

        // Step 1: Stream file once to compute MD5 + SHA256 + File Size (handles >100MB smoothly)
        statusProgress?.Report("Đang tính mã băm MD5 & SHA-256...");
        var (sizeBytes, md5Hex, sha256Hex) = await ComputeHashesStreamingAsync(fullPath, statusProgress, cancellationToken);

        // Step 2: Run Native Inspector quickly so we always have fallback/supplemental section info
        statusProgress?.Report("Đang phân tích cấu trúc Header & Section...");
        var nativeResult = await Task.Run(() => NativeBinaryInspector.Inspect(fullPath, cancellationToken), cancellationToken);

        string? resolvedDiec = ConfigManager.ResolveExecutablePath(diecPath);
        List<DieDetectionGroup> detectionGroups = new();
        List<SectionEntropy> sections = new();
        double totalEntropy = nativeResult.TotalEntropy;
        string packStatus = nativeResult.OverallPackStatus;
        string detectedFileType = nativeResult.FileType;
        bool usedFallback = false;
        string notice = string.Empty;

        if (resolvedDiec is not null)
        {
            statusProgress?.Report("Đang chạy Detect It Easy (diec -d -j & diec -e -j)...");
            try
            {
                Task<string> detectTask = RunDiecCommandAsync(resolvedDiec, ["-d", "-j", fullPath], cancellationToken);
                Task<string> entropyTask = RunDiecCommandAsync(resolvedDiec, ["-e", "-j", fullPath], cancellationToken);

                await Task.WhenAll(detectTask, entropyTask);

                var parsedDetects = ParseDieDetectionsJson(await detectTask);
                if (!string.IsNullOrWhiteSpace(parsedDetects.FileType))
                    detectedFileType = parsedDetects.FileType;

                if (parsedDetects.Groups.Count > 0)
                    detectionGroups = parsedDetects.Groups;

                var parsedEntropy = ParseDieEntropyJson(await entropyTask);
                if (parsedEntropy.HasData)
                {
                    totalEntropy = parsedEntropy.TotalEntropy;
                    if (!string.IsNullOrWhiteSpace(parsedEntropy.OverallStatus))
                        packStatus = parsedEntropy.OverallStatus;
                    if (parsedEntropy.Sections.Count > 0)
                        sections = parsedEntropy.Sections;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                usedFallback = true;
                notice = $"Lỗi khi gọi diec.exe ({ex.Message}) — Đã tự động chuyển sang bộ phân tích nội bộ.";
            }
        }
        else
        {
            usedFallback = true;
            notice = "Chưa tìm thấy diec.exe (hãy cấu hình trong Settings ⚙) — Đang sử dụng bộ phân tích PE/ELF & Entropy nội bộ.";
        }

        if (detectionGroups.Count == 0)
            detectionGroups = nativeResult.DetectionGroups;

        if (sections.Count == 0)
            sections = nativeResult.Sections;

        // Enrich FileType label if .NET is detected inside PE32/PE64
        bool isDotNet = detectionGroups.SelectMany(g => g.Items)
            .Any(i => i.Name.Contains(".NET", StringComparison.OrdinalIgnoreCase) ||
                      i.Name.Contains("MSIL", StringComparison.OrdinalIgnoreCase));

        if (isDotNet && !detectedFileType.Contains(".NET", StringComparison.OrdinalIgnoreCase))
            detectedFileType = $"{detectedFileType} (.NET)";

        sw.Stop();

        var metadata = new FileMetadata
        {
            FullPath = fullPath,
            FileName = Path.GetFileName(fullPath),
            Directory = Path.GetDirectoryName(fullPath) ?? string.Empty,
            FileStem = Path.GetFileNameWithoutExtension(fullPath),
            Extension = Path.GetExtension(fullPath),
            SizeBytes = sizeBytes,
            FormattedSize = FileMetadata.FormatBytes(sizeBytes),
            Md5 = md5Hex,
            Sha256 = sha256Hex,
            FileType = detectedFileType
        };

        return new ScanResult
        {
            File = metadata,
            DetectionGroups = detectionGroups,
            TotalEntropy = totalEntropy,
            OverallPackStatus = packStatus,
            Sections = sections,
            UsedNativeFallback = usedFallback,
            ScannerNotice = notice,
            ScanDuration = sw.Elapsed
        };
    }

    public static async Task<(long SizeBytes, string Md5, string Sha256)> ComputeHashesStreamingAsync(
        string filePath,
        IProgress<string>? statusProgress = null,
        CancellationToken cancellationToken = default)
    {
        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(1024 * 1024); // 1 MB streaming buffer
        try
        {
            await using var fs = new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite,
                bufferSize: 1024 * 1024,
                options: FileOptions.Asynchronous | FileOptions.SequentialScan);

            long totalBytes = fs.Length;
            long processed = 0;
            int lastPercentReported = 0;

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int bytesRead = await fs.ReadAsync(buffer.AsMemory(), cancellationToken);
                if (bytesRead <= 0)
                    break;

                md5.AppendData(buffer, 0, bytesRead);
                sha256.AppendData(buffer, 0, bytesRead);
                processed += bytesRead;

                if (totalBytes >= 20 * 1024 * 1024) // Report % for files >= 20 MB
                {
                    int pct = (int)(processed * 100 / totalBytes);
                    if (pct - lastPercentReported >= 10)
                    {
                        lastPercentReported = pct;
                        statusProgress?.Report($"Đang băm MD5/SHA-256 ({pct}%)...");
                    }
                }
            }

            string md5Hex = Convert.ToHexStringLower(md5.GetHashAndReset());
            string sha256Hex = Convert.ToHexStringLower(sha256.GetHashAndReset());
            return (totalBytes, md5Hex, sha256Hex);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task<string> RunDiecCommandAsync(
        string diecExecutable,
        IReadOnlyList<string> args,
        CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = diecExecutable,
            UseShellExecute = false,
            CreateNoWindow = true, // Prevents black CMD flash on Windows GUI
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        foreach (string arg in args)
            psi.ArgumentList.Add(arg);

        using var process = new Process { StartInfo = psi };
        if (!process.Start())
            throw new InvalidOperationException("Không thể khởi chạy tiến trình diec.exe.");

        using var registration = cancellationToken.Register(() =>
        {
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
            }
            catch
            {
                // Ignore race condition on exit
            }
        });

        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await process.WaitForExitAsync(cancellationToken);
        string stdout = await stdoutTask;
        string stderr = await stderrTask;

        if (string.IsNullOrWhiteSpace(stdout) && !string.IsNullOrWhiteSpace(stderr))
            throw new InvalidOperationException(stderr.Trim());

        return stdout;
    }

    public static (string FileType, List<DieDetectionGroup> Groups) ParseDieDetectionsJson(string rawOutput)
    {
        string json = ExtractJsonObject(rawOutput);
        if (string.IsNullOrWhiteSpace(json))
            return (string.Empty, new List<DieDetectionGroup>());

        using var doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            return (string.Empty, new List<DieDetectionGroup>());

        string topFileType = GetStringProp(root, "filetype");
        var groups = new List<DieDetectionGroup>();

        if (root.TryGetProperty("detects", out JsonElement detectsEl) && detectsEl.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement detectBlock in detectsEl.EnumerateArray())
            {
                if (detectBlock.ValueKind != JsonValueKind.Object)
                    continue;

                string blockFileType = GetStringProp(detectBlock, "filetype");
                if (string.IsNullOrWhiteSpace(topFileType) && !string.IsNullOrWhiteSpace(blockFileType))
                    topFileType = blockFileType;

                string parentPart = GetStringProp(detectBlock, "parentfilepart");
                string groupCategoryType = GetStringProp(detectBlock, "type");

                var items = new List<DieDetectionItem>();
                if (detectBlock.TryGetProperty("values", out JsonElement valuesEl) && valuesEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement val in valuesEl.EnumerateArray())
                    {
                        if (val.ValueKind != JsonValueKind.Object)
                            continue;

                        string itemType = GetStringProp(val, "type");
                        if (string.IsNullOrWhiteSpace(itemType))
                            itemType = string.IsNullOrWhiteSpace(groupCategoryType) ? "Signature" : groupCategoryType;

                        string info = GetStringProp(val, "info");
                        if (string.IsNullOrWhiteSpace(info))
                            info = GetStringProp(val, "options");

                        items.Add(new DieDetectionItem
                        {
                            Type = itemType,
                            Name = GetStringProp(val, "name"),
                            Version = GetStringProp(val, "version"),
                            Info = info,
                            RawString = GetStringProp(val, "string")
                        });
                    }
                }

                if (items.Count > 0)
                {
                    groups.Add(new DieDetectionGroup
                    {
                        FileType = string.IsNullOrWhiteSpace(blockFileType) ? topFileType : blockFileType,
                        FilePart = !string.IsNullOrWhiteSpace(parentPart)
                            ? parentPart
                            : (!string.IsNullOrWhiteSpace(groupCategoryType) ? groupCategoryType : "Header"),
                        Items = items
                    });
                }
            }
        }
        else if (root.TryGetProperty("values", out JsonElement rootValues) && rootValues.ValueKind == JsonValueKind.Array)
        {
            var items = new List<DieDetectionItem>();
            foreach (JsonElement val in rootValues.EnumerateArray())
            {
                if (val.ValueKind != JsonValueKind.Object)
                    continue;

                items.Add(new DieDetectionItem
                {
                    Type = GetStringProp(val, "type", "Signature"),
                    Name = GetStringProp(val, "name"),
                    Version = GetStringProp(val, "version"),
                    Info = GetStringProp(val, "info"),
                    RawString = GetStringProp(val, "string")
                });
            }

            if (items.Count > 0)
            {
                groups.Add(new DieDetectionGroup
                {
                    FileType = topFileType,
                    FilePart = "Header",
                    Items = items
                });
            }
        }

        return (topFileType, groups);
    }

    public static (bool HasData, double TotalEntropy, string OverallStatus, List<SectionEntropy> Sections) ParseDieEntropyJson(string rawOutput)
    {
        string json = ExtractJsonObject(rawOutput);
        if (string.IsNullOrWhiteSpace(json))
            return (false, 0.0, string.Empty, new List<SectionEntropy>());

        using var doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            return (false, 0.0, string.Empty, new List<SectionEntropy>());

        double total = GetDoubleProp(root, "total", GetDoubleProp(root, "entropy", -1.0));
        string status = GetStringProp(root, "status");
        var sections = new List<SectionEntropy>();

        JsonElement recordsEl = default;
        bool hasRecords =
            (root.TryGetProperty("records", out recordsEl) && recordsEl.ValueKind == JsonValueKind.Array) ||
            (root.TryGetProperty("sections", out recordsEl) && recordsEl.ValueKind == JsonValueKind.Array);

        if (hasRecords)
        {
            foreach (JsonElement rec in recordsEl.EnumerateArray())
            {
                if (rec.ValueKind != JsonValueKind.Object)
                    continue;

                double ent = GetDoubleProp(rec, "entropy", 0.0);
                string recStatus = GetStringProp(rec, "status", ent > 7.2 ? "packed" : "not packed");

                sections.Add(new SectionEntropy
                {
                    Name = CleanDieSectionName(GetStringProp(rec, "name", "Section")),
                    Offset = GetLongProp(rec, "offset"),
                    Size = GetLongProp(rec, "size"),
                    Entropy = Math.Round(ent, 4),
                    Status = recStatus
                });
            }
        }

        if (total < 0 && sections.Count > 0)
        {
            long totalSize = sections.Sum(s => Math.Max(s.Size, 1));
            total = sections.Sum(s => s.Entropy * Math.Max(s.Size, 1)) / totalSize;
        }

        bool hasAnyData = total >= 0 || sections.Count > 0;
        return (hasAnyData, Math.Max(0.0, Math.Round(total, 4)), status, sections);
    }

    private static string CleanDieSectionName(string raw)
    {
        // DIE often formats names like: Section(0)['.text'] -> make it cleaner while preserving info
        int quoteStart = raw.IndexOf("['", StringComparison.Ordinal);
        int quoteEnd = raw.LastIndexOf("']", StringComparison.Ordinal);
        if (quoteStart >= 0 && quoteEnd > quoteStart + 2)
        {
            string inner = raw[(quoteStart + 2)..quoteEnd];
            string prefix = raw[..quoteStart].Trim();
            return string.IsNullOrWhiteSpace(prefix) ? inner : $"{inner} ({prefix})";
        }
        return raw;
    }

    private static string ExtractJsonObject(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return string.Empty;

        int firstBrace = raw.IndexOf('{');
        int lastBrace = raw.LastIndexOf('}');
        if (firstBrace >= 0 && lastBrace > firstBrace)
            return raw[firstBrace..(lastBrace + 1)];

        return string.Empty;
    }

    private static string GetStringProp(JsonElement obj, string propName, string fallback = "")
    {
        foreach (JsonProperty prop in obj.EnumerateObject())
        {
            if (prop.Name.Equals(propName, StringComparison.OrdinalIgnoreCase))
            {
                return prop.Value.ValueKind switch
                {
                    JsonValueKind.String => prop.Value.GetString() ?? fallback,
                    JsonValueKind.Number => prop.Value.GetRawText(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    _ => fallback
                };
            }
        }
        return fallback;
    }

    private static double GetDoubleProp(JsonElement obj, string propName, double fallback = 0.0)
    {
        foreach (JsonProperty prop in obj.EnumerateObject())
        {
            if (!prop.Name.Equals(propName, StringComparison.OrdinalIgnoreCase))
                continue;

            if (prop.Value.ValueKind == JsonValueKind.Number && prop.Value.TryGetDouble(out double d))
                return d;

            if (prop.Value.ValueKind == JsonValueKind.String &&
                double.TryParse(prop.Value.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out double parsed))
                return parsed;
        }
        return fallback;
    }

    private static long GetLongProp(JsonElement obj, string propName, long fallback = 0)
    {
        foreach (JsonProperty prop in obj.EnumerateObject())
        {
            if (!prop.Name.Equals(propName, StringComparison.OrdinalIgnoreCase))
                continue;

            if (prop.Value.ValueKind == JsonValueKind.Number && prop.Value.TryGetInt64(out long l))
                return l;

            if (prop.Value.ValueKind == JsonValueKind.String)
            {
                string? s = prop.Value.GetString();
                if (!string.IsNullOrWhiteSpace(s))
                {
                    if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                        long.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long hexVal))
                        return hexVal;

                    if (long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out long decVal))
                        return decVal;
                }
            }
        }
        return fallback;
    }
}
