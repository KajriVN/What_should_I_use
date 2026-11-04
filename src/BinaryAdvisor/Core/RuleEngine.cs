using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using BinaryAdvisor.Models;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace BinaryAdvisor.Core;

public sealed class RuleEngine
{
    private readonly RulesDatabase _database;

    public RuleEngine(RulesDatabase database)
    {
        _database = database ?? new RulesDatabase();
    }

    public static RuleEngine LoadFromFile(string? yamlPath = null)
    {
        string path = yamlPath ?? ConfigManager.GetRulesYamlPath();
        if (File.Exists(path))
        {
            string yamlContent = File.ReadAllText(path, Encoding.UTF8);
            return LoadFromYaml(yamlContent);
        }

        // Auto-extract embedded rules.yaml when running as a standalone copied .exe
        string? embeddedYaml = ConfigManager.ReadEmbeddedResourceText("BinaryAdvisor.Config.rules.yaml");
        if (!string.IsNullOrWhiteSpace(embeddedYaml))
        {
            if (yamlPath is null)
            {
                try
                {
                    string? dir = Path.GetDirectoryName(path);
                    if (!string.IsNullOrWhiteSpace(dir))
                        Directory.CreateDirectory(dir);
                    File.WriteAllText(path, embeddedYaml, Encoding.UTF8);
                }
                catch
                {
                    // Even on read-only media, still load from memory cleanly
                }
            }
            return LoadFromYaml(embeddedYaml);
        }

        return new RuleEngine(new RulesDatabase());
    }

    public static RuleEngine LoadFromYaml(string yamlContent)
    {
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        var db = deserializer.Deserialize<RulesDatabase>(yamlContent) ?? new RulesDatabase();
        return new RuleEngine(db);
    }

    public AnalysisPlan Evaluate(ScanResult scan, ToolsConfig toolsConfig)
    {
        double threshold = _database.HeuristicEntropyThreshold > 0
            ? _database.HeuristicEntropyThreshold
            : 7.2;

        // 1. Match rules and sort by Priority (1: Installer/SFX -> 2: Packer/Protector -> 3: Compiler/Language)
        var matchedRules = _database.Rules
            .Where(rule => IsRuleMatched(rule, scan))
            .OrderBy(rule => rule.Priority)
            .ToList();

        // 2. Evaluate Heuristic Filter (Suspected Custom Packer)
        bool hasRecognizedPackerOrInstaller =
            matchedRules.Any(r => r.Priority is 1 or 2) ||
            HasExplicitDiePackerOrInstaller(scan);

        var highEntropySections = scan.Sections
            .Where(s => s.Entropy > threshold || s.IsPackedStatus)
            .ToList();

        bool isOverallPacked = !string.IsNullOrWhiteSpace(scan.OverallPackStatus) &&
            scan.OverallPackStatus.Contains("packed", StringComparison.OrdinalIgnoreCase) &&
            !scan.OverallPackStatus.Contains("not packed", StringComparison.OrdinalIgnoreCase);

        bool suspectedCustomPacker = !hasRecognizedPackerOrInstaller &&
            (scan.TotalEntropy > threshold || isOverallPacked || highEntropySections.Count > 0);

        string heuristicTitle = string.Empty;
        string heuristicDetails = string.Empty;

        if (suspectedCustomPacker)
        {
            heuristicTitle = "CẢNH BÁO HEURISTIC: Suspected Custom Packer / Encrypted Payload";
            var reasons = new List<string>();
            if (scan.TotalEntropy > threshold)
                reasons.Add($"Tổng Entropy tệp rất cao ({scan.TotalEntropy:F2} > {threshold:F1})");

            if (highEntropySections.Count > 0)
            {
                string secList = string.Join(", ", highEntropySections
                    .Take(4)
                    .Select(s => $"{s.Name} ({s.Entropy:F2}{(s.IsPackedStatus ? ", packed" : "")})"));
                reasons.Add($"Phân vùng nghi ngờ nén/mã hóa: {secList}");
            }
            else if (isOverallPacked)
            {
                reasons.Add("Trạng thái tệp được đánh dấu 'packed'");
            }

            heuristicDetails = $"{string.Join(" • ", reasons)} — nhưng DIE không khớp chữ ký Packer thương mại nào. Khả năng cao tệp dùng Custom Packer, Crypter tự viết hoặc đã xóa chữ ký Header (như sửa magic 'UPX!').";
        }

        // 3. Build deduplicated, ranked Tool Recommendation Cards across Step 1 -> Step 2 -> Step 3
        var cards = new List<ToolRecommendationCard>();
        var seenStepToolKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddSpecs(IEnumerable<RuleToolSpec> specs, int priority, string ruleTitle)
        {
            foreach (RuleToolSpec spec in specs)
            {
                AnalysisStep step = spec.Step switch
                {
                    1 => AnalysisStep.UnpackExtract,
                    3 => AnalysisStep.DynamicAnalysis,
                    _ => AnalysisStep.StaticAnalysis
                };

                string dedupKey = $"{(int)step}:{spec.ToolId}:{spec.FallbackName}";
                if (!seenStepToolKeys.Add(dedupKey))
                    continue;

                cards.Add(BuildCard(spec, step, priority, ruleTitle, scan.File, toolsConfig));
            }
        }

        if (suspectedCustomPacker)
        {
            AddSpecs(_database.HeuristicRecommendations, priority: 0, ruleTitle: "Suspected Custom Packer");
        }

        foreach (RuleDefinition rule in matchedRules)
        {
            AddSpecs(rule.Recommendations, rule.Priority, rule.Title);
        }

        // Evaluate user-defined Custom Tool Rules from tools_config.json
        foreach (var (toolId, toolEntry) in toolsConfig.Tools)
        {
            if (toolEntry.CustomRule is { Enabled: true } customRule &&
                IsCustomToolRuleMatched(customRule, scan))
            {
                var customSpec = new RuleToolSpec
                {
                    ToolId = toolId,
                    FallbackName = toolEntry.Name,
                    FallbackType = toolEntry.Type,
                    Step = Math.Clamp(customRule.Step, 1, 3),
                    Reason = string.IsNullOrWhiteSpace(customRule.Reason)
                        ? "Công cụ tùy chỉnh do người dùng thiết lập cho điều kiện tệp này."
                        : customRule.Reason,
                    Warning = customRule.Warning
                };

                string badgeTitle = customRule.AlwaysRecommend
                    ? "Custom Tool • Luôn hiển thị"
                    : "Custom Rule • Tự cấu hình";

                AddSpecs([customSpec], Math.Clamp(customRule.Priority, 1, 3), badgeTitle);
            }
        }

        if (cards.Count == 0)
        {
            AddSpecs(_database.FallbackRecommendations, priority: 3, ruleTitle: "Khảo sát nhị phân tổng quát");
        }

        // Sort cards cleanly by Step (1 -> 2 -> 3), then Priority (0 -> 1 -> 2 -> 3), then Installed tools first
        var sortedCards = cards
            .OrderBy(c => (int)c.Step)
            .ThenBy(c => c.Priority)
            .ThenByDescending(c => c.IsToolInstalled)
            .ToList();

        string primarySummary = BuildPrimaryStrategySummary(matchedRules, suspectedCustomPacker);

        return new AnalysisPlan
        {
            IsSuspectedCustomPacker = suspectedCustomPacker,
            HeuristicAlertTitle = heuristicTitle,
            HeuristicAlertDetails = heuristicDetails,
            MatchedRules = matchedRules,
            PrimaryStrategySummary = primarySummary,
            Cards = sortedCards
        };
    }

    private static string BuildPrimaryStrategySummary(IReadOnlyList<RuleDefinition> matchedRules, bool suspectedCustomPacker)
    {
        if (matchedRules.Count > 0)
        {
            RuleDefinition top = matchedRules[0];
            if (suspectedCustomPacker)
                return $"[{top.PriorityLabel}] {top.Summary} (Lưu ý thêm: phát hiện mức Entropy cao bất thường, hãy kiểm tra bước Unpack/Overlay trước!)";

            return $"[{top.PriorityLabel}] {top.Summary}";
        }

        if (suspectedCustomPacker)
        {
            return "[Heuristic Priority] Tệp có dấu hiệu nén hoặc mã hóa tùy biến (Suspected Custom Packer). Không nên phân tích tĩnh sâu ngay — hãy kiểm tra Header/Overlay và giải nén động qua API Breakpoint trước.";
        }

        return "Chưa nhận diện được trình biên dịch hoặc trình đóng gói đặc thù. Khuyến nghị khảo sát cấu trúc Header, chuỗi ký tự (FLOSS) và dịch ngược tổng quát.";
    }

    private static bool HasExplicitDiePackerOrInstaller(ScanResult scan)
    {
        string[] packedCategories = ["Packer", "Protector", "Cryptor", "Obfuscator", "Virtualizer", "Installer", "SFX"];
        return scan.AllDetections.Any(item =>
            !string.IsNullOrWhiteSpace(item.Name) &&
            packedCategories.Any(cat => item.Type.Equals(cat, StringComparison.OrdinalIgnoreCase)));
    }

    private static bool IsRuleMatched(RuleDefinition rule, ScanResult scan)
    {
        RuleMatchCriteria criteria = rule.Match;

        // Check FileTypes if specified
        if (criteria.FileTypes.Count > 0)
        {
            bool fileTypeMatches = criteria.FileTypes.Any(ft =>
                scan.File.FileType.StartsWith(ft, StringComparison.OrdinalIgnoreCase) ||
                scan.DetectionGroups.Any(g => g.FileType.Equals(ft, StringComparison.OrdinalIgnoreCase)));

            if (!fileTypeMatches)
                return false;

            // If rule ONLY specifies FileTypes (e.g. ELF rule), match immediately
            if (criteria.Keywords.Count == 0)
                return true;
        }

        if (criteria.Keywords.Count == 0)
            return false;

        foreach (DieDetectionItem item in scan.AllDetections)
        {
            if (criteria.Types.Count > 0)
            {
                bool typeMatched = criteria.Types.Any(t =>
                    item.Type.Contains(t, StringComparison.OrdinalIgnoreCase));
                if (!typeMatched)
                    continue;
            }

            string combinedText = $"{item.Name} {item.Version} {item.Info} {item.RawString}";
            foreach (string keyword in criteria.Keywords)
            {
                if (MatchesKeywordSmart(combinedText, keyword))
                    return true;
            }
        }

        return false;
    }

    private static bool IsCustomToolRuleMatched(CustomToolRule customRule, ScanResult scan)
    {
        if (customRule.AlwaysRecommend)
            return true;

        bool hasFileTypeFilter = customRule.FileTypes.Count > 0;
        bool hasKeywordFilter = customRule.Keywords.Count > 0;

        if (!hasFileTypeFilter && !hasKeywordFilter)
            return false;

        if (hasFileTypeFilter)
        {
            bool fileTypeMatched = customRule.FileTypes.Any(ft =>
                scan.File.FileType.Contains(ft, StringComparison.OrdinalIgnoreCase) ||
                scan.File.Extension.Equals(ft, StringComparison.OrdinalIgnoreCase) ||
                scan.File.Extension.Equals($".{ft.TrimStart('.')}", StringComparison.OrdinalIgnoreCase) ||
                scan.DetectionGroups.Any(g => g.FileType.Contains(ft, StringComparison.OrdinalIgnoreCase)));

            if (!fileTypeMatched)
                return false;
        }

        if (hasKeywordFilter)
        {
            bool keywordMatched = false;
            foreach (string kw in customRule.Keywords)
            {
                if (MatchesKeywordSmart(scan.File.FileType, kw))
                {
                    keywordMatched = true;
                    break;
                }

                foreach (DieDetectionItem item in scan.AllDetections)
                {
                    string combined = $"{item.Type} {item.Name} {item.Version} {item.Info} {item.RawString}";
                    if (MatchesKeywordSmart(combined, kw))
                    {
                        keywordMatched = true;
                        break;
                    }
                }

                if (keywordMatched)
                    break;
            }

            if (!keywordMatched)
                return false;
        }

        return true;
    }

    public static ToolRecommendationCard CreateQuickLaunchCard(
        string toolId,
        ToolEntry entry,
        FileMetadata? currentFile)
    {
        string? resolvedExe = ConfigManager.ResolveExecutablePath(entry.Executable);
        bool isInstalled = resolvedExe is not null;
        string effectiveExe = resolvedExe ?? (!string.IsNullOrWhiteSpace(entry.Executable) ? entry.Executable : $"{toolId}.exe");

        IReadOnlyList<string> rawArgs = entry.Args.Count > 0 ? entry.Args : ["{file}"];
        List<string> expandedArgs = currentFile is not null
            ? rawArgs.Select(a => ExpandPlaceholders(a, currentFile)).ToList()
            : rawArgs.ToList();

        int stepInt = entry.CustomRule?.Step is >= 1 and <= 3 ? entry.CustomRule.Step : 2;
        var step = (AnalysisStep)stepInt;

        return new ToolRecommendationCard
        {
            ToolId = toolId,
            ToolName = string.IsNullOrWhiteSpace(entry.Name) ? toolId : entry.Name,
            ToolType = entry.Type,
            Step = step,
            Priority = entry.CustomRule?.Priority ?? 3,
            MatchedRuleTitle = "Mở nhanh thủ công",
            Reason = entry.CustomRule?.Reason ?? string.Empty,
            Warning = entry.CustomRule?.Warning ?? string.Empty,
            ExecutablePath = effectiveExe,
            ResolvedArgs = expandedArgs,
            CommandPreview = FormatCommandPreview(effectiveExe, expandedArgs),
            IsToolInstalled = isInstalled
        };
    }

    private static bool MatchesKeywordSmart(string hayStack, string keyword)
    {
        if (string.IsNullOrWhiteSpace(hayStack) || string.IsNullOrWhiteSpace(keyword))
            return false;

        // Short purely alphanumeric keywords (like "Go", "MSI", "CAB", "RAR", "UPX") require word boundaries
        bool isShortAlnum = keyword.Length <= 3 && keyword.All(char.IsLetterOrDigit);
        if (isShortAlnum)
        {
            string pattern = $@"(?<![A-Za-z0-9]){Regex.Escape(keyword)}(?![A-Za-z0-9])";
            return Regex.IsMatch(hayStack, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        return hayStack.Contains(keyword, StringComparison.OrdinalIgnoreCase);
    }

    private static ToolRecommendationCard BuildCard(
        RuleToolSpec spec,
        AnalysisStep step,
        int priority,
        string ruleTitle,
        FileMetadata file,
        ToolsConfig toolsConfig)
    {
        ToolEntry? configuredTool = null;
        if (!string.IsNullOrWhiteSpace(spec.ToolId))
            toolsConfig.Tools.TryGetValue(spec.ToolId, out configuredTool);

        string toolName = !string.IsNullOrWhiteSpace(configuredTool?.Name)
            ? configuredTool.Name
            : (!string.IsNullOrWhiteSpace(spec.FallbackName) ? spec.FallbackName : spec.ToolId);

        string toolType = !string.IsNullOrWhiteSpace(configuredTool?.Type)
            ? configuredTool.Type
            : spec.FallbackType;

        string configuredExe = configuredTool?.Executable ?? string.Empty;
        string? resolvedExe = ConfigManager.ResolveExecutablePath(configuredExe);
        bool isInstalled = resolvedExe is not null;

        string effectiveExe = resolvedExe ?? (!string.IsNullOrWhiteSpace(configuredExe) ? configuredExe : $"{spec.ToolId}.exe");

        IReadOnlyList<string> rawArgs = spec.OverrideArgs.Count > 0
            ? spec.OverrideArgs
            : (configuredTool?.Args ?? ["{file}"]);

        List<string> expandedArgs = rawArgs
            .Select(arg => ExpandPlaceholders(arg, file))
            .ToList();

        string preview = FormatCommandPreview(effectiveExe, expandedArgs);

        return new ToolRecommendationCard
        {
            ToolId = spec.ToolId,
            ToolName = toolName,
            ToolType = toolType,
            Step = step,
            Priority = priority,
            MatchedRuleTitle = ruleTitle,
            Reason = spec.Reason,
            Warning = spec.Warning,
            ExecutablePath = effectiveExe,
            ResolvedArgs = expandedArgs,
            CommandPreview = preview,
            IsToolInstalled = isInstalled
        };
    }

    public static string ExpandPlaceholders(string template, FileMetadata file)
    {
        if (string.IsNullOrEmpty(template))
            return string.Empty;

        bool hadPlaceholder = template.Contains("{file", StringComparison.OrdinalIgnoreCase);

        string expanded = template
            .Replace("{file}", file.FullPath, StringComparison.OrdinalIgnoreCase)
            .Replace("{file_dir}", file.Directory.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase)
            .Replace("{file_name}", file.FileName, StringComparison.OrdinalIgnoreCase)
            .Replace("{file_stem}", file.FileStem, StringComparison.OrdinalIgnoreCase)
            .Replace("{file_ext}", file.Extension, StringComparison.OrdinalIgnoreCase);

        // Normalize mixed slashes inside path arguments like "{file_dir}/{file_stem}_unpacked{file_ext}"
        if (hadPlaceholder && Path.DirectorySeparatorChar == '\\')
        {
            expanded = expanded.Replace('/', '\\');
        }

        return expanded;
    }

    public static string FormatCommandPreview(string executable, IReadOnlyList<string> args)
    {
        var sb = new StringBuilder();
        sb.Append(QuoteArgumentIfNeeded(executable));

        foreach (string arg in args)
        {
            sb.Append(' ');
            sb.Append(QuoteArgumentIfNeeded(arg));
        }

        return sb.ToString();
    }

    public static string QuoteArgumentIfNeeded(string value)
    {
        if (string.IsNullOrEmpty(value))
            return "\"\"";

        // Handle flags with embedded paths like -dC:\My Folder\out -> -d"C:\My Folder\out" or quote whole token
        bool needsQuotes = value.Any(ch => char.IsWhiteSpace(ch) || ch is '"' or '&' or '|' or '(' or ')' or '^');
        if (!needsQuotes)
            return value;

        return $"\"{value.Replace("\"", "\\\"")}\"";
    }
}
