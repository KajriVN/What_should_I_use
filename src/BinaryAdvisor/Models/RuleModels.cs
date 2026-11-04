namespace BinaryAdvisor.Models;

public enum AnalysisStep
{
    UnpackExtract = 1,
    StaticAnalysis = 2,
    DynamicAnalysis = 3
}

public sealed class RulesDatabase
{
    public double HeuristicEntropyThreshold { get; set; } = 7.2;
    public List<RuleDefinition> Rules { get; set; } = new();
    public List<RuleToolSpec> HeuristicRecommendations { get; set; } = new();
    public List<RuleToolSpec> FallbackRecommendations { get; set; } = new();
}

public sealed class RuleDefinition
{
    public string Id { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public int Priority { get; set; } = 3;
    public string Category { get; set; } = "Compiler/Language";
    public RuleMatchCriteria Match { get; set; } = new();
    public string Summary { get; set; } = string.Empty;
    public List<RuleToolSpec> Recommendations { get; set; } = new();

    public string PriorityLabel => Priority switch
    {
        1 => "Ưu tiên 1 • Installer / SFX",
        2 => "Ưu tiên 2 • Packer / Protector",
        _ => "Ưu tiên 3 • Compiler / Ngôn ngữ"
    };
}

public sealed class RuleMatchCriteria
{
    public List<string> Types { get; set; } = new();
    public List<string> Keywords { get; set; } = new();
    public List<string> FileTypes { get; set; } = new();
}

public sealed class RuleToolSpec
{
    public string ToolId { get; set; } = string.Empty;
    public string FallbackName { get; set; } = string.Empty;
    public string FallbackType { get; set; } = "gui";
    public int Step { get; set; } = 2;
    public string Reason { get; set; } = string.Empty;
    public string Warning { get; set; } = string.Empty;
    public List<string> OverrideArgs { get; set; } = new();
}

public sealed class ToolRecommendationCard
{
    public required string ToolId { get; init; }
    public required string ToolName { get; init; }
    public required string ToolType { get; init; } // "gui" or "cli"
    public required AnalysisStep Step { get; init; }
    public required int Priority { get; init; }
    public required string MatchedRuleTitle { get; init; }
    public required string Reason { get; init; }
    public string Warning { get; init; } = string.Empty;
    public required string ExecutablePath { get; init; }
    public required List<string> ResolvedArgs { get; init; }
    public required string CommandPreview { get; init; }
    public required bool IsToolInstalled { get; init; }

    public bool IsGui => string.Equals(ToolType, "gui", StringComparison.OrdinalIgnoreCase);
    public bool IsCli => !IsGui;

    public string StepBadge => Step switch
    {
        AnalysisStep.UnpackExtract => "Bước 1 • Unpack / Extract",
        AnalysisStep.StaticAnalysis => "Bước 2 • Phân tích tĩnh",
        AnalysisStep.DynamicAnalysis => "Bước 3 • Phân tích động",
        _ => "Khuyến nghị"
    };

    public string PriorityBadge => Priority switch
    {
        0 => "Heuristic Alert",
        1 => "Ưu tiên 1 (Installer/SFX)",
        2 => "Ưu tiên 2 (Packer/Protector)",
        _ => "Ưu tiên 3 (Compiler/Runtime)"
    };

    public string PrimaryActionLabel => IsGui
        ? $"Open in {ToolName}"
        : "Run CLI";
}

public sealed class AnalysisPlan
{
    public bool IsSuspectedCustomPacker { get; init; }
    public string HeuristicAlertTitle { get; init; } = string.Empty;
    public string HeuristicAlertDetails { get; init; } = string.Empty;
    public List<RuleDefinition> MatchedRules { get; init; } = new();
    public string PrimaryStrategySummary { get; init; } = string.Empty;
    public List<ToolRecommendationCard> Cards { get; init; } = new();

    public IReadOnlyList<ToolRecommendationCard> Step1Cards =>
        Cards.Where(c => c.Step == AnalysisStep.UnpackExtract).ToList();

    public IReadOnlyList<ToolRecommendationCard> Step2Cards =>
        Cards.Where(c => c.Step == AnalysisStep.StaticAnalysis).ToList();

    public IReadOnlyList<ToolRecommendationCard> Step3Cards =>
        Cards.Where(c => c.Step == AnalysisStep.DynamicAnalysis).ToList();
}
