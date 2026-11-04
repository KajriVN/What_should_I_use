using System.Text.Json.Serialization;

namespace BinaryAdvisor.Models;

public sealed class ToolsConfig
{
    [JsonPropertyName("diec_path")]
    public string DiecPath { get; set; } = @"C:/Tools/die_win64_portable/diec.exe";

    [JsonPropertyName("tools")]
    public Dictionary<string, ToolEntry> Tools { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class ToolEntry
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = "gui";

    [JsonPropertyName("executable")]
    public string Executable { get; set; } = string.Empty;

    [JsonPropertyName("args")]
    public List<string> Args { get; set; } = new() { "{file}" };

    [JsonPropertyName("custom_rule")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CustomToolRule? CustomRule { get; set; }

    [JsonIgnore]
    public bool IsGui => string.Equals(Type, "gui", StringComparison.OrdinalIgnoreCase);

    [JsonIgnore]
    public bool IsCli => !IsGui;

    public ToolEntry Clone() => new()
    {
        Name = Name,
        Type = Type,
        Executable = Executable,
        Args = new List<string>(Args),
        CustomRule = CustomRule?.Clone()
    };
}

public sealed class CustomToolRule
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("always_recommend")]
    public bool AlwaysRecommend { get; set; }

    [JsonPropertyName("keywords")]
    public List<string> Keywords { get; set; } = new();

    [JsonPropertyName("file_types")]
    public List<string> FileTypes { get; set; } = new();

    [JsonPropertyName("step")]
    public int Step { get; set; } = 1;

    [JsonPropertyName("priority")]
    public int Priority { get; set; } = 2;

    [JsonPropertyName("reason")]
    public string Reason { get; set; } = string.Empty;

    [JsonPropertyName("warning")]
    public string Warning { get; set; } = string.Empty;

    public CustomToolRule Clone() => new()
    {
        Enabled = Enabled,
        AlwaysRecommend = AlwaysRecommend,
        Keywords = new List<string>(Keywords),
        FileTypes = new List<string>(FileTypes),
        Step = Step,
        Priority = Priority,
        Reason = Reason,
        Warning = Warning
    };
}
