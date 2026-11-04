using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using BinaryAdvisor.Models;

namespace BinaryAdvisor.Core;

public static class ConfigManager
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static string GetAppBaseDirectory()
    {
        string? processPath = Environment.ProcessPath;
        if (!string.IsNullOrWhiteSpace(processPath) &&
            Path.GetFileName(processPath).StartsWith("BinaryAdvisor", StringComparison.OrdinalIgnoreCase))
        {
            string? exeDir = Path.GetDirectoryName(processPath);
            if (!string.IsNullOrWhiteSpace(exeDir))
                return exeDir;
        }

        return AppContext.BaseDirectory;
    }

    public static string GetConfigDirectory()
    {
        string baseConfig = Path.Combine(GetAppBaseDirectory(), "Config");
        if (Directory.Exists(baseConfig))
            return baseConfig;

        string cwdConfig = Path.Combine(Directory.GetCurrentDirectory(), "Config");
        if (Directory.Exists(cwdConfig))
            return cwdConfig;

        Directory.CreateDirectory(baseConfig);
        return baseConfig;
    }

    public static string GetToolsConfigPath() =>
        Path.Combine(GetConfigDirectory(), "tools_config.json");

    public static string GetRulesYamlPath() =>
        Path.Combine(GetConfigDirectory(), "rules.yaml");

    public static string? ReadEmbeddedResourceText(string logicalName)
    {
        Assembly asm = typeof(ConfigManager).Assembly;
        using Stream? stream = asm.GetManifestResourceStream(logicalName);
        if (stream is null)
            return null;

        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    public static ToolsConfig LoadToolsConfig(string? customPath = null)
    {
        string path = customPath ?? GetToolsConfigPath();
        ToolsConfig config;

        if (File.Exists(path))
        {
            string json = File.ReadAllText(path, Encoding.UTF8);
            config = JsonSerializer.Deserialize<ToolsConfig>(json, JsonOptions) ?? CreateDefaultToolsConfig();
        }
        else
        {
            string? embeddedJson = ReadEmbeddedResourceText("BinaryAdvisor.Config.tools_config.json");
            config = !string.IsNullOrWhiteSpace(embeddedJson)
                ? (JsonSerializer.Deserialize<ToolsConfig>(embeddedJson, JsonOptions) ?? CreateDefaultToolsConfig())
                : CreateDefaultToolsConfig();

            if (customPath is null)
                SaveToolsConfig(config, path);
        }

        // Normalize case-insensitive dictionary
        config.Tools = new Dictionary<string, ToolEntry>(config.Tools, StringComparer.OrdinalIgnoreCase);

        // If configured diec_path doesn't exist yet, check portable folders or PATH non-destructively
        if (!IsExecutableAvailable(config.DiecPath))
        {
            string? detectedDiec = TryFindPortableOrSystemDiec();
            if (!string.IsNullOrWhiteSpace(detectedDiec))
            {
                config.DiecPath = detectedDiec;
            }
        }

        return config;
    }

    public static void SaveToolsConfig(ToolsConfig config, string? customPath = null)
    {
        string path = customPath ?? GetToolsConfigPath();
        string? dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);

        string json = JsonSerializer.Serialize(config, JsonOptions);
        File.WriteAllText(path, json);
    }

    public static string? ResolveExecutablePath(string? configuredPath)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
            return null;

        string expanded = Environment.ExpandEnvironmentVariables(configuredPath.Trim().Trim('"'));

        // Direct absolute or relative path from app base directory
        if (Path.IsPathRooted(expanded))
        {
            return File.Exists(expanded) ? Path.GetFullPath(expanded) : null;
        }

        string relativeToApp = Path.Combine(GetAppBaseDirectory(), expanded);
        if (File.Exists(relativeToApp))
            return Path.GetFullPath(relativeToApp);

        if (File.Exists(expanded))
            return Path.GetFullPath(expanded);

        // Search in system PATH if bare command name or relative exe name
        if (!expanded.Contains(Path.DirectorySeparatorChar) && !expanded.Contains(Path.AltDirectorySeparatorChar))
        {
            return FindInSystemPath(expanded);
        }

        return null;
    }

    public static bool IsExecutableAvailable(string? configuredPath) =>
        ResolveExecutablePath(configuredPath) is not null;

    public static string? TryFindPortableOrSystemDiec()
    {
        string baseDir = GetAppBaseDirectory();
        string[] candidateRelativePaths =
        [
            Path.Combine(baseDir, "diec", "diec.exe"),
            Path.Combine(baseDir, "die_portable", "diec.exe"),
            Path.Combine(baseDir, "tools_portable", "diec", "diec.exe"),
            @"C:\Tools\die_win64_portable\diec.exe",
            @"C:\Tools\die\diec.exe",
            @"D:\Tools\die_win64_portable\diec.exe",
            @"D:\Tools\die\diec.exe"
        ];

        foreach (string candidate in candidateRelativePaths)
        {
            if (File.Exists(candidate))
                return Path.GetFullPath(candidate);
        }

        return FindInSystemPath("diec.exe") ?? FindInSystemPath("diec");
    }

    public static int AutoDetectInstalledTools(ToolsConfig config)
    {
        int foundCount = 0;

        if (!IsExecutableAvailable(config.DiecPath))
        {
            string? diec = TryFindPortableOrSystemDiec() ?? SearchCommonDirectories(["diec.exe"]);
            if (!string.IsNullOrWhiteSpace(diec))
            {
                config.DiecPath = diec;
                foundCount++;
            }
        }

        var knownBinaryNames = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["pe_bear"] = ["PE-bear.exe"],
            ["die_gui"] = ["die.exe"],
            ["dnspy"] = ["dnSpy.exe"],
            ["ilspy"] = ["ILSpy.exe"],
            ["ida64"] = ["ida.exe", "ida64.exe"],
            ["ghidra"] = ["ghidraRun.bat"],
            ["x64dbg"] = ["x64dbg.exe"],
            ["x32dbg"] = ["x32dbg.exe"],
            ["procmon"] = ["Procmon64.exe", "Procmon.exe"],
            ["upx"] = ["upx.exe"],
            ["goresym"] = ["GoReSym.exe", "GoReSym_win.exe"],
            ["floss"] = ["floss.exe"],
            ["capa"] = ["capa.exe"],
            ["reactor_slayer"] = ["NETReactorSlayer.CLI.exe", "NETReactorSlayer-cli.exe"],
            ["reactor_slayer_gui"] = ["NETReactorSlayer.exe"],
            ["de4dot"] = ["de4dot.exe", "de4dot-x64.exe"],
            ["pyinstxtractor"] = ["pyinstxtractor-ng.exe"],
            ["innounp"] = ["innounp.exe"],
            ["sevenzip"] = ["7z.exe"],
            ["vb_decompiler"] = ["VB Decompiler.exe"],
            ["idr"] = ["idr.exe"]
        };

        foreach (var (toolId, entry) in config.Tools)
        {
            if (IsExecutableAvailable(entry.Executable))
                continue;

            var exeCandidates = new List<string>();
            if (!string.IsNullOrWhiteSpace(entry.Executable))
            {
                string fileName = Path.GetFileName(entry.Executable);
                if (!string.IsNullOrWhiteSpace(fileName))
                    exeCandidates.Add(fileName);
            }

            if (knownBinaryNames.TryGetValue(toolId, out string[]? extraNames))
            {
                foreach (string name in extraNames)
                {
                    if (!exeCandidates.Contains(name, StringComparer.OrdinalIgnoreCase))
                        exeCandidates.Add(name);
                }
            }

            string? discovered = null;
            foreach (string exeName in exeCandidates)
            {
                discovered = FindInSystemPath(exeName);
                if (discovered is not null)
                    break;
            }

            discovered ??= SearchCommonDirectories(exeCandidates);

            if (!string.IsNullOrWhiteSpace(discovered))
            {
                entry.Executable = discovered.Replace('\\', '/');
                foundCount++;
            }
        }

        return foundCount;
    }

    private static string? FindInSystemPath(string exeName)
    {
        string? pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(pathEnv))
            return null;

        string[] extensions = Path.HasExtension(exeName)
            ? [string.Empty]
            : [".exe", ".bat", ".cmd"];

        foreach (string rawDir in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string dir = rawDir.Trim().Trim('"');
            if (string.IsNullOrWhiteSpace(dir))
                continue;

            foreach (string ext in extensions)
            {
                try
                {
                    string candidate = Path.Combine(dir, exeName + ext);
                    if (File.Exists(candidate))
                        return Path.GetFullPath(candidate);
                }
                catch
                {
                    // Ignore malformed PATH entries
                }
            }
        }

        return null;
    }

    private static string? SearchCommonDirectories(IReadOnlyCollection<string> exeNames)
    {
        if (exeNames.Count == 0)
            return null;

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] roots =
        [
            Path.Combine(GetAppBaseDirectory(), "tools_portable"),
            @"C:\Tools",
            @"D:\Tools",
            @"C:\Program Files\7-Zip",
            @"C:\Program Files (x86)\7-Zip",
            @"C:\Program Files",
            Path.Combine(localAppData, "Programs"),
            Path.Combine(localAppData, "Microsoft", "WinGet", "Packages"),
            Path.Combine(userProfile, "scoop", "apps")
        ];

        var nameSet = new HashSet<string>(exeNames, StringComparer.OrdinalIgnoreCase);

        foreach (string root in roots)
        {
            if (!Directory.Exists(root))
                continue;

            try
            {
                // Bounded depth walk (max depth 3) so auto-detect stays sub-second
                string? hit = SearchDirectoryBounded(root, nameSet, maxDepth: 3);
                if (hit is not null)
                    return hit;
            }
            catch
            {
                // Skip inaccessible directories
            }
        }

        return null;
    }

    private static string? SearchDirectoryBounded(string currentDir, HashSet<string> targetNames, int maxDepth)
    {
        try
        {
            foreach (string file in Directory.EnumerateFiles(currentDir))
            {
                if (targetNames.Contains(Path.GetFileName(file)))
                    return Path.GetFullPath(file);
            }

            if (maxDepth <= 0)
                return null;

            foreach (string subDir in Directory.EnumerateDirectories(currentDir))
            {
                string dirName = Path.GetFileName(subDir);
                if (dirName.StartsWith('.') ||
                    dirName.Equals("WindowsApps", StringComparison.OrdinalIgnoreCase) ||
                    dirName.Equals("Common Files", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string? found = SearchDirectoryBounded(subDir, targetNames, maxDepth - 1);
                if (found is not null)
                    return found;
            }
        }
        catch
        {
            // Ignore permission denied
        }

        return null;
    }

    public static ToolsConfig CreateDefaultToolsConfig() => new()
    {
        DiecPath = "C:/Tools/die_win64_portable/diec.exe",
        Tools = new Dictionary<string, ToolEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["pe_bear"] = new() { Name = "PE-bear", Type = "gui", Executable = "C:/Tools/PE-bear/PE-bear.exe", Args = ["{file}"] },
            ["dnspy"] = new() { Name = "dnSpyEx", Type = "gui", Executable = "C:/Tools/dnSpy/dnSpy.exe", Args = ["{file}"] },
            ["x64dbg"] = new() { Name = "x64dbg", Type = "gui", Executable = "C:/Tools/x64dbg/release/x64/x64dbg.exe", Args = ["{file}"] },
            ["upx"] = new() { Name = "UPX Unpacker", Type = "cli", Executable = "C:/Tools/upx/upx.exe", Args = ["-d", "{file}", "-o", "{file_dir}/{file_stem}_unpacked{file_ext}"] },
            ["reactor_slayer"] = new() { Name = "NETReactorSlayer (CLI)", Type = "cli", Executable = "C:/Tools/NETReactorSlayer/NETReactorSlayer.CLI.exe", Args = ["{file}", "--no-pause"] },
            ["reactor_slayer_gui"] = new() { Name = "NETReactorSlayer (GUI)", Type = "gui", Executable = "C:/Tools/NETReactorSlayer/NETReactorSlayer.exe", Args = ["{file}"] },
            ["goresym"] = new() { Name = "GoReSym", Type = "cli", Executable = "C:/Tools/GoReSym/GoReSym.exe", Args = ["-t", "-d", "-p", "{file}"] }
        }
    };
}
