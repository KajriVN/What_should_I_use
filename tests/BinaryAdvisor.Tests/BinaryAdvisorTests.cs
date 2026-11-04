using System.IO;
using System.Security.Cryptography;
using System.Text;
using BinaryAdvisor.Core;
using BinaryAdvisor.Models;

namespace BinaryAdvisor.Tests;

public class BinaryAdvisorTests
{
    private static RuleEngine LoadProductionRuleEngine()
    {
        string yamlPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "BinaryAdvisor", "Config", "rules.yaml"));
        Assert.True(File.Exists(yamlPath), $"Missing rules.yaml at {yamlPath}");
        return RuleEngine.LoadFromFile(yamlPath);
    }

    [Fact]
    public void ParseDieJson_ModernAndLegacySchemas_ExtractsDetectionsAndEntropy()
    {
        const string detectJson = """
        Warning: custom signature db notice
        {
          "detects": [
            {
              "filetype": "PE64",
              "parentfilepart": "Header",
              "values": [
                {
                  "info": "NRV,brute",
                  "name": "UPX",
                  "string": "Packer: UPX(4.24)[NRV,brute]",
                  "type": "Packer",
                  "version": "4.24"
                },
                {
                  "info": "Console64",
                  "name": "Go",
                  "string": "Compiler: Go(1.22.1)",
                  "type": "Compiler",
                  "version": "1.22.1"
                }
              ]
            }
          ]
        }
        """;

        var (fileType, groups) = Scanner.ParseDieDetectionsJson(detectJson);
        Assert.Equal("PE64", fileType);
        Assert.Single(groups);
        Assert.Equal(2, groups[0].Items.Count);
        Assert.Equal("UPX", groups[0].Items[0].Name);
        Assert.Equal("4.24", groups[0].Items[0].Version);

        const string entropyJson = """
        {
          "records": [
            {
              "entropy": 6.2145,
              "name": "Section(0)['UPX0']",
              "offset": 1024,
              "size": 0,
              "status": "not packed"
            },
            {
              "entropy": 7.9123,
              "name": "Section(1)['UPX1']",
              "offset": 1024,
              "size": 245760,
              "status": "packed"
            }
          ],
          "status": "packed",
          "total": 7.8451
        }
        """;

        var (hasData, totalEntropy, overallStatus, sections) = Scanner.ParseDieEntropyJson(entropyJson);
        Assert.True(hasData);
        Assert.Equal(7.8451, totalEntropy, 3);
        Assert.Equal("packed", overallStatus);
        Assert.Equal(2, sections.Count);
        Assert.False(sections[0].IsWarning);
        Assert.True(sections[1].IsHighEntropy);
        Assert.True(sections[1].IsWarning);
        Assert.Contains("UPX1", sections[1].Name);
    }

    [Fact]
    public void RuleEngine_PriorityRanking_InstallerBeatsPackerAndCompiler()
    {
        RuleEngine engine = LoadProductionRuleEngine();
        ToolsConfig config = ConfigManager.CreateDefaultToolsConfig();

        var scan = new ScanResult
        {
            File = new FileMetadata
            {
                FullPath = @"D:\Mẫu Kiểm Thử\Bộ cài đặt ứng dụng.exe",
                FileName = "Bộ cài đặt ứng dụng.exe",
                Directory = @"D:\Mẫu Kiểm Thử",
                FileStem = "Bộ cài đặt ứng dụng",
                Extension = ".exe",
                FileType = "PE32"
            },
            TotalEntropy = 7.65,
            OverallPackStatus = "packed",
            DetectionGroups =
            [
                new DieDetectionGroup
                {
                    FileType = "PE32",
                    FilePart = "Header",
                    Items =
                    [
                        new DieDetectionItem { Type = "Compiler", Name = "Delphi", Version = "10.4" },
                        new DieDetectionItem { Type = "Installer", Name = "Inno Setup", Version = "6.2.2" }
                    ]
                }
            ]
        };

        AnalysisPlan plan = engine.Evaluate(scan, config);

        // Recognized installer => should NOT falsely flag Suspected Custom Packer
        Assert.False(plan.IsSuspectedCustomPacker);
        Assert.NotEmpty(plan.MatchedRules);
        Assert.Equal("inno_setup", plan.MatchedRules[0].Id);
        Assert.Equal(1, plan.MatchedRules[0].Priority);
        Assert.NotEmpty(plan.Step1Cards);
        Assert.Equal("innounp", plan.Step1Cards[0].ToolId);
    }

    [Fact]
    public void RuleEngine_HeuristicFilter_TriggersSuspectedCustomPackerWhenHighEntropyWithoutKnownPacker()
    {
        RuleEngine engine = LoadProductionRuleEngine();
        ToolsConfig config = ConfigManager.CreateDefaultToolsConfig();

        var scan = new ScanResult
        {
            File = new FileMetadata
            {
                FullPath = @"C:\Samples\mystery_loader.exe",
                FileName = "mystery_loader.exe",
                Directory = @"C:\Samples",
                FileStem = "mystery_loader",
                Extension = ".exe",
                FileType = "PE64"
            },
            TotalEntropy = 7.62,
            OverallPackStatus = "packed",
            Sections =
            [
                new SectionEntropy { Name = ".text", Size = 16384, Entropy = 6.10, Status = "not packed" },
                new SectionEntropy { Name = ".enc0", Size = 524288, Entropy = 7.94, Status = "packed" }
            ],
            DetectionGroups =
            [
                new DieDetectionGroup
                {
                    FileType = "PE64",
                    FilePart = "Header",
                    Items =
                    [
                        new DieDetectionItem { Type = "Compiler", Name = "Microsoft Visual C/C++", Version = "2022" }
                    ]
                }
            ]
        };

        AnalysisPlan plan = engine.Evaluate(scan, config);

        Assert.True(plan.IsSuspectedCustomPacker);
        Assert.Contains("Suspected Custom Packer", plan.HeuristicAlertTitle);
        Assert.Contains(".enc0", plan.HeuristicAlertDetails);
        Assert.Contains(plan.Step1Cards, c => c.Priority == 0);
    }

    [Fact]
    public void RuleEngine_SmartKeywordBoundary_PreventsGoogleFalseMatchForGolang()
    {
        RuleEngine engine = LoadProductionRuleEngine();
        ToolsConfig config = ConfigManager.CreateDefaultToolsConfig();

        var googleScan = new ScanResult
        {
            File = new FileMetadata
            {
                FullPath = @"C:\Samples\chrome_helper.exe",
                FileName = "chrome_helper.exe",
                Directory = @"C:\Samples",
                FileStem = "chrome_helper",
                Extension = ".exe",
                FileType = "PE64"
            },
            DetectionGroups =
            [
                new DieDetectionGroup
                {
                    FileType = "PE64",
                    Items =
                    [
                        new DieDetectionItem { Type = "Compiler", Name = "Google Internal Builder" }
                    ]
                }
            ]
        };

        AnalysisPlan googlePlan = engine.Evaluate(googleScan, config);
        Assert.DoesNotContain(googlePlan.MatchedRules, r => r.Id == "golang_binary");

        var goScan = new ScanResult
        {
            File = googleScan.File,
            DetectionGroups =
            [
                new DieDetectionGroup
                {
                    FileType = "PE64",
                    Items =
                    [
                        new DieDetectionItem { Type = "Compiler", Name = "Go", Version = "1.23" }
                    ]
                }
            ]
        };

        AnalysisPlan goPlan = engine.Evaluate(goScan, config);
        Assert.Contains(goPlan.MatchedRules, r => r.Id == "golang_binary");
        Assert.Contains(goPlan.Cards, c => c.ToolId == "goresym");
    }

    [Fact]
    public async Task Scanner_VietnameseAndSpacesPath_ScansRealDotNetPeBinaryCleanly()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), $"BinaryAdvisor_KiểmThử_{Guid.NewGuid():N}", "Thư mục có khoảng trắng");
        Directory.CreateDirectory(tempRoot);

        try
        {
            // Copy compiled BinaryAdvisor.dll (a real PE/.NET assembly) to a Vietnamese filename with spaces
            string sourcePe = typeof(Scanner).Assembly.Location;
            string targetFile = Path.Combine(tempRoot, "Ứng dụng mẫu Tiếng Việt 2026.exe");
            File.Copy(sourcePe, targetFile, overwrite: true);

            var scanner = new Scanner();
            ScanResult result = await scanner.ScanFileAsync(targetFile, diecPath: @"C:\non_existent\diec.exe");

            Assert.Equal("Ứng dụng mẫu Tiếng Việt 2026.exe", result.File.FileName);
            Assert.Equal(32, result.File.Md5.Length);
            Assert.Equal(64, result.File.Sha256.Length);
            Assert.Contains(".NET", result.File.FileType);
            Assert.NotEmpty(result.Sections);

            RuleEngine engine = LoadProductionRuleEngine();
            ToolsConfig config = ConfigManager.CreateDefaultToolsConfig();
            AnalysisPlan plan = engine.Evaluate(result, config);

            Assert.Contains(plan.MatchedRules, r => r.Id == "dotnet_cil");
            Assert.Contains(plan.Step2Cards, c => c.ToolId == "dnspy");

            // Verify command line round-tripping with spaces & Vietnamese characters
            ToolRecommendationCard dnspyCard = plan.Step2Cards.First(c => c.ToolId == "dnspy");
            List<string> split = ToolLauncher.SplitCommandLine(dnspyCard.CommandPreview);
            Assert.Equal(2, split.Count);
            Assert.Equal(targetFile, split[1]);
        }
        finally
        {
            string? parent = Directory.GetParent(tempRoot)?.FullName;
            if (parent is not null && Directory.Exists(parent))
                Directory.Delete(parent, recursive: true);
        }
    }

    [Fact]
    public async Task Scanner_LargeFileOver100MB_StreamsFastAndDetectsHighEntropy()
    {
        string tempFile = Path.Combine(Path.GetTempPath(), $"BinaryAdvisor_Large102MB_{Guid.NewGuid():N}.bin");
        const long sizeOver100Mb = 102L * 1024 * 1024; // 102 MB

        try
        {
            // Write 102 MB of pseudo-random high-entropy data quickly
            byte[] block = new byte[1024 * 1024];
            RandomNumberGenerator.Fill(block);
            await using (var fs = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 1024))
            {
                for (int i = 0; i < 102; i++)
                {
                    // Mutate a few bytes per MB so it stays realistic
                    block[0] = (byte)i;
                    await fs.WriteAsync(block);
                }
            }

            var progressMessages = new List<string>();
            var progress = new Progress<string>(msg => progressMessages.Add(msg));

            var scanner = new Scanner();
            ScanResult scan = await scanner.ScanFileAsync(tempFile, diecPath: null, progress);

            Assert.Equal(sizeOver100Mb, scan.File.SizeBytes);
            Assert.True(scan.TotalEntropy > 7.9, $"Expected high entropy > 7.9, got {scan.TotalEntropy}");
            Assert.False(string.IsNullOrWhiteSpace(scan.File.Md5));
            Assert.False(string.IsNullOrWhiteSpace(scan.File.Sha256));

            RuleEngine engine = LoadProductionRuleEngine();
            AnalysisPlan plan = engine.Evaluate(scan, ConfigManager.CreateDefaultToolsConfig());
            Assert.True(plan.IsSuspectedCustomPacker);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ToolLauncher_RunCliToolAsync_CapturesStdoutWithoutWindow()
    {
        var launcher = new ToolLauncher();
        var lines = new List<string>();

        int exitCode = await launcher.RunCliToolAsync(
            "cmd.exe",
            ["/c", "echo BinaryAdvisor_CLI_OK"],
            line => lines.Add(line));

        Assert.Equal(0, exitCode);
        Assert.Contains(lines, l => l.Contains("BinaryAdvisor_CLI_OK", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Scanner_WithMockDiecSubprocess_ExecutesBothFlagsHiddenAndParsesOutput()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"BinaryAdvisor_MockDiec_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            // Create a small mock diec.bat that outputs real DIE JSON for -d -j and -e -j
            string mockDiec = Path.Combine(tempDir, "mock_diec.cmd");
            const string batScript = """
                @echo off
                if "%~1"=="-d" (
                    echo {"detects":[{"filetype":"PE64","parentfilepart":"Header","values":[{"type":"Packer","name":"UPX","version":"4.24","info":"NRV"}]}]}
                    exit /b 0
                )
                if "%~1"=="-e" (
                    echo {"records":[{"name":"Section(0)['UPX1']","offset":1024,"size":40960,"entropy":7.92,"status":"packed"}],"status":"packed","total":7.81}
                    exit /b 0
                )
                """;
            await File.WriteAllTextAsync(mockDiec, batScript, Encoding.ASCII);

            string samplePath = Path.Combine(tempDir, "Mẫu UPX khoảng trắng.exe");
            await File.WriteAllBytesAsync(samplePath, new byte[2048]);

            var scanner = new Scanner();
            ScanResult result = await scanner.ScanFileAsync(samplePath, mockDiec);

            Assert.False(result.UsedNativeFallback);
            Assert.Equal("PE64", result.File.FileType);
            Assert.Contains(result.AllDetections, d => d.Name == "UPX" && d.Version == "4.24");
            Assert.Equal(7.81, result.TotalEntropy, 2);
            Assert.Single(result.Sections);
            Assert.True(result.Sections[0].IsWarning);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void WpfUi_SmokeTest_MainWindowAndSettingsWindowRenderCleanly()
    {
        Exception? threadException = null;

        var staThread = new Thread(() =>
        {
            try
            {
                var dispatcher = System.Windows.Threading.Dispatcher.CurrentDispatcher;
                SynchronizationContext.SetSynchronizationContext(
                    new System.Windows.Threading.DispatcherSynchronizationContext(dispatcher));

                if (System.Windows.Application.Current is null)
                {
                    var app = new BinaryAdvisor.App();
                    app.InitializeComponent();
                }

                var mainWindow = new BinaryAdvisor.MainWindow();
                string notepadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
                if (File.Exists(notepadPath))
                {
                    var frame = new System.Windows.Threading.DispatcherFrame();
                    Task scanTask = mainWindow.AnalyzeTargetFileAsync(notepadPath);
                    scanTask.ContinueWith(_ => frame.Continue = false);
                    System.Windows.Threading.Dispatcher.PushFrame(frame);
                    scanTask.GetAwaiter().GetResult();
                }

                var settingsWindow = new BinaryAdvisor.UI.Dialogs.SettingsWindow(ConfigManager.CreateDefaultToolsConfig());
                Assert.NotNull(settingsWindow.SavedConfig);

                var addEditDialog = new BinaryAdvisor.UI.Dialogs.AddEditToolDialog(
                    new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "upx" });
                Assert.NotNull(addEditDialog);
            }
            catch (Exception ex)
            {
                threadException = ex;
            }
        });

        staThread.SetApartmentState(ApartmentState.STA);
        staThread.Start();
        staThread.Join();

        if (threadException is not null)
            throw new AggregateException("WPF UI Smoke Test failed", threadException);
    }

    [Fact]
    public void RuleEngine_NetReactorDetection_RecommendsNetReactorSlayerWithNoPauseFlag()
    {
        RuleEngine engine = LoadProductionRuleEngine();
        ToolsConfig config = ConfigManager.CreateDefaultToolsConfig();

        var scan = new ScanResult
        {
            File = new FileMetadata
            {
                FullPath = @"D:\Mẫu Thử\App Bảo Vệ.exe",
                FileName = "App Bảo Vệ.exe",
                Directory = @"D:\Mẫu Thử",
                FileStem = "App Bảo Vệ",
                Extension = ".exe",
                FileType = "PE64 (.NET)"
            },
            TotalEntropy = 7.45,
            OverallPackStatus = "packed",
            DetectionGroups =
            [
                new DieDetectionGroup
                {
                    FileType = "PE64",
                    FilePart = "Header",
                    Items =
                    [
                        new DieDetectionItem { Type = "Protector", Name = ".NET Reactor", Version = "6.9", Info = "NecroBit" },
                        new DieDetectionItem { Type = "Library", Name = ".NET(v4.0.30319)" }
                    ]
                }
            ]
        };

        AnalysisPlan plan = engine.Evaluate(scan, config);

        Assert.False(plan.IsSuspectedCustomPacker);
        Assert.Contains(plan.MatchedRules, r => r.Id == "dotnet_reactor");
        Assert.Contains(plan.Step1Cards, c => c.ToolId == "reactor_slayer");
        Assert.Contains(plan.Step1Cards, c => c.ToolId == "reactor_slayer_gui");

        ToolRecommendationCard cliCard = plan.Step1Cards.First(c => c.ToolId == "reactor_slayer");
        Assert.Contains("--no-pause", cliCard.CommandPreview);
        Assert.Contains("App Bảo Vệ.exe", cliCard.CommandPreview);
    }

    [Fact]
    public void CustomToolRule_SavedInToolsConfig_AutoTriggersAtConfiguredStepAndSupportsQuickLaunch()
    {
        string tempJson = Path.Combine(Path.GetTempPath(), $"tools_custom_{Guid.NewGuid():N}.json");
        try
        {
            ToolsConfig config = ConfigManager.CreateDefaultToolsConfig();
            config.Tools["extreme_dumper"] = new ToolEntry
            {
                Name = "ExtremeDumper",
                Type = "gui",
                Executable = @"C:/Tools/ExtremeDumper/ExtremeDumper.exe",
                Args = [],
                CustomRule = new CustomToolRule
                {
                    Enabled = true,
                    AlwaysRecommend = false,
                    Keywords = [".NET Reactor", "Confuser"],
                    FileTypes = [".NET"],
                    Step = 3,
                    Priority = 1,
                    Reason = "Dump trực tiếp Assembly .NET giải mã trong RAM.",
                    Warning = "Chạy mẫu trong máy ảo trước khi attach."
                }
            };

            ConfigManager.SaveToolsConfig(config, tempJson);
            ToolsConfig reloaded = ConfigManager.LoadToolsConfig(tempJson);

            Assert.True(reloaded.Tools.ContainsKey("extreme_dumper"));
            Assert.NotNull(reloaded.Tools["extreme_dumper"].CustomRule);
            Assert.True(reloaded.Tools["extreme_dumper"].CustomRule!.Enabled);

            var scan = new ScanResult
            {
                File = new FileMetadata
                {
                    FullPath = @"C:\Samples\reactor_sample.exe",
                    FileName = "reactor_sample.exe",
                    Directory = @"C:\Samples",
                    FileStem = "reactor_sample",
                    Extension = ".exe",
                    FileType = "PE32 (.NET)"
                },
                DetectionGroups =
                [
                    new DieDetectionGroup
                    {
                        FileType = "PE32",
                        Items = [new DieDetectionItem { Type = "Protector", Name = ".NET Reactor" }]
                    }
                ]
            };

            RuleEngine engine = LoadProductionRuleEngine();
            AnalysisPlan plan = engine.Evaluate(scan, reloaded);

            Assert.Contains(plan.Step3Cards, c =>
                c.ToolId == "extreme_dumper" &&
                c.Reason.Contains("Dump trực tiếp", StringComparison.Ordinal));

            ToolRecommendationCard quickCard = RuleEngine.CreateQuickLaunchCard(
                "extreme_dumper",
                reloaded.Tools["extreme_dumper"],
                scan.File);
            Assert.Equal("ExtremeDumper", quickCard.ToolName);
        }
        finally
        {
            if (File.Exists(tempJson))
                File.Delete(tempJson);
        }
    }
}
