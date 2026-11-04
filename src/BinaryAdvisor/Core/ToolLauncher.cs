using System.Diagnostics;
using System.IO;
using System.Text;
using BinaryAdvisor.Models;

namespace BinaryAdvisor.Core;

public sealed class ToolLauncher
{
    public void OpenInGuiTool(string executablePath, IReadOnlyList<string> arguments)
    {
        string? resolvedExe = ConfigManager.ResolveExecutablePath(executablePath);
        if (resolvedExe is null)
        {
            throw new FileNotFoundException(
                $"Không tìm thấy tệp thực thi công cụ tại: {executablePath}. Vui lòng mở Settings (⚙) để cấu hình đường dẫn thực tế.",
                executablePath);
        }

        bool isBatchScript = resolvedExe.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) ||
                             resolvedExe.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase);

        var psi = new ProcessStartInfo
        {
            FileName = isBatchScript ? "cmd.exe" : resolvedExe,
            WorkingDirectory = Path.GetDirectoryName(resolvedExe) ?? AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = isBatchScript
        };

        if (isBatchScript)
        {
            psi.ArgumentList.Add("/c");
            psi.ArgumentList.Add(resolvedExe);
        }

        foreach (string arg in arguments)
        {
            if (!string.IsNullOrWhiteSpace(arg))
                psi.ArgumentList.Add(arg);
        }

        Process.Start(psi);
    }

    public async Task<int> RunCliCommandLineAsync(
        string commandLineText,
        Action<string> onOutputLine,
        CancellationToken cancellationToken = default)
    {
        List<string> tokens = SplitCommandLine(commandLineText);
        if (tokens.Count == 0)
            throw new ArgumentException("Câu lệnh CLI đang để trống.");

        string exeToken = tokens[0];
        IReadOnlyList<string> args = tokens.Skip(1).ToList();

        return await RunCliToolAsync(exeToken, args, onOutputLine, cancellationToken);
    }

    public async Task<int> RunCliToolAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        Action<string> onOutputLine,
        CancellationToken cancellationToken = default)
    {
        string? resolvedExe = ConfigManager.ResolveExecutablePath(executablePath);
        if (resolvedExe is null)
        {
            throw new FileNotFoundException(
                $"Không tìm thấy công cụ CLI: '{executablePath}'. Vui lòng kiểm tra lại đường dẫn trong Settings (⚙).",
                executablePath);
        }

        var psi = new ProcessStartInfo
        {
            FileName = resolvedExe,
            WorkingDirectory = Path.GetDirectoryName(resolvedExe) ?? AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        foreach (string arg in arguments)
            psi.ArgumentList.Add(arg);

        onOutputLine($"$ {RuleEngine.FormatCommandPreview(resolvedExe, arguments)}");
        onOutputLine(new string('─', 72));

        using var process = new Process { StartInfo = psi, EnableRaisingEvents = true };

        var outputTcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var errorTcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null)
                outputTcs.TrySetResult();
            else
                onOutputLine(e.Data);
        };

        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is null)
                errorTcs.TrySetResult();
            else
                onOutputLine($"[stderr] {e.Data}");
        };

        if (!process.Start())
            throw new InvalidOperationException($"Không thể khởi chạy '{resolvedExe}'.");

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var registration = cancellationToken.Register(() =>
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    onOutputLine("[!] Đã dừng tiến trình theo yêu cầu người dùng.");
                }
            }
            catch
            {
                // Ignore race condition
            }
        });

        await process.WaitForExitAsync(cancellationToken);
        await Task.WhenAll(outputTcs.Task, errorTcs.Task);

        onOutputLine(new string('─', 72));
        onOutputLine($"[Hoàn tất với mã thoát (Exit Code): {process.ExitCode}]");

        return process.ExitCode;
    }

    /// <summary>
    /// Splits a command line string into executable + arguments while preserving quoted paths
    /// (including spaces and Vietnamese UTF-8 characters).
    /// </summary>
    public static List<string> SplitCommandLine(string commandLine)
    {
        var args = new List<string>();
        if (string.IsNullOrWhiteSpace(commandLine))
            return args;

        var current = new StringBuilder();
        bool inQuotes = false;

        for (int i = 0; i < commandLine.Length; i++)
        {
            char c = commandLine[i];

            if (c == '\\' && i + 1 < commandLine.Length && commandLine[i + 1] == '"')
            {
                current.Append('"');
                i++;
                continue;
            }

            if (c == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }

            if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (current.Length > 0)
                {
                    args.Add(current.ToString());
                    current.Clear();
                }
            }
            else
            {
                current.Append(c);
            }
        }

        if (current.Length > 0)
            args.Add(current.ToString());

        return args;
    }
}
