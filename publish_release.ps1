param(
    [ValidateSet("All", "Standalone", "Lightweight")]
    [string]$Mode = "All"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Join-Path $root "src\BinaryAdvisor\BinaryAdvisor.csproj"

function New-PortableFolderNote([string]$targetDir) {
    $portableDiecDir = Join-Path $targetDir "tools_portable\diec"
    New-Item -ItemType Directory -Force -Path $portableDiecDir | Out-Null
    $readmePortable = @"
Đặt bộ Detect It Easy Portable (chứa diec.exe, thư mục db/, ...) vào thư mục này:
  tools_portable\diec\diec.exe

Binary Advisor sẽ tự động nhận diện ngay khi khởi động mà không cần cấu hình thủ công!
Hoặc mở Settings (⚙) trong phần mềm để trỏ tới đường dẫn diec.exe sẵn có trên máy của bạn.
"@
    Set-Content -Path (Join-Path $portableDiecDir "PUT_DIEC_PORTABLE_HERE.txt") -Value $readmePortable -Encoding UTF8
}

if ($Mode -in @("All", "Standalone")) {
    $standaloneDir = Join-Path $root "dist\BinaryAdvisor_Standalone"
    if (Test-Path $standaloneDir) { Remove-Item $standaloneDir -Recurse -Force }

    Write-Host "[1] Building Standalone Single-File EXE (runs on ANY Windows x64 PC without .NET installed)..." -ForegroundColor Cyan
    dotnet publish $proj `
        -c Release `
        -r win-x64 `
        --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:EnableCompressionInSingleFile=true `
        -p:DebugType=None `
        -p:DebugSymbols=false `
        -o $standaloneDir

    New-PortableFolderNote $standaloneDir
    Write-Host "[+] Standalone EXE ready: $standaloneDir\BinaryAdvisor.exe" -ForegroundColor Green
}

if ($Mode -in @("All", "Lightweight")) {
    $lightDir = Join-Path $root "dist\BinaryAdvisor_Lightweight"
    if (Test-Path $lightDir) { Remove-Item $lightDir -Recurse -Force }

    Write-Host "[2] Building Lightweight Single-File EXE (~650 KB, uses installed .NET Desktop Runtime)..." -ForegroundColor Cyan
    dotnet publish $proj `
        -c Release `
        -r win-x64 `
        --self-contained false `
        -p:PublishSingleFile=true `
        -p:DebugType=None `
        -p:DebugSymbols=false `
        -o $lightDir

    New-PortableFolderNote $lightDir
    Write-Host "[+] Lightweight EXE ready: $lightDir\BinaryAdvisor.exe" -ForegroundColor Green
}
