# Binary Advisor — Reverse Engineering Triage & One-Click Launcher

**Binary Advisor** (*What Should I Use?*) là ứng dụng Windows Desktop (C# / .NET WPF — Dark Mode) giúp tự động định danh tệp nhị phân qua **Detect It Easy CLI (`diec.exe`)**, phân tích mức độ nén **Shannon Entropy** từng Section, phát hiện **Suspected Custom Packer** bằng bộ lọc Heuristic và điều phối mở nhanh bộ công cụ Dịch ngược / Phân tích Mã độc theo luồng 3 bước chuẩn.

---

## Tính năng chính

1. **Vùng 1 — Thanh Kéo Thả & Thông tin Tệp (Top Bar)**
   - Kéo & thả tệp trực tiếp vào bất kỳ vị trí nào trên cửa sổ (hoặc kéo tệp thả thẳng lên biểu tượng `BinaryAdvisor.exe`).
   - Băm **MD5 & SHA-256** theo cơ chế Streaming 1-lượt (xử lý mượt tệp `> 100 MB` không treo giao diện, hỗ trợ đầy đủ đường dẫn chứa khoảng trắng & tiếng Việt).
2. **Vùng 2 — Bảng Kết quả DIE & Thanh Entropy (Left Panel)**
   - Hiển thị dạng cây (**TreeView**) kết quả từ `diec -d -j` (kèm bộ phân tích PE32/PE64/.NET/ELF nội bộ dự phòng khi chưa trỏ `diec.exe`).
   - Thanh màu **Entropy** (`diec -e -j`) cho toàn tệp và từng Section, tự động tô đỏ cảnh báo các phân vùng có **Entropy > 7.2** hoặc bị đánh dấu `packed`.
3. **Vùng 3 — Luồng Khuyến nghị Công cụ 3 Bước (Center/Right Panel)**
   - Xếp hạng theo độ ưu tiên: **Ưu tiên 1 (Installer/SFX)** → **Ưu tiên 2 (Packer/Protector)** → **Ưu tiên 3 (Compiler/Ngôn ngữ)**.
   - Bộ lọc **Heuristic Alert**: tự động kích hoạt cảnh báo `Suspected Custom Packer` khi tổng Entropy `> 7.2` hoặc Section bị nén mà không khớp chữ ký Packer phổ thông.
   - Chia thẻ trực quan theo **Bước 1: Unpack/Extract** → **Bước 2: Phân tích tĩnh** → **Bước 3: Phân tích động**.
4. **Vùng 4 — Trình Khởi chạy & Dòng lệnh (Bottom Drawer)**
   - Tự động điền các biến giữ chỗ `{file}`, `{file_dir}`, `{file_name}`, `{file_stem}`, `{file_ext}`.
   - Hỗ trợ **Copy Command**, **Run CLI** (chạy ngầm `CreateNoWindow` và đẩy `stdout/stderr` trực tiếp lên khung Terminal Log), **Open in Tool** (mở thẳng phần mềm GUI) và menu **`⚡ Chọn Tool ▾`** để mở nhanh bất kỳ công cụ nào.
5. **Tự thêm Công cụ & Quy tắc Tự động Gợi ý (`＋ Tự thêm Tool` & Settings)**
   - Tích hợp sẵn bộ công cụ phổ biến gồm cả **NETReactorSlayer (CLI `--no-pause` & GUI)**, `de4dot`, `dnSpyEx`, `ILSpy`, `IDA Pro`, `Ghidra`, `x64dbg`, `PE-bear`, `UPX`, `GoReSym`, `FLOSS`, `CAPA`, `pyinstxtractor`, `innounp`, `7-Zip`...
   - Hộp thoại **Thêm / Tùy chỉnh Công cụ** cho phép tự thêm bất kỳ phần mềm GUI/CLI nào, chèn nhanh biến `{file}`, `{file_dir}`... và gán **điều kiện tự động gợi ý** (theo Từ khóa DIE, Định dạng/Đuôi tệp hoặc Luôn hiển thị ở Bước 1/2/3) ngay trên giao diện mà không cần sửa YAML thủ công.

---

## Cấu trúc Thư mục

```text
What_should_I_use/
├── BinaryAdvisor.slnx
├── publish_release.ps1               # Script đóng gói bản phát hành BinaryAdvisor.exe gọn nhẹ
├── src/BinaryAdvisor/
│   ├── Assets/DarkTheme.xaml         # Giao diện Dark Mode
│   ├── Config/
│   │   ├── rules.yaml                # Cơ sở dữ liệu quy tắc ánh xạ & Heuristic
│   │   └── tools_config.json         # Cấu hình đường dẫn thực tế tới diec.exe và các tool
│   ├── Core/
│   │   ├── Scanner.cs                # Gọi ngầm diec -d -j / -e -j, parse JSON & streaming MD5/SHA256
│   │   ├── NativeBinaryInspector.cs  # Bộ đọc PE/ELF & tính Shannon Entropy nội bộ tốc độ cao
│   │   ├── RuleEngine.cs             # Đánh giá rules.yaml, bộ lọc Heuristic & thay thế placeholder
│   │   ├── ConfigManager.cs          # Quản lý tools_config.json & tự động dò công cụ
│   │   └── ToolLauncher.cs           # Khởi chạy GUI tool & chạy ngầm CLI streaming stdout/stderr
│   ├── Models/                       # Các lớp dữ liệu Scan, Rule, Config
│   └── UI/                           # MainWindow, ToolCardControl, SettingsWindow
└── tests/BinaryAdvisor.Tests/        # Bộ kiểm thử tự động xUnit (JSON, Heuristic, >100MB, Tiếng Việt, UI)
```

---

## Khởi chạy & Đóng gói

### 1. Chạy trực tiếp khi phát triển
```powershell
dotnet run --project src\BinaryAdvisor\BinaryAdvisor.csproj
```

### 2. Chạy bộ kiểm thử tự động (xUnit)
```powershell
dotnet test BinaryAdvisor.slnx
```

### 3. Đóng gói file `.exe` phát hành (`dist\BinaryAdvisor\BinaryAdvisor.exe`)
```powershell
# Bản gọn nhẹ (~600 KB, dùng .NET Desktop Runtime trên máy):
powershell -ExecutionPolicy Bypass -File .\publish_release.ps1

# Hoặc bản độc lập hoàn toàn (Self-Contained, chạy trên máy chưa cài .NET):
powershell -ExecutionPolicy Bypass -File .\publish_release.ps1 -SelfContained
```

> **Mẹo dùng ngay với Detect It Easy:** Mở **Settings (`⚙`)** trên thanh trên cùng của ứng dụng, bấm **Browse...** tại mục `diec.exe` để trỏ tới tệp `diec.exe` có sẵn trên máy bạn (hoặc chép thư mục DIE Portable vào `tools_portable\diec\`).
