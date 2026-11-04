using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using BinaryAdvisor.Models;

namespace BinaryAdvisor.Core;

/// <summary>
/// Built-in high-speed PE32/PE64/ELF structural &amp; Shannon Entropy analyzer.
/// Serves both as a fallback when diec.exe is not configured and as a supplemental entropy verifier.
/// </summary>
public static class NativeBinaryInspector
{
    public sealed class NativeInspectionResult
    {
        public string FileType { get; set; } = "Unknown";
        public double TotalEntropy { get; set; }
        public string OverallPackStatus { get; set; } = "not packed";
        public List<SectionEntropy> Sections { get; set; } = new();
        public List<DieDetectionGroup> DetectionGroups { get; set; } = new();
    }

    public static NativeInspectionResult Inspect(string filePath, CancellationToken cancellationToken = default)
    {
        var result = new NativeInspectionResult();
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 65536);

        long fileLength = fs.Length;
        if (fileLength == 0)
        {
            result.FileType = "Empty";
            return result;
        }

        result.TotalEntropy = ComputeRangeEntropy(fs, 0, fileLength, cancellationToken);

        Span<byte> magic = stackalloc byte[(int)Math.Min(64, fileLength)];
        fs.Position = 0;
        fs.ReadExactly(magic);

        if (magic.Length >= 2 && magic[0] == (byte)'M' && magic[1] == (byte)'Z')
        {
            InspectPeFile(fs, fileLength, result, cancellationToken);
        }
        else if (magic.Length >= 4 && magic[0] == 0x7F && magic[1] == (byte)'E' && magic[2] == (byte)'L' && magic[3] == (byte)'F')
        {
            InspectElfFile(fs, fileLength, result, cancellationToken);
        }
        else
        {
            InspectGenericFormat(fs, magic, fileLength, result, cancellationToken);
        }

        bool anyPackedSection = result.Sections.Any(s => s.IsHighEntropy || s.IsPackedStatus);
        result.OverallPackStatus = (result.TotalEntropy > 7.2 || anyPackedSection) ? "packed" : "not packed";

        return result;
    }

    public static double ComputeByteBufferEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return 0.0;

        Span<long> counts = stackalloc long[256];
        counts.Clear();

        foreach (byte b in data)
            counts[b]++;

        double total = data.Length;
        double entropy = 0.0;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0)
                continue;
            double p = counts[i] / total;
            entropy -= p * Math.Log2(p);
        }

        return Math.Round(entropy, 4);
    }

    public static double ComputeRangeEntropy(Stream stream, long offset, long size, CancellationToken cancellationToken = default)
    {
        if (size <= 0 || offset < 0 || offset >= stream.Length)
            return 0.0;

        long safeSize = Math.Min(size, stream.Length - offset);
        if (safeSize <= 0)
            return 0.0;

        Span<long> counts = stackalloc long[256];
        counts.Clear();

        byte[] buffer = ArrayPool<byte>.Shared.Rent(262_144); // 256 KB
        try
        {
            stream.Position = offset;
            long remaining = safeSize;
            long totalRead = 0;

            while (remaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int toRead = (int)Math.Min(buffer.Length, remaining);
                int read = stream.Read(buffer, 0, toRead);
                if (read <= 0)
                    break;

                ReadOnlySpan<byte> chunk = buffer.AsSpan(0, read);
                for (int i = 0; i < chunk.Length; i++)
                    counts[chunk[i]]++;

                totalRead += read;
                remaining -= read;
            }

            if (totalRead == 0)
                return 0.0;

            double entropy = 0.0;
            double totalDouble = totalRead;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0)
                    continue;
                double p = counts[i] / totalDouble;
                entropy -= p * Math.Log2(p);
            }

            return Math.Round(entropy, 4);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void InspectPeFile(FileStream fs, long fileLength, NativeInspectionResult result, CancellationToken ct)
    {
        var detections = new List<DieDetectionItem>();

        if (fileLength < 0x40)
        {
            result.FileType = "MS-DOS";
            return;
        }

        Span<byte> dosBuf = stackalloc byte[64];
        fs.Position = 0;
        fs.ReadExactly(dosBuf);
        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(dosBuf.Slice(0x3C, 4));

        if (peOffset < 0 || peOffset + 24 > fileLength)
        {
            result.FileType = "MS-DOS";
            return;
        }

        Span<byte> peHeader = stackalloc byte[24];
        fs.Position = peOffset;
        fs.ReadExactly(peHeader);

        if (peHeader[0] != (byte)'P' || peHeader[1] != (byte)'E' || peHeader[2] != 0 || peHeader[3] != 0)
        {
            result.FileType = "MS-DOS";
            return;
        }

        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(peHeader.Slice(4, 2));
        ushort numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(peHeader.Slice(6, 2));
        ushort sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(peHeader.Slice(20, 2));

        long optHeaderOffset = peOffset + 24;
        bool is64Bit = machine is 0x8664 or 0xAA64;
        bool hasClrHeader = false;

        if (sizeOfOptionalHeader >= 2 && optHeaderOffset + sizeOfOptionalHeader <= fileLength)
        {
            byte[] optHeader = new byte[sizeOfOptionalHeader];
            fs.Position = optHeaderOffset;
            fs.ReadExactly(optHeader);

            ushort optMagic = BinaryPrimitives.ReadUInt16LittleEndian(optHeader.AsSpan(0, 2));
            is64Bit = optMagic == 0x20B;

            if (optHeader.Length >= 4)
            {
                byte majorLinker = optHeader[2];
                byte minorLinker = optHeader[3];
                detections.Add(new DieDetectionItem
                {
                    Type = "Linker",
                    Name = "PE Linker",
                    Version = $"{majorLinker}.{minorLinker}",
                    Info = is64Bit ? "PE32+" : "PE32"
                });
            }

            // Check DataDirectory[14] (COM Descriptor / .NET CLI Header)
            int clrDirOffset = is64Bit ? 112 + (14 * 8) : 96 + (14 * 8);
            if (optHeader.Length >= clrDirOffset + 8)
            {
                uint clrRva = BinaryPrimitives.ReadUInt32LittleEndian(optHeader.AsSpan(clrDirOffset, 4));
                uint clrSize = BinaryPrimitives.ReadUInt32LittleEndian(optHeader.AsSpan(clrDirOffset + 4, 4));
                hasClrHeader = clrRva != 0 && clrSize >= 0x48;
            }
        }

        result.FileType = is64Bit ? "PE64" : "PE32";

        if (hasClrHeader)
        {
            detections.Add(new DieDetectionItem
            {
                Type = "Library",
                Name = ".NET (CIL / MSIL)",
                Version = "CLR",
                Info = is64Bit ? "64-bit / AnyCPU" : "32-bit / AnyCPU"
            });
        }

        // Parse Section Headers
        long sectionTableOffset = optHeaderOffset + sizeOfOptionalHeader;
        long maxSectionEnd = sectionTableOffset + (numberOfSections * 40L);
        int safeSections = Math.Min((int)numberOfSections, 96);

        if (sectionTableOffset + (safeSections * 40L) <= fileLength)
        {
            byte[] secBuf = new byte[safeSections * 40];
            fs.Position = sectionTableOffset;
            fs.ReadExactly(secBuf);

            for (int i = 0; i < safeSections; i++)
            {
                ReadOnlySpan<byte> entry = secBuf.AsSpan(i * 40, 40);
                string rawName = Encoding.ASCII.GetString(entry.Slice(0, 8)).TrimEnd('\0');
                if (string.IsNullOrWhiteSpace(rawName))
                    rawName = $"Section_{i}";

                uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(8, 4));
                uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(16, 4));
                uint rawPtr = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(20, 4));

                double secEntropy = rawSize > 0 && rawPtr < fileLength
                    ? ComputeRangeEntropy(fs, rawPtr, rawSize, ct)
                    : 0.0;

                bool suspiciousVirtualVsRaw = rawSize == 0 && virtualSize >= 0x2000 &&
                    (rawName.StartsWith("UPX", StringComparison.OrdinalIgnoreCase) || i == 0);

                string secStatus = (secEntropy > 7.2 || suspiciousVirtualVsRaw) ? "packed" : "not packed";

                result.Sections.Add(new SectionEntropy
                {
                    Name = rawName,
                    Offset = rawPtr,
                    Size = rawSize,
                    Entropy = secEntropy,
                    Status = secStatus
                });

                long endPos = (long)rawPtr + rawSize;
                if (endPos > maxSectionEnd && rawSize > 0)
                    maxSectionEnd = endPos;

                DetectKnownSectionSignatures(rawName, detections);
            }
        }

        // Overlay check (crucial for Installers, SFX, PyInstaller)
        if (maxSectionEnd > 0 && maxSectionEnd < fileLength)
        {
            long overlaySize = fileLength - maxSectionEnd;
            if (overlaySize >= 64)
            {
                double overlayEntropy = ComputeRangeEntropy(fs, maxSectionEnd, overlaySize, ct);
                result.Sections.Add(new SectionEntropy
                {
                    Name = "Overlay",
                    Offset = maxSectionEnd,
                    Size = overlaySize,
                    Entropy = overlayEntropy,
                    Status = overlayEntropy > 7.2 ? "packed" : "not packed"
                });
            }
        }

        // Bounded byte-pattern signature scan (first 2MB + last 2MB)
        ScanBoundedSignatures(fs, fileLength, hasClrHeader, detections);

        result.DetectionGroups.Add(new DieDetectionGroup
        {
            FileType = result.FileType,
            FilePart = "Native PE Inspector",
            Items = detections
        });
    }

    private static void DetectKnownSectionSignatures(string sectionName, List<DieDetectionItem> detections)
    {
        if (sectionName.StartsWith("UPX", StringComparison.OrdinalIgnoreCase) &&
            !detections.Any(d => d.Name.Equals("UPX", StringComparison.OrdinalIgnoreCase)))
        {
            detections.Add(new DieDetectionItem { Type = "Packer", Name = "UPX", Info = $"Section {sectionName}" });
        }
        else if (sectionName.StartsWith(".vmp", StringComparison.OrdinalIgnoreCase) &&
                 !detections.Any(d => d.Name.Contains("VMProtect", StringComparison.OrdinalIgnoreCase)))
        {
            detections.Add(new DieDetectionItem { Type = "Protector", Name = "VMProtect", Info = $"Section {sectionName}" });
        }
        else if ((sectionName.StartsWith(".themida", StringComparison.OrdinalIgnoreCase) ||
                  sectionName.StartsWith(".winlice", StringComparison.OrdinalIgnoreCase)) &&
                 !detections.Any(d => d.Name.Contains("Themida", StringComparison.OrdinalIgnoreCase)))
        {
            detections.Add(new DieDetectionItem { Type = "Protector", Name = "Themida / WinLicense", Info = $"Section {sectionName}" });
        }
        else if (sectionName.StartsWith(".MPRESS", StringComparison.OrdinalIgnoreCase) &&
                 !detections.Any(d => d.Name.Equals("MPRESS", StringComparison.OrdinalIgnoreCase)))
        {
            detections.Add(new DieDetectionItem { Type = "Packer", Name = "MPRESS", Info = $"Section {sectionName}" });
        }
        else if (sectionName.Equals(".aspack", StringComparison.OrdinalIgnoreCase) &&
                 !detections.Any(d => d.Name.Equals("ASPack", StringComparison.OrdinalIgnoreCase)))
        {
            detections.Add(new DieDetectionItem { Type = "Packer", Name = "ASPack", Info = $"Section {sectionName}" });
        }
    }

    private static void ScanBoundedSignatures(FileStream fs, long fileLength, bool hasClrHeader, List<DieDetectionItem> detections)
    {
        const int WindowSize = 2 * 1024 * 1024; // 2 MB head + 2 MB tail
        int headLen = (int)Math.Min(WindowSize, fileLength);
        byte[] head = new byte[headLen];
        fs.Position = 0;
        fs.ReadExactly(head);

        byte[] tail = Array.Empty<byte>();
        if (fileLength > WindowSize)
        {
            int tailLen = (int)Math.Min(WindowSize, fileLength - headLen);
            if (tailLen > 0)
            {
                tail = new byte[tailLen];
                fs.Position = fileLength - tailLen;
                fs.ReadExactly(tail);
            }
        }

        string headAscii = Encoding.Latin1.GetString(head);
        string tailAscii = tail.Length > 0 ? Encoding.Latin1.GetString(tail) : string.Empty;

        bool ContainsMarker(string marker) =>
            headAscii.Contains(marker, StringComparison.Ordinal) ||
            tailAscii.Contains(marker, StringComparison.Ordinal);

        if (ContainsMarker("Inno Setup Setup Data") || ContainsMarker("Inno Setup Messages"))
            detections.Add(new DieDetectionItem { Type = "Installer", Name = "Inno Setup", Info = "Setup Header/Overlay" });

        if (ContainsMarker("Nullsoft.NSIS.exehead") || ContainsMarker("NullsoftInst"))
            detections.Add(new DieDetectionItem { Type = "Installer", Name = "Nullsoft Scriptable Install System (NSIS)" });

        if (ContainsMarker("MEI\x0c\x0b\x0a\x0b\x0e") || ContainsMarker("pyi-runtime-tmpdir") || ContainsMarker("PYZ-00.pyz"))
            detections.Add(new DieDetectionItem { Type = "Packer", Name = "PyInstaller", Info = "Python Bundle" });

        if (ContainsMarker("UPX!") && !detections.Any(d => d.Name.Equals("UPX", StringComparison.OrdinalIgnoreCase)))
            detections.Add(new DieDetectionItem { Type = "Packer", Name = "UPX", Info = "UPX! Magic" });

        if (ContainsMarker("ConfuserEx") || ContainsMarker("Confuser.Core"))
            detections.Add(new DieDetectionItem { Type = "Protector", Name = "ConfuserEx" });

        if (ContainsMarker(".NET Reactor") || ContainsMarker("Eziriz") || ContainsMarker("___.netmodule"))
            detections.Add(new DieDetectionItem { Type = "Protector", Name = ".NET Reactor", Info = "Eziriz / NecroBit" });

        if (ContainsMarker("Go build ID:") || ContainsMarker("Go buildinf:") || ContainsMarker("runtime.gopanic"))
            detections.Add(new DieDetectionItem { Type = "Compiler", Name = "Go (Golang)" });

        if (ContainsMarker("rustc/") || ContainsMarker("rust_begin_unwind"))
            detections.Add(new DieDetectionItem { Type = "Compiler", Name = "Rust (rustc)" });

        if (ContainsMarker("MSVBVM60.DLL") || ContainsMarker("VB5!"))
            detections.Add(new DieDetectionItem { Type = "Compiler", Name = "Microsoft Visual Basic 6.0" });

        if (ContainsMarker("Embarcadero Delphi") || ContainsMarker("Borland Delphi"))
            detections.Add(new DieDetectionItem { Type = "Compiler", Name = "Delphi" });

        if (!hasClrHeader && !detections.Any(d => d.Type == "Compiler"))
        {
            if (ContainsMarker("VCRUNTIME140") || ContainsMarker("MSVCP140") || ContainsMarker("api-ms-win-crt") || ContainsMarker("Rich"))
            {
                detections.Add(new DieDetectionItem { Type = "Compiler", Name = "Microsoft Visual C/C++", Info = "Native PE" });
            }
            else if (ContainsMarker("MINGW") || ContainsMarker("GCC: ("))
            {
                detections.Add(new DieDetectionItem { Type = "Compiler", Name = "GCC / MinGW" });
            }
        }
    }

    private static void InspectElfFile(FileStream fs, long fileLength, NativeInspectionResult result, CancellationToken ct)
    {
        if (fileLength < 52)
        {
            result.FileType = "ELF";
            return;
        }

        Span<byte> ehdr = stackalloc byte[(int)Math.Min(64, fileLength)];
        fs.Position = 0;
        fs.ReadExactly(ehdr);

        bool is64 = ehdr[4] == 2;
        bool littleEndian = ehdr[5] == 1;
        result.FileType = is64 ? "ELF64" : "ELF32";

        if (littleEndian)
        {
            long shOff = is64
                ? (long)BinaryPrimitives.ReadUInt64LittleEndian(ehdr.Slice(40, 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(ehdr.Slice(32, 4));
            ushort shEntSize = BinaryPrimitives.ReadUInt16LittleEndian(ehdr.Slice(is64 ? 58 : 46, 2));
            ushort shNum = BinaryPrimitives.ReadUInt16LittleEndian(ehdr.Slice(is64 ? 60 : 48, 2));
            ushort shStrNdx = BinaryPrimitives.ReadUInt16LittleEndian(ehdr.Slice(is64 ? 62 : 50, 2));

            int safeNum = Math.Min((int)shNum, 64);
            if (shOff > 0 && shEntSize >= (is64 ? 64 : 40) && shOff + (long)safeNum * shEntSize <= fileLength)
            {
                byte[] shTable = new byte[safeNum * shEntSize];
                fs.Position = shOff;
                fs.ReadExactly(shTable);

                byte[] strTab = Array.Empty<byte>();
                if (shStrNdx < safeNum)
                {
                    ReadOnlySpan<byte> strSec = shTable.AsSpan(shStrNdx * shEntSize, shEntSize);
                    long strOff = is64
                        ? (long)BinaryPrimitives.ReadUInt64LittleEndian(strSec.Slice(24, 8))
                        : BinaryPrimitives.ReadUInt32LittleEndian(strSec.Slice(16, 4));
                    long strSize = is64
                        ? (long)BinaryPrimitives.ReadUInt64LittleEndian(strSec.Slice(32, 8))
                        : BinaryPrimitives.ReadUInt32LittleEndian(strSec.Slice(20, 4));

                    if (strOff > 0 && strSize > 0 && strSize <= 1_048_576 && strOff + strSize <= fileLength)
                    {
                        strTab = new byte[strSize];
                        fs.Position = strOff;
                        fs.ReadExactly(strTab);
                    }
                }

                for (int i = 1; i < safeNum; i++)
                {
                    ReadOnlySpan<byte> sec = shTable.AsSpan(i * shEntSize, shEntSize);
                    uint nameIdx = BinaryPrimitives.ReadUInt32LittleEndian(sec.Slice(0, 4));
                    uint shType = BinaryPrimitives.ReadUInt32LittleEndian(sec.Slice(4, 4));
                    long secOff = is64
                        ? (long)BinaryPrimitives.ReadUInt64LittleEndian(sec.Slice(24, 8))
                        : BinaryPrimitives.ReadUInt32LittleEndian(sec.Slice(16, 4));
                    long secSize = is64
                        ? (long)BinaryPrimitives.ReadUInt64LittleEndian(sec.Slice(32, 8))
                        : BinaryPrimitives.ReadUInt32LittleEndian(sec.Slice(20, 4));

                    if (shType == 8 || secSize <= 0) // SHT_NOBITS (.bss)
                        continue;

                    string name = ReadNullTerminatedAscii(strTab, (int)nameIdx) ?? $"sec_{i}";
                    double ent = ComputeRangeEntropy(fs, secOff, secSize, ct);
                    result.Sections.Add(new SectionEntropy
                    {
                        Name = name,
                        Offset = secOff,
                        Size = secSize,
                        Entropy = ent,
                        Status = ent > 7.2 ? "packed" : "not packed"
                    });
                }
            }
        }

        result.DetectionGroups.Add(new DieDetectionGroup
        {
            FileType = result.FileType,
            FilePart = "Native ELF Inspector",
            Items =
            [
                new DieDetectionItem { Type = "Format", Name = result.FileType, Info = "Linux / Unix Executable" }
            ]
        });
    }

    private static string? ReadNullTerminatedAscii(byte[] table, int offset)
    {
        if (offset < 0 || offset >= table.Length)
            return null;
        int end = offset;
        while (end < table.Length && table[end] != 0)
            end++;
        return end > offset ? Encoding.ASCII.GetString(table, offset, end - offset) : null;
    }

    private static void InspectGenericFormat(FileStream fs, ReadOnlySpan<byte> magic, long fileLength, NativeInspectionResult result, CancellationToken ct)
    {
        var items = new List<DieDetectionItem>();

        if (magic.Length >= 6 && magic[0] == 0x37 && magic[1] == 0x7A && magic[2] == 0xBC && magic[3] == 0xAF)
        {
            result.FileType = "7-Zip";
            items.Add(new DieDetectionItem { Type = "Archive", Name = "7-Zip Archive" });
        }
        else if (magic.Length >= 4 && magic[0] == (byte)'R' && magic[1] == (byte)'a' && magic[2] == (byte)'r' && magic[3] == (byte)'!')
        {
            result.FileType = "RAR";
            items.Add(new DieDetectionItem { Type = "Archive", Name = "WinRAR Archive" });
        }
        else if (magic.Length >= 8 && magic[0] == 0xD0 && magic[1] == 0xCF && magic[2] == 0x11 && magic[3] == 0xE0)
        {
            result.FileType = "MSI / OLE2";
            items.Add(new DieDetectionItem { Type = "Installer", Name = "Windows Installer (MSI)" });
        }
        else if (magic.Length >= 4 && magic[0] == (byte)'M' && magic[1] == (byte)'S' && magic[2] == (byte)'C' && magic[3] == (byte)'F')
        {
            result.FileType = "CAB";
            items.Add(new DieDetectionItem { Type = "Archive", Name = "Microsoft Cabinet" });
        }
        else if (magic.Length >= 4 && magic[0] == (byte)'P' && magic[1] == (byte)'K' && magic[2] == 3 && magic[3] == 4)
        {
            result.FileType = "ZIP";
            items.Add(new DieDetectionItem { Type = "Archive", Name = "ZIP / JAR / APK Archive" });
        }
        else
        {
            result.FileType = "Binary";
        }

        result.Sections.Add(new SectionEntropy
        {
            Name = "Whole File",
            Offset = 0,
            Size = fileLength,
            Entropy = result.TotalEntropy,
            Status = result.TotalEntropy > 7.2 ? "packed" : "not packed"
        });

        if (items.Count > 0)
        {
            result.DetectionGroups.Add(new DieDetectionGroup
            {
                FileType = result.FileType,
                FilePart = "Magic Signature",
                Items = items
            });
        }
    }
}
