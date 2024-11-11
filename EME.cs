using System.Text;
using Utility.Compression;
using SixLabors.ImageSharp;

namespace EmonTool
{
    internal class EME
    {
        private string Magic => "RREDATA ";
        public void Unpack(string filePath, string folderPath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath), "File path cannot be null or empty");
            if (string.IsNullOrEmpty(folderPath))
                throw new ArgumentNullException(nameof(folderPath), "Folder path cannot be null or empty");
            if (!File.Exists(filePath))
                throw new FileNotFoundException("EME file not found", filePath);

            using (FileStream fs = File.OpenRead(filePath))
            using (BinaryReader br = new BinaryReader(fs))
            {
                try
                {
                    // Validate file size
                    if (fs.Length < 52) // 8 (magic) + 40 (key) + 4 (count)
                        throw new InvalidDataException("File is too small to be a valid EME file");

                    // Read and validate magic
                    string magicRead = Encoding.ASCII.GetString(br.ReadBytes(8));
                    if (magicRead != Magic)
                        throw new InvalidDataException($"Invalid file magic. Expected '{Magic}', got '{magicRead}'");

                    // Read file count
                    fs.Position = fs.Length - 4;
                    int fileCount = br.ReadInt32();
                    if (fileCount < 0)
                        throw new InvalidDataException($"Invalid file count: {fileCount}");

                    // Calculate and validate index size
                    uint indexSize = (uint)fileCount * 0x60;
                    if (indexSize > fs.Length - 52)
                        throw new InvalidDataException("Index size exceeds file size");

                    var indexOffset = fs.Length - 4 - indexSize;
                    fs.Position = indexOffset - 40;
                    var key = br.ReadBytes(40);

                    fs.Position = indexOffset;
                    var index = br.ReadBytes((int)indexSize);

                    int currentOffset = 0;
                    var entries = new List<Utils.Entry>(fileCount);

                    for (int i = 0; i < fileCount; i++)
                    {
                        try
                        {
                            Utils.Entry entry = new Utils.Entry();
                            Utils.Decrypt(index, currentOffset, 0x60, key);

                            if (currentOffset + 0x60 > index.Length)
                                throw new InvalidDataException($"Index entry {i} exceeds buffer size");

                            entry.Name = Utils.GetNullTerminatedString(index, currentOffset, 0x40);
                            if (string.IsNullOrEmpty(entry.Name))
                                throw new InvalidDataException($"Invalid entry name at index {i}");

                            // Sanitize file path
                            string safeName = string.Join("_", entry.Name.Split(Path.GetInvalidFileNameChars()));
                            entry.Path = Path.Combine(folderPath, safeName);

                            entry.LzssFrameSize = BitConverter.ToUInt16(index, currentOffset + 0x40);
                            entry.LzssInitPos = BitConverter.ToUInt16(index, currentOffset + 0x42);

                            if (entry.LzssFrameSize != 0)
                                entry.LzssInitPos = (entry.LzssFrameSize - entry.LzssInitPos) % entry.LzssFrameSize;

                            entry.SubType = BitConverter.ToUInt16(index, currentOffset + 0x48);
                            entry.PackedSize = BitConverter.ToUInt32(index, currentOffset + 0x4C);
                            entry.UnpackedSize = BitConverter.ToUInt32(index, currentOffset + 0x50);
                            entry.Offset = BitConverter.ToUInt32(index, currentOffset + 0x54);

                            // Validate entry
                            if (entry.Offset >= fs.Length)
                                throw new InvalidDataException($"Entry offset exceeds file size for {entry.Name}");
                            if (entry.PackedSize > fs.Length - entry.Offset)
                                throw new InvalidDataException($"Entry packed size exceeds remaining file size for {entry.Name}");

                            entries.Add(entry);
                            currentOffset += 0x60;
                        }
                        catch (Exception ex)
                        {
                            throw new InvalidDataException($"Error processing entry {i}", ex);
                        }
                    }

                    // Create output directory
                    try
                    {
                        Directory.CreateDirectory(folderPath);
                    }
                    catch (Exception ex)
                    {
                        throw new IOException($"Failed to create output directory: {folderPath}", ex);
                    }

                    // Extract files
                    foreach (var entry in entries)
                    {
                        try
                        {
                            if (entry.SubType == 3)
                            {
                                ExtractScript(br, entry, key);
                            }
                            else if (entry.SubType == 4)
                            {
                                ExtractBMP(br, entry, key, folderPath);
                            }
                            else if (entry.SubType == 5 && entry.PackedSize > 4)
                            {
                                ExtractType5(br, entry, key);
                            }
                            else
                            {
                                throw new InvalidDataException($"Unknow File Type : {entry.Name}");
                            }
                        }
                        catch (Exception ex)
                        {
                            throw new InvalidOperationException($"Failed to extract file: {entry.Name}", ex);
                        }
                    }
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("Failed to unpack EME file", ex);
                }
            }
        }

        private void ExtractScript(BinaryReader br, Utils.Entry entry, byte[] key)
        {
            try
            {
                br.BaseStream.Position = entry.Offset;
                byte[] header = br.ReadBytes(12);
                if (header.Length < 12)
                    throw new InvalidDataException("Script header is too small");

                Utils.Decrypt(header, 0, 12, key);

                if (entry.LzssFrameSize == 0)
                {
                    byte[] data = new byte[entry.PackedSize + 12];
                    Array.Copy(header, 0, data, 0, 12);
                    int bytesRead = br.Read(data, 12, (int)entry.PackedSize);
                    if (bytesRead != entry.PackedSize)
                        throw new InvalidDataException("Failed to read complete script data");
                    File.WriteAllBytes(entry.Path, data);
                    return;
                }

                int part2unpackedSize = BitConverter.ToInt32(header, 4);
                if (0 != part2unpackedSize && part2unpackedSize < entry.UnpackedSize)
                {
                    uint packedSize = BitConverter.ToUInt32(header, 0);
                    if (packedSize > entry.PackedSize)
                        throw new InvalidDataException("Invalid packed size in script header");

                    br.BaseStream.Seek(entry.Offset + 12, SeekOrigin.Begin);
                    byte[] part2data = br.ReadBytes((int)packedSize);
                    part2data = Lzss.Decompress(part2data);

                    br.BaseStream.Seek(entry.Offset + 12 + packedSize, SeekOrigin.Begin);
                    int part1UnpackedSize = (int)entry.PackedSize;
                    byte[] part1data = br.ReadBytes(part1UnpackedSize);
                    part1data = Lzss.Decompress(part1data);

                    byte[] combinedData = new byte[part1data.Length + part2data.Length];
                    Array.Copy(part1data, 0, combinedData, 0, part1data.Length);
                    Array.Copy(part2data, 0, combinedData, part1data.Length, part2data.Length);

                    File.WriteAllBytes(entry.Path, combinedData);
                }
                else
                {
                    br.BaseStream.Position = entry.Offset + 12;
                    byte[] data = br.ReadBytes((int)entry.PackedSize);
                    data = Lzss.Decompress(data);
                    File.WriteAllBytes(entry.Path, data);
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to extract script: {entry.Name}", ex);
            }
        }

        private void ExtractBMP(BinaryReader br, Utils.Entry entry, byte[] key, string folderPath)
        {
            try
            {
                string outPath = Path.Combine(folderPath, entry.Name);
                br.BaseStream.Position = entry.Offset;
                byte[] header = br.ReadBytes(32);
                if (header.Length < 32)
                    throw new InvalidDataException("BMP header is too small");

                Utils.Decrypt(header, 0, 32, key);

                uint entrySize = entry.PackedSize + 32;
                int colors = BitConverter.ToUInt16(header, 6);

                if (0 != colors && header[0] != 7)
                {
                    entrySize += (uint)Math.Max(colors, 3) * 4;
                }
                br.BaseStream.Position = entry.Offset;
                byte[] data = br.ReadBytes((int)entrySize);

                if (entrySize > br.BaseStream.Length - entry.Offset)
                    throw new InvalidDataException("BMP data exceeds file size");
                using var image = EXBMP.DecodeImage(data, entry, key);
                if (image != null)
                {
                    string pngPath = Path.ChangeExtension(outPath, ".bmp"); //Only extension is bmp the files are png.
                    image.SaveAsPng(pngPath);
                }
                else
                {
                    throw new InvalidDataException($"Failed to decode image: {entry.Name}");
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to extract BMP: {entry.Name}", ex);
            }
        }

        private void ExtractType5(BinaryReader br, Utils.Entry entry, byte[] key)
        {
            try
            {
                br.BaseStream.Position = entry.Offset;
                byte[] data = br.ReadBytes((int)entry.PackedSize);
                if (data.Length < 4)
                    throw new InvalidDataException("Type5 data is too small");

                Utils.Decrypt(data, 0, 4, key);
                File.WriteAllBytes(entry.Path, data);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to extract Type5 file: {entry.Name}", ex);
            }
        }

        public void Pack(string folderPath, string filePath)
        {
            if (string.IsNullOrEmpty(folderPath))
                throw new ArgumentNullException(nameof(folderPath), "Folder path cannot be null or empty");
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath), "File path cannot be null or empty");
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"Source directory not found: {folderPath}");

            try
            {
                byte[] key = new byte[40];
                FileInfo[] files = new DirectoryInfo(folderPath).GetFiles();
                List<Utils.Entry> entries = new List<Utils.Entry>();

                using (FileStream fw = File.OpenWrite(filePath))
                using (BinaryWriter bw = new BinaryWriter(fw))
                {
                    bw.Write(Encoding.ASCII.GetBytes(Magic));
                    uint currentOffset = 8;

                    foreach (FileInfo file in files)
                    {
                        try
                        {
                            Utils.Entry entry = new Utils.Entry();
                            entry.Name = file.Name;
                            entry.Offset = currentOffset;

                            // Create buffer for file name (0x40 bytes)
                            byte[] nameBytes = new byte[0x40];
                            byte[] sourceBytes = Encoding.ASCII.GetBytes(file.Name);
                            Array.Copy(sourceBytes, nameBytes, Math.Min(sourceBytes.Length, 0x40));

                            switch (file.Extension.ToLower())
                            {
                                case ".txt":
                                    PackTxt(bw, entry, file);
                                    break;
                                case ".ogg":
                                    PackOgg(bw, entry, file);
                                    break;
                                case ".bmp":
                                    PackBmp(bw, entry, file);
                                    break;
                                default:
                                    continue;
                            }

                            currentOffset = (uint)fw.Position;
                            entries.Add(entry);
                        }
                        catch (Exception ex)
                        {
                            throw new InvalidOperationException($"Failed to pack file: {file.Name}", ex);
                        }
                    }

                    // Write encryption key
                    bw.Write(key);

                    // Write file index
                    foreach (var entry in entries)
                    {
                        byte[] entryData = new byte[0x60]; // 96 bytes per entry
                        byte[] nameBytes = Encoding.ASCII.GetBytes(entry.Name.ToString());
                        Array.Copy(nameBytes, entryData, nameBytes.Length);

                        BitConverter.GetBytes(entry.LzssFrameSize).CopyTo(entryData, 0x40);
                        BitConverter.GetBytes(entry.LzssInitPos).CopyTo(entryData, 0x42); // lzss_init_pos
                        BitConverter.GetBytes(entry.Magic).CopyTo(entryData, 0x44); // Flag
                        BitConverter.GetBytes(entry.SubType).CopyTo(entryData, 0x48);
                        BitConverter.GetBytes(entry.PackedSize).CopyTo(entryData, 0x4C); // Calculated Size
                        BitConverter.GetBytes(entry.UnpackedSize).CopyTo(entryData, 0x50); // Unpacked Size
                        BitConverter.GetBytes(entry.Offset).CopyTo(entryData, 0x54); // Calculated Offset

                        bw.Write(entryData, 0, entryData.Length);
                    }

                    bw.Write(entries.Count);
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to pack EME file: {filePath}", ex);
            }
        }

        private void PackTxt(BinaryWriter bw, Utils.Entry entry, FileInfo file)
        {
            entry.UnpackedSize = (uint)file.Length;
            entry.SubType = 3;
            entry.Magic = 1;
            entry.LzssFrameSize = 0x1000;
            entry.LzssInitPos = 0x12;

            bw.Write(0);
            bw.Write(0);
            bw.Write(0);

            byte[] packedTXT = Lzss.Compress(File.ReadAllBytes(file.FullName));
            entry.PackedSize = (uint)packedTXT.Length;
            bw.Write(packedTXT);
        }

        private void PackOgg(BinaryWriter bw, Utils.Entry entry, FileInfo file)
        {
            try
            {
                entry.PackedSize = (uint)file.Length;
                entry.UnpackedSize = entry.PackedSize;
                entry.SubType = 0;
                entry.Magic = 0x20400000u;

                byte[] data = File.ReadAllBytes(file.FullName);
                if (data.Length != file.Length)
                    throw new InvalidDataException($"Failed to read complete OGG file: {file.Name}");

                bw.Write(data);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to pack OGG file: {file.Name}", ex);
            }
        }

        private void PackBmp(BinaryWriter bw, Utils.Entry entry, FileInfo file)
        {
            try
            {
                entry.SubType = 4;
                entry.Magic = 0x10;
                entry.LzssFrameSize = 0x1000;
                entry.LzssInitPos = 0x12;

                using var image = Image.Load(file.FullName);
                byte[] imgData = CRBMP.EncodeImage(image);

                // Calculate packed size
                int colors = BitConverter.ToUInt16(imgData, 6);
                if (imgData[0] != 7 && colors != 0)
                {
                    int colorTableSize = Math.Max(colors, 3) * 4;
                    entry.PackedSize = (uint)(imgData.Length - 32 - colorTableSize);
                }
                else
                {
                    entry.PackedSize = (uint)(imgData.Length - 32);
                }
                entry.UnpackedSize = entry.PackedSize;

                // Validate sizes
                if (entry.PackedSize > int.MaxValue)
                    throw new InvalidDataException($"BMP file too large: {file.Name}");

                bw.Write(imgData);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to pack BMP file: {file.Name}", ex);
            }
        }

        // Utility methods for validation
        private bool ValidateHeader(byte[] header, string fileName, int expectedSize)
        {
            if (header == null || header.Length < expectedSize)
            {
                throw new InvalidDataException($"Invalid header size for file: {fileName}");
            }
            return true;
        }

        private bool ValidateFileSize(long size, string fileName)
        {
            if (size <= 0 || size > int.MaxValue)
            {
                throw new InvalidDataException($"Invalid file size for: {fileName}");
            }
            return true;
        }

        private bool ValidateOffset(long offset, long fileSize, string fileName)
        {
            if (offset < 0 || offset >= fileSize)
            {
                throw new InvalidDataException($"Invalid offset for file: {fileName}");
            }
            return true;
        }

        private string SanitizeFileName(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
                return "_unnamed_";

            // Remove invalid characters
            string invalid = new string(Path.GetInvalidFileNameChars());
            foreach (char c in invalid)
            {
                fileName = fileName.Replace(c.ToString(), "_");
            }

            // Ensure the filename isn't too long
            if (fileName.Length > 255)
                fileName = fileName.Substring(0, 255);

            return fileName;
        }

        private void EnsureDirectoryExists(string path)
        {
            string directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                try
                {
                    Directory.CreateDirectory(directory);
                }
                catch (Exception ex)
                {
                    throw new IOException($"Failed to create directory: {directory}", ex);
                }
            }
        }

        private void ValidateEntryBasics(Utils.Entry entry)
        {
            if (entry == null)
                throw new ArgumentNullException(nameof(entry));

            if (string.IsNullOrEmpty(entry.Name))
                throw new InvalidDataException("Entry name cannot be null or empty");

            if (entry.PackedSize > int.MaxValue)
                throw new InvalidDataException($"Packed size too large for entry: {entry.Name}");

            if (entry.UnpackedSize > int.MaxValue)
                throw new InvalidDataException($"Unpacked size too large for entry: {entry.Name}");
        }

        // Custom exceptions for better error handling
        public class EmeFormatException : Exception
        {
            public EmeFormatException(string message) : base(message) { }
            public EmeFormatException(string message, Exception innerException)
                : base(message, innerException) { }
        }

        public class EmeCompressionException : Exception
        {
            public EmeCompressionException(string message) : base(message) { }
            public EmeCompressionException(string message, Exception innerException)
                : base(message, innerException) { }
        }

        public class EmeEncryptionException : Exception
        {
            public EmeEncryptionException(string message) : base(message) { }
            public EmeEncryptionException(string message, Exception innerException)
                : base(message, innerException) { }
        }
    }
}