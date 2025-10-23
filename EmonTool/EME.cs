using System.Text;
using System.Text.Json;
using Compression;
using SixLabors.ImageSharp;

namespace EmonTool
{
    internal class Eme
    {
        private const string Magic = "RREDATA ";
        private const string MetadataFileName = "_metadata.json";

        public void Unpack(string filePath, string folderPath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));
            if (string.IsNullOrEmpty(folderPath))
                throw new ArgumentNullException(nameof(folderPath));
            if (!File.Exists(filePath))
                throw new FileNotFoundException("EME file not found", filePath);

            using var fs = File.OpenRead(filePath);
            using var br = new BinaryReader(fs);

            if (fs.Length < 52)
                throw new InvalidDataException("File is too small to be a valid EME file");

            ValidateMagic(br.ReadBytes(8));

            fs.Position = fs.Length - 4;
            int fileCount = br.ReadInt32();
            if (fileCount < 0)
                throw new InvalidDataException($"Invalid file count: {fileCount}");

            uint indexSize = (uint)fileCount * 0x60;
            if (indexSize > fs.Length - 52)
                throw new InvalidDataException("Index size exceeds file size");

            var indexOffset = fs.Length - 4 - indexSize;
            fs.Position = indexOffset - 40;
            var key = br.ReadBytes(40);

            fs.Position = indexOffset;
            var index = br.ReadBytes((int)indexSize);

            var entries = ParseEntries(index, key, fileCount, fs.Length, folderPath);
            Directory.CreateDirectory(folderPath);

            // Save metadata
            SaveMetadata(folderPath, entries, key);

            foreach (var entry in entries)
            {
                br.BaseStream.Position = entry.Offset;

                switch (entry.SubType)
                {
                    case 3:
                        ExtractScript(br, entry, key);
                        break;
                    case 4:
                        ExtractBmp(br, entry, key, folderPath);
                        break;
                    case 5:
                        ExtractType5(br, entry, key);
                        break;
                    default:
                        ExtractDefault(br, entry);
                        break;
                }
            }
        }

        public void Pack(string folderPath, string filePath, bool encrypt = false)
        {
            if (string.IsNullOrEmpty(folderPath))
                throw new ArgumentNullException(nameof(folderPath));
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"Source directory not found: {folderPath}");

            // Load metadata and key if available
            var metadata = LoadMetadata(folderPath);
            byte[] key = encrypt && metadata != null && !string.IsNullOrEmpty(metadata.Key)
                ? Convert.FromHexString(metadata.Key)
                : new byte[40];

            var files = new DirectoryInfo(folderPath).GetFiles()
                .Where(f => f.Name != MetadataFileName)
                .ToArray();
            var entries = new List<Entry>();

            using var fw = File.OpenWrite(filePath);
            using var bw = new BinaryWriter(fw);

            bw.Write(Encoding.ASCII.GetBytes(Magic));
            uint currentOffset = 8;

            foreach (var file in files)
            {
                var entry = new Entry { Name = file.Name, Offset = currentOffset };

                var metaEntry = metadata?.Entries.FirstOrDefault(e =>
                    Path.GetFileNameWithoutExtension(e.Name) == Path.GetFileNameWithoutExtension(file.Name));

                switch (file.Extension.ToLower())
                {
                    case ".txt":
                        PackTxt(bw, entry, file, metaEntry, key, encrypt);
                        break;
                    case ".ogg":
                        PackOgg(bw, entry, file, metaEntry);
                        break;
                    case ".bmp":
                    case ".png":
                        PackBmp(bw, entry, file, metaEntry, key, encrypt);
                        break;
                    default:
                        continue;
                }

                currentOffset = (uint)fw.Position;
                entries.Add(entry);
            }

            if (encrypt && metadata != null)
                bw.Write(key);
            else
            {
                bw.Write(new byte[40]);
            }

            foreach (var entry in entries)
            {
                if (entry.LzssFrameSize != 0 && metadata != null)
                    entry.LzssInitPos = (ushort)((entry.LzssFrameSize - entry.LzssInitPos) % entry.LzssFrameSize);

                byte[] entryData = new byte[0x60];
                Array.Copy(Encoding.ASCII.GetBytes(entry.Name), entryData, Math.Min(entry.Name.Length, 0x40));

                BitConverter.GetBytes(entry.LzssFrameSize).CopyTo(entryData, 0x40);
                BitConverter.GetBytes(entry.LzssInitPos).CopyTo(entryData, 0x42);
                BitConverter.GetBytes(entry.Magic).CopyTo(entryData, 0x44);
                BitConverter.GetBytes(entry.SubType).CopyTo(entryData, 0x48);
                BitConverter.GetBytes(entry.PackedSize).CopyTo(entryData, 0x4C);
                BitConverter.GetBytes(entry.UnpackedSize).CopyTo(entryData, 0x50);
                BitConverter.GetBytes(entry.Offset).CopyTo(entryData, 0x54);

                if (encrypt && metadata != null)
                {
                    Utils.Encrypt(entryData, 0, entryData.Length, key);
                }

                bw.Write(entryData);
            }


            bw.Write(entries.Count);
        }

        private void SaveMetadata(string folderPath, List<Entry> entries, byte[] key)
        {
            var metadata = new ArchiveMetadata
            {
                Key = Convert.ToHexString(key),
                Entries = entries.Select(e => new Entry
                {
                    Name = e.Name,
                    SubType = e.SubType,
                    Magic = e.Magic,
                    LzssFrameSize = e.LzssFrameSize,
                    LzssInitPos = e.LzssInitPos,
                    UnpackedSize = e.UnpackedSize,
                    Offset = e.Offset,
                    PackedSize = e.PackedSize,
                    IsPacked = e.IsPacked
                }).ToList()
            };

            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(metadata, options);
            File.WriteAllText(Path.Combine(folderPath, MetadataFileName), json);
        }

        private ArchiveMetadata? LoadMetadata(string folderPath)
        {
            string metadataPath = Path.Combine(folderPath, MetadataFileName);
            if (!File.Exists(metadataPath))
                return null;

            try
            {
                string json = File.ReadAllText(metadataPath);
                return JsonSerializer.Deserialize<ArchiveMetadata>(json);
            }
            catch
            {
                return null;
            }
        }

        private List<Entry> ParseEntries(byte[] index, byte[] key, int fileCount, long fileSize, string folderPath)
        {
            var entries = new List<Entry>(fileCount);
            int offset = 0;

            for (int i = 0; i < fileCount; i++)
            {
                Utils.Decrypt(index, offset, 0x60, key);

                var entry = new Entry
                {
                    Name = Utils.GetNullTerminatedString(index, offset, 0x40),
                    LzssFrameSize = BitConverter.ToUInt16(index, offset + 0x40),
                    LzssInitPos = BitConverter.ToUInt16(index, offset + 0x42),
                    Magic = BitConverter.ToUInt32(index, offset + 0x44),
                    SubType = BitConverter.ToUInt16(index, offset + 0x48),
                    PackedSize = BitConverter.ToUInt32(index, offset + 0x4C),
                    UnpackedSize = BitConverter.ToUInt32(index, offset + 0x50),
                    Offset = BitConverter.ToUInt32(index, offset + 0x54)
                };

                if (entry.LzssFrameSize != 0)
                    entry.LzssInitPos = (entry.LzssFrameSize - entry.LzssInitPos) % entry.LzssFrameSize;

                entry.Path = Path.Combine(folderPath, string.Join("_", entry.Name.Split(Path.GetInvalidFileNameChars())));

                if (entry.Offset >= fileSize || entry.PackedSize > fileSize - entry.Offset)
                    throw new InvalidDataException($"Invalid entry data for {entry.Name}");

                entries.Add(entry);
                offset += 0x60;
            }

            return entries;
        }

        private void ExtractDefault(BinaryReader br, Entry entry)
        {
            byte[] data = br.ReadBytes((int)entry.PackedSize);
            if (entry.IsPacked)
                data = Lzss.Decompress(data);
            File.WriteAllBytes(entry.Path, data);
        }

        private void ExtractScript(BinaryReader br, Entry entry, byte[] key)
        {
            byte[] header = br.ReadBytes(12);
            Utils.Decrypt(header, 0, 12, key);

            if (entry.LzssFrameSize == 0)
            {
                byte[] data = new byte[entry.PackedSize + 12];
                Array.Copy(header, 0, data, 0, 12);
                br.Read(data, 12, (int)entry.PackedSize);
                File.WriteAllBytes(entry.Path, data);
                return;
            }

            int part2UnpackedSize = BitConverter.ToInt32(header, 4);
            if (part2UnpackedSize != 0 && part2UnpackedSize < entry.UnpackedSize)
            {
                uint packedSize = BitConverter.ToUInt32(header, 0);
                br.BaseStream.Seek(entry.Offset + 12, SeekOrigin.Begin);

                byte[] part2data = Lzss.Decompress(br.ReadBytes((int)packedSize));
                byte[] part1data = Lzss.Decompress(br.ReadBytes((int)entry.PackedSize));

                byte[] combinedData = new byte[part1data.Length + part2data.Length];
                Array.Copy(part1data, 0, combinedData, 0, part1data.Length);
                Array.Copy(part2data, 0, combinedData, part1data.Length, part2data.Length);

                File.WriteAllBytes(entry.Path, combinedData);
            }
            else
            {
                br.BaseStream.Position = entry.Offset + 12;
                File.WriteAllBytes(entry.Path, Lzss.Decompress(br.ReadBytes((int)entry.PackedSize)));
            }
        }

        private void ExtractBmp(BinaryReader br, Entry entry, byte[] key, string folderPath)
        {
            byte[] header = br.ReadBytes(32);
            Utils.Decrypt(header, 0, 32, key);

            uint entrySize = entry.PackedSize + 32;
            int colors = BitConverter.ToUInt16(header, 6);

            if (colors != 0 && header[0] != 7)
                entrySize += (uint)Math.Max(colors, 3) * 4;

            br.BaseStream.Position = entry.Offset;
            using var image = ExBmp.DecodeImage(br.ReadBytes((int)entrySize), entry, key);

            if (image == null)
                throw new InvalidDataException($"Failed to decode image: {entry.Name}");

            image.SaveAsPng(Path.ChangeExtension(Path.Combine(folderPath, entry.Name), ".bmp"));
        }

        private void ExtractType5(BinaryReader br, Entry entry, byte[] key)
        {
            byte[] data = br.ReadBytes((int)entry.PackedSize);
            Utils.Decrypt(data, 0, 4, key);
            File.WriteAllBytes(entry.Path, data);
        }

        private void PackTxt(BinaryWriter bw, Entry entry, FileInfo file, Entry? metadata, byte[] key, bool encrypt)
        {
            byte[] fileData = File.ReadAllBytes(file.FullName);

            entry.SubType = metadata?.SubType ?? 3;
            entry.Magic = metadata?.Magic ?? 1;
            entry.LzssFrameSize = metadata?.LzssFrameSize ?? 0x1000;
            entry.LzssInitPos = metadata?.LzssInitPos ?? 0x12;
            entry.UnpackedSize = metadata?.UnpackedSize ?? (uint)fileData.Length;

            byte[] header = new byte[12]; // Dummy header.

            if (encrypt && metadata != null)
            {
                Utils.Encrypt(header, 0, header.Length, key);
            }

            byte[] compressed = Lzss.Compress(fileData);
            entry.PackedSize = (uint)compressed.Length;

            bw.Write(header);
            bw.Write(compressed);
        }

        private void PackOgg(BinaryWriter bw, Entry entry, FileInfo file, Entry? metadata)
        {
            entry.PackedSize = entry.UnpackedSize = (uint)file.Length;
            entry.SubType = metadata?.SubType ?? 0;
            entry.Magic = metadata?.Magic ?? 0x20400000u;
            entry.LzssFrameSize = metadata?.LzssFrameSize ?? 0x1000;
            entry.LzssInitPos = metadata?.LzssInitPos ?? 0x12;

            bw.Write(File.ReadAllBytes(file.FullName));
        }

        private void PackBmp(BinaryWriter bw, Entry entry, FileInfo file, Entry? metadata, byte[] key, bool encrypt)
        {
            entry.SubType = metadata?.SubType ?? 4;
            entry.Magic = metadata?.Magic ?? 0x10;
            entry.LzssFrameSize = metadata?.LzssFrameSize ?? 0x1000;
            entry.LzssInitPos = metadata?.LzssInitPos ?? 0x12;

            using var image = Image.Load(file.FullName);
            byte[] imgData = CrBmp.EncodeImage(image);

            int colors = BitConverter.ToUInt16(imgData, 6);
            entry.PackedSize = (uint)(imgData.Length - 32 -
                (imgData[0] != 7 && colors != 0 ? Math.Max(colors, 3) * 4 : 0));
            entry.UnpackedSize = metadata?.UnpackedSize ?? (uint)file.Length;

            if (encrypt && metadata != null)
            {
                Utils.Encrypt(imgData, 0, 32, key);
            }

            bw.Write(imgData);
        }

        private void ValidateMagic(byte[] magic)
        {
            string magicRead = Encoding.ASCII.GetString(magic);
            if (magicRead != Magic)
                throw new InvalidDataException($"Invalid file magic. Expected '{Magic}', got '{magicRead}'");
        }
    }

    public class ArchiveMetadata
    {
        public string Key { get; set; } = string.Empty;
        public List<Entry> Entries { get; set; } = new();
    }
}
