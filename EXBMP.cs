using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using System.Buffers.Binary;
using Utility.Compression;

namespace EmonTool
{
    internal class EXBMP
    {
        private const int HEADER_SIZE = 32;
        public static Image DecodeImage(byte[] data, Utils.Entry entry, byte[] key)
        {
            try
            {
                if (data.Length < HEADER_SIZE)
                    throw new InvalidDataException("Failed to decode header");

                var header = data[..HEADER_SIZE].ToArray();
                Utils.Decrypt(header, 0, HEADER_SIZE, key);

                ushort bpp = (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(0)) & 0xFF);
                int width = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(2));
                int height = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(4));
                int colors = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(6));
                int stride = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(8));
                int offsetX = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(0xC));
                int offsetY = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(0x10));

                int dataOffset = HEADER_SIZE;
                List<(byte R, byte G, byte B)>? palette = null;

                if (colors > 0 && (data[HEADER_SIZE] & 0xFF) != 7)
                {
                    int actualColors = Math.Max(colors, 3);
                    palette = ReadPalette(data, dataOffset, actualColors);
                    dataOffset += actualColors * 4;
                }

                byte[] pixelData;
                if (entry.IsPacked)
                {
                    byte[] compressedData = new byte[entry.PackedSize - (dataOffset - HEADER_SIZE)];
                    Array.Copy(data, dataOffset, compressedData, 0, compressedData.Length);
                    pixelData = Lzss.Decompress(compressedData);
                }
                else
                {
                    pixelData = new byte[stride * height];
                    int copySize = Math.Min(data.Length - dataOffset, pixelData.Length);
                    Array.Copy(data, dataOffset, pixelData, 0, copySize);
                }

                Image image;

                if (bpp == 7)
                {
                    image = Image.LoadPixelData<L8>(pixelData, width, height);
                }
                else if (bpp == 32)
                {
                    var rgbaImage = new Image<Rgba32>(width, height);
                    for (int y = 0; y < height; y++)
                    {
                        int srcY = height - 1 - y;
                        int rowOffset = srcY * stride;
                        for (int x = 0; x < width; x++)
                        {
                            int pixelOffset = rowOffset + (x * 4);
                            if (pixelOffset + 4 <= pixelData.Length)
                            {
                                rgbaImage[x, y] = new Rgba32(
                                    pixelData[pixelOffset + 2],  // R
                                    pixelData[pixelOffset + 1],  // G
                                    pixelData[pixelOffset],      // B
                                    pixelData[pixelOffset + 3]   // A
                                );
                            }
                        }
                    }
                    image = rgbaImage;
                }
                else if (bpp == 24)
                {
                    var rgbImage = new Image<Rgb24>(width, height);
                    int rowPadding = stride - (width * 3);

                    for (int y = 0; y < height; y++)
                    {
                        int srcY = height - 1 - y;  // Flip vertically
                        int rowOffset = srcY * stride;

                        for (int x = 0; x < width; x++)
                        {
                            int pixelOffset = rowOffset + (x * 3);
                            if (pixelOffset + 3 <= pixelData.Length)
                            {
                                rgbImage[x, y] = new Rgb24(
                                    pixelData[pixelOffset + 2],  // R
                                    pixelData[pixelOffset + 1],  // G
                                    pixelData[pixelOffset]       // B
                                );
                            }
                        }
                    }
                    image = rgbImage;
                }
                else if (palette != null)
                {
                    var rgbImage = new Image<Rgb24>(width, height);
                    for (int y = 0; y < height; y++)
                    {
                        int srcY = height - 1 - y;
                        int rowOffset = srcY * stride;
                        for (int x = 0; x < width; x++)
                        {
                            int pixelOffset = rowOffset + x;
                            if (pixelOffset < pixelData.Length)
                            {
                                byte paletteIndex = pixelData[pixelOffset];
                                if (paletteIndex < palette.Count)
                                {
                                    var (r, g, b) = palette[paletteIndex];
                                    rgbImage[x, y] = new Rgb24(r, g, b);
                                }
                            }
                        }
                    }
                    image = rgbImage;
                }
                else
                {
                    throw new InvalidDataException("Unsupported image format");
                }

                return image;
            }
            catch (Exception ex)
            {
                throw new InvalidDataException($"Image decoding error: {ex.Message}");
            }
        }
        private static List<(byte R, byte G, byte B)> ReadPalette(byte[] data, int offset, int colors)
        {
            var palette = new List<(byte R, byte G, byte B)>(colors);
            for (int i = 0; i < colors; i++)
            {
                int idx = offset + (i * 4);
                if (idx + 2 >= data.Length)
                    break;

                palette.Add((
                    data[idx + 2],  // R
                    data[idx + 1],  // G
                    data[idx]       // B
                ));
            }
            return palette;
        }

    }
}