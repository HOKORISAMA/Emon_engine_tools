using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using System.Buffers.Binary;
using Compression;

namespace EmonTool
{
    internal class ExBmp
    {
        private const int HeaderSize = 32;
        public static Image DecodeImage(byte[] data, Entry entry, byte[] key)
        {
            try
            {
                if (data.Length < HeaderSize)
                    throw new InvalidDataException("Failed to decode header");

                var header = data[..HeaderSize].ToArray();
                Utils.Decrypt(header, 0, HeaderSize, key);

                EmeMetaData metaData = new EmeMetaData();
                metaData.Bpp = (ushort)BitConverter.ToUInt16(header, 0) & 0xFF;
                metaData.Width = BitConverter.ToUInt16(header, 2);
                metaData.Height = BitConverter.ToUInt16(header, 4);
                metaData.Colors = BitConverter.ToUInt16(header, 6);
                metaData.Stride = BitConverter.ToUInt16(header, 8);
                metaData.OffsetX = (int)BitConverter.ToUInt32(header, 0xC);
                metaData.OffsetY = (int)BitConverter.ToUInt32(header, 0x10);

                int dataOffset = HeaderSize;
                List<(byte R, byte G, byte B)>? palette = null;

                if (metaData.Colors > 0 && (data[HeaderSize] & 0xFF) != 7)
                {
                    int actualColors = Math.Max(metaData.Colors, 3);
                    palette = ReadPalette(data, dataOffset, actualColors);
                    dataOffset += actualColors * 4;
                }

                byte[] pixelData;
                if (entry.IsPacked)
                {
                    byte[] compressedData = new byte[entry.PackedSize - (dataOffset - HeaderSize)];
                    Array.Copy(data, dataOffset, compressedData, 0, compressedData.Length);
                    pixelData = Lzss.Decompress(compressedData);
                }
                else
                {
                    pixelData = new byte[metaData.Stride * metaData.Height];
                    int copySize = Math.Min(data.Length - dataOffset, pixelData.Length);
                    Array.Copy(data, dataOffset, pixelData, 0, copySize);
                }

                Image image;

                if (metaData.Bpp == 7)
                {
                    image = Image.LoadPixelData<L8>(pixelData, metaData.Width, metaData.Height);
                }
                else if (metaData.Bpp == 32)
                {
                    var rgbaImage = new Image<Rgba32>(metaData.Width, metaData.Height);
                    for (int y = 0; y <  metaData.Height; y++)
                    {
                        int srcY =  metaData.Height - 1 - y;
                        int rowOffset = srcY * metaData.Stride;
                        for (int x = 0; x < metaData.Width; x++)
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
                else if (metaData.Bpp == 24)
                {
                    var rgbImage = new Image<Rgb24>(metaData.Width, metaData.Height);
                    int rowPadding = metaData.Stride - (metaData.Width * 3);

                    for (int y = 0; y < metaData.Height; y++)
                    {
                        int srcY = metaData.Height - 1 - y;  // Flip vertically
                        int rowOffset = srcY * metaData.Stride;

                        for (int x = 0; x < metaData.Width; x++)
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
                    var rgbImage = new Image<Rgb24>(metaData.Width, metaData.Height);
                    for (int y = 0; y < metaData.Height; y++)
                    {
                        int srcY = metaData.Height - 1 - y;
                        int rowOffset = srcY * metaData.Stride;
                        for (int x = 0; x < metaData.Width; x++)
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
