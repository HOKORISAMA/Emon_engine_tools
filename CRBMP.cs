using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
using Utility.Compression;

namespace EmonTool
{
    internal class CRBMP
    {
        private const int HEADER_SIZE = 32;

        internal static byte[] EncodeImage(Image image)
        {
            try
            {
                int bpp;
                int stride;
                byte[] rawData;

                if (image is Image<L8> grayscaleImage) // Grayscale
                {
                    bpp = 7;
                    stride = image.Width;
                    rawData = new byte[image.Width * image.Height];
                    grayscaleImage.CopyPixelDataTo(rawData);
                }
                else if (image is Image<Rgb24> rgbImage) // Convert to BGR, 24bpp
                {
                    bpp = 24;
                    stride = ((image.Width * 3 + 3) / 4) * 4;  // Align to 4 bytes
                    rgbImage.Mutate(ctx => ctx.Flip(FlipMode.Vertical));

                    // Copy pixel data and convert RGB to BGR
                    rawData = new byte[image.Width * image.Height * 3];
                    rgbImage.CopyPixelDataTo(rawData);
                    for (int i = 0; i < rawData.Length; i += 3)
                    {
                        // Swap R and B channels
                        (rawData[i], rawData[i + 2]) = (rawData[i + 2], rawData[i]);
                    }
                }
                else if (image is Image<Rgba32> rgbaImage) // Convert to BGRA, 32bpp
                {
                    bpp = 32;
                    stride = image.Width * 4;
                    rgbaImage.Mutate(ctx => ctx.Flip(FlipMode.Vertical));

                    // Copy pixel data and convert RGBA to BGRA
                    rawData = new byte[image.Width * image.Height * 4];
                    rgbaImage.CopyPixelDataTo(rawData);
                    for (int i = 0; i < rawData.Length; i += 4)
                    {
                        // Swap R and B channels
                        (rawData[i], rawData[i + 2]) = (rawData[i + 2], rawData[i]);
                    }
                }
                else
                {
                    throw new InvalidDataException("Unsupported image format");
                }

                if (rawData.Length < stride * image.Height)
                {
                    Array.Resize(ref rawData, stride * image.Height);
                }

                byte[] compressedData = Lzss.Compress(rawData);

                byte[] header = new byte[32];
                BitConverter.GetBytes((short)bpp).CopyTo(header, 0);
                BitConverter.GetBytes((short)image.Width).CopyTo(header, 2);
                BitConverter.GetBytes((short)image.Height).CopyTo(header, 4);
                BitConverter.GetBytes((short)0).CopyTo(header, 6);
                BitConverter.GetBytes(stride).CopyTo(header, 8);

                //header = Utils.Encrypt(header, 0, header.Length, key);
                //header = Utils.ApplyImageHeaderXorMask(header);

                byte[] data = new byte[header.Length + compressedData.Length];
                Array.Copy(header, data, header.Length);
                Array.Copy(compressedData, 0, data, header.Length, compressedData.Length);

                return data;

            }
            catch (Exception e)
            {
                throw new InvalidDataException($"Image encoding error: {e.Message}");
            }
        }
    }
}
