using System;
using System.Text;

namespace EmonTool
{
    internal class Utils
    {
        public class Entry
        {
            public string Name { get; set; }
            public string Path { get; set; }
            public uint Offset { get; set; }
            public uint PackedSize { get; set; }
            public uint UnpackedSize { get; set; }
            public int LzssFrameSize { get; set; }
            public int LzssInitPos { get; set; }
            public int SubType { get; set; }
            public uint Magic { get; set; }
            public bool IsPacked { get; set; } = true;
        }
        public static byte[] ApplyXorMask(byte[] data)
        {
            byte[] xorMask = StringToByteArray("ca96e2f800000000");
            byte[] transformedData = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                transformedData[i] = (byte)(data[i] ^ xorMask[i % xorMask.Length]);
            }

            return transformedData;
        }

        public static byte[] ApplyHeaderXorMask(byte[] data)
        {
            byte[] xorMask = StringToByteArray("ca0000f8009600000000e200");
            byte[] transformedData = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                transformedData[i] = (byte)(data[i] ^ xorMask[i % xorMask.Length]);
            }

            return transformedData;
        }
        public static byte[] StringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
        public static byte[] Encrypt(byte[] buffer, int offset, int length, byte[] routine)
        {
            byte[] data = new byte[length];
            Array.Copy(buffer, offset, data, 0, length);

            for (int i = 0; i < 8; i++)
            {
                uint key = BitConverter.ToUInt32(routine, 8 + i * 4);

                switch (routine[i])
                {
                    case 1:
                        for (int j = 0; j < data.Length; j += 4)
                        {
                            uint v = BitConverter.ToUInt32(data, j);
                            BitConverter.GetBytes(v ^ key).CopyTo(data, j);
                        }
                        break;

                    case 2:
                        uint prev = 0;
                        for (int j = 0; j < data.Length; j += 4)
                        {
                            uint v = BitConverter.ToUInt32(data, j);
                            uint newVal = v ^ key ^ prev;
                            BitConverter.GetBytes(newVal).CopyTo(data, j);
                            prev = newVal;
                        }
                        break;

                    case 4:
                        for (int j = 0; j < data.Length; j += 4)
                        {
                            uint v = BitConverter.ToUInt32(data, j);
                            int result = RevShiftValue(v, key);
                            BitConverter.GetBytes(result).CopyTo(data, j);
                        }
                        break;

                    case 8:
                        RevInitTable(data, key);
                        break;
                }
            }

            return data;
        }
        private static int RevShiftValue(uint result, uint key)
        {
            uint originalValue = 0;
            int shift = 0;

            for (int i = 0; i < 32; i++)
            {
                shift += (int)key;
                int originalPosition = shift % 32;
                uint bit = (result >> originalPosition) & 1;
                originalValue |= (bit << i);
            }

            return (int)originalValue;
        }

        private static void RevInitTable(Span<byte> buffer, uint key)
        {
            int length = buffer.Length;
            byte[] table = new byte[length];

            int[] xSequence = new int[length];
            int currentX = 0;

            for (int i = 0; i < length; i++)
            {
                currentX = (int)((currentX + key) % length);
                xSequence[i] = currentX;
            }

            int[] invXSequence = new int[length];
            for (int i = 0; i < xSequence.Length; i++)
            {
                invXSequence[xSequence[i]] = i;
            }

            for (int i = 0; i < length; i++)
            {
                table[invXSequence[i]] = buffer[i];
            }

            table.CopyTo(buffer);
        }

        public static byte[] ApplyImageHeaderXorMask(byte[] data)
        {
            byte[] xorMask = Convert.FromHexString("ca96e2d0000000a89f96e27800000000cb82e2f800140000ca86c8f800000000");
            byte[] transformedData = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                transformedData[i] = (byte)(data[i] ^ xorMask[i % xorMask.Length]);
            }

            return transformedData;
        }
        internal static unsafe void Decrypt(byte[] buffer, int offset, int length, byte[] routine)
        {
            if (null == buffer)
            {
                throw new ArgumentNullException("buffer", "Buffer cannot be null.");
            }

            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException("offset", "Buffer offset should be non-negative.");
            }

            if (buffer.Length - offset < length)
            {
                throw new ArgumentException("Buffer offset and length are out of bounds.");
            }

            fixed (byte* data8 = &buffer[offset])
            {
                uint* data32 = (uint*)data8;
                int length32 = length / 4;
                int key_index = routine.Length;
                for (int i = 7; i >= 0; --i)
                {
                    key_index -= 4;
                    uint key = BitConverter.ToUInt32(routine, key_index);
                    switch (routine[i])
                    {
                        case 1:
                            for (int j = 0; j < length32; ++j)
                            {
                                data32[j] ^= key;
                            }

                            break;
                        case 2:
                            for (int j = 0; j < length32; ++j)
                            {
                                uint v = data32[j];
                                data32[j] = v ^ key;
                                key = v;
                            }
                            break;
                        case 4:
                            for (int j = 0; j < length32; ++j)
                            {
                                data32[j] = ShiftValue(data32[j], key);
                            }

                            break;
                        case 8:
                            InitTable(buffer, offset, length, key);
                            break;
                    }
                }
            }
        }

        private static uint ShiftValue(uint val, uint key)
        {
            int shift = 0;
            uint result = 0;
            for (int i = 0; i < 32; ++i)
            {
                shift += (int)key;
                result |= ((val >> i) & 1) << shift;
            }
            return result;
        }

        private static void InitTable(byte[] buffer, int offset, int length, uint key)
        {
            var table = new byte[length];
            int x = 0;
            for (int i = 0; i < length; ++i)
            {
                x += (int)key;
                while (x >= length)
                {
                    x -= length;
                }

                table[x] = buffer[offset + i];
            }
            Buffer.BlockCopy(table, 0, buffer, offset, length);
        }
        public static string GetNullTerminatedString(byte[] data, int offset, int maxLength)
        {
            int end = Array.IndexOf(data, (byte)0, offset, maxLength);
            if (end == -1)
                end = offset + maxLength;

            return Encoding.UTF8.GetString(data, offset, end - offset);
        }

    }
}