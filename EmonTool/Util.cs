using System;
using System.Text;

namespace EmonTool
{
	public class Entry
	{
		public string Name { get; set; } = String.Empty;
		public string Path { get; set; } = String.Empty;
		public uint Offset { get; set; }
		public uint PackedSize { get; set; }
		public uint UnpackedSize { get; set; }
		public int LzssFrameSize { get; set; }
		public int LzssInitPos { get; set; }
		public int SubType { get; set; }
		public uint Magic { get; set; }
		public bool IsPacked { get; set; } = true;
	}

	public class EmeMetaData
	{
		public int Bpp { get; set; }
		public int Width { get; set; }
		public int Height { get; set; }   
		public int Colors { get; set; }  
		public int Stride { get; set; }
		public int OffsetX { get; set; }
		public int OffsetY { get; set; }   
	}
	
    public class Utils
    {
		public static unsafe void Encrypt(byte[] buffer, int offset, int length, byte[] routine)
		{
			if (buffer == null)
				throw new ArgumentNullException(nameof(buffer));
			if (offset < 0)
				throw new ArgumentOutOfRangeException(nameof(offset));
			if (buffer.Length - offset < length)
				throw new ArgumentException("Buffer offset and length are out of bounds.");

			fixed (byte* data8 = &buffer[offset])
			{
				uint* data32 = (uint*)data8;
				int length32 = length / 4;

				for (int i = 0; i < 8; i++)
				{
					byte op = routine[i];
					uint key = BitConverter.ToUInt32(routine, 8 + i * 4);

					switch (op)
					{
						case 1: // Simple XOR (self-inverse)
							for (int j = 0; j < length32; j++)
								data32[j] ^= key;
							break;

						case 2: // Chained XOR (forward version)
							{
								uint prev = key;
								for (int j = 0; j < length32; j++)
								{
									uint v = data32[j];
									uint enc = v ^ prev;
									data32[j] = enc;
									prev = enc;
								}
							}
							break;

						case 4: // Bit shift forward
							for (int j = 0; j < length32; j++)
								data32[j] = (uint)ShiftValueEncrypt(data32[j], key);
							break;

						case 8: // Table permutation forward
							TablePermuteEncrypt(buffer, offset, length, key);
							break;
					}
				}
			}
		}

		private static int ShiftValueEncrypt(uint val, uint key)
		{
			// Build inverse mapping for encryption
			int[] forwardMap = new int[32];
			int shift = 0;
			for (int i = 0; i < 32; i++)
			{
				shift += (int)key;
				forwardMap[i] = shift % 32;
			}

			int[] inverseMap = new int[32];
			for (int i = 0; i < 32; i++)
				inverseMap[forwardMap[i]] = i;

			uint result = 0;
			for (int i = 0; i < 32; i++)
			{
				uint bit = (val >> i) & 1;
				result |= bit << inverseMap[i];
			}

			return (int)result;
		}

		private static void TablePermuteEncrypt(byte[] buffer, int offset, int length, uint key)
		{
			if (length == 0) return;

			byte[] table = new byte[length];
			int x = 0;
			for (int i = 0; i < length; i++)
			{
				x = (int)((x + key) % length);
				table[i] = buffer[offset + x];
			}

			Buffer.BlockCopy(table, 0, buffer, offset, length);
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
