#Can be used to extarct the image archives and converts them to pngs.

import struct
from PIL import Image
from pathlib import Path
from lzss import decompress

class EmeError(Exception):
    pass

class EmeDecodingError(EmeError):
    pass

class EmEntry:
    def __init__(self, data: bytes, offset: int):
        self.name = self._get_null_terminated_string(data, offset, 0x40)
        self.lzss_frame_size = struct.unpack_from('<H', data, offset + 0x40)[0]
        self.lzss_init_pos = struct.unpack_from('<H', data, offset + 0x42)[0]
        self.sub_type = struct.unpack_from('<I', data, offset + 0x48)[0]
        self.size = struct.unpack_from('<I', data, offset + 0x4C)[0]
        self.unpacked_size = struct.unpack_from('<I', data, offset + 0x50)[0]
        self.offset = struct.unpack_from('<I', data, offset + 0x54)[0]
        self.is_packed = self.unpacked_size != self.size

    @staticmethod
    def _get_null_terminated_string(data: bytes, offset: int, max_length: int) -> str:
        end = data.find(b'\0', offset, offset + max_length)
        if end == -1:
            end = offset + max_length
        return data[offset:end].decode('ascii')

class EmeArchive:
    SIGNATURE = b'RRED'
    HEADER_SIZE = 32

    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.key: bytes = b''
        self.entries: list[EmEntry] = []

    def open(self) -> bool:
        try:
            with open(self.filepath, 'rb') as f:
                if f.read(4) != self.SIGNATURE or f.read(4) != b'ATA ':
                    return False

                f.seek(0, 2)
                file_size = f.tell()
                f.seek(file_size - 4)
                entry_count = struct.unpack('<I', f.read(4))[0]

                if entry_count > 10000:
                    return False

                index_size = entry_count * 0x60
                index_offset = file_size - 4 - index_size

                f.seek(index_offset - 40)
                self.key = f.read(40)

                f.seek(index_offset)
                index_data = bytearray(f.read(index_size))

                for offset in range(0, index_size, 0x60):
                    self._decrypt(index_data, offset, 0x60)
                    self.entries.append(EmEntry(index_data, offset))

                return True

        except (IOError, struct.error) as e:
            print(f"Error opening archive: {e}")
            return False

    def _decrypt(self, buffer: bytearray, offset: int, length: int) -> None:
        data = memoryview(buffer)[offset:offset + length]
        key_index = len(self.key)

        for i in range(7, -1, -1):
            key_index -= 4
            key = struct.unpack_from("<I", self.key, key_index)[0]

            if self.key[i] == 1:
                for j in range(0, len(data), 4):
                    struct.pack_into("<I", data, j, struct.unpack_from("<I", data, j)[0] ^ key)
            elif self.key[i] == 2:
                for j in range(0, len(data), 4):
                    v = struct.unpack_from("<I", data, j)[0]
                    struct.pack_into("<I", data, j, v ^ key)
                    key = v
            elif self.key[i] == 4:
                for j in range(0, len(data), 4):
                    v = struct.unpack_from("<I", data, j)[0]
                    struct.pack_into("<I", data, j, self._shift_value(v, key))
            elif self.key[i] == 8:
                self._init_table(data, key)

    def _shift_value(self, val: int, key: int) -> int:
        shift = 0
        result = 0
        for i in range(32):
            shift += key
            result |= ((val >> i) & 1) << (shift % 32)
        return result

    def _init_table(self, buffer: memoryview, key: int) -> None:
        length = len(buffer)
        table = bytearray(length)
        x = 0
        for i in range(length):
            x = (x + key) % length
            table[x] = buffer[i]
        buffer[:] = table

    def extract(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)

        with open(self.filepath, 'rb') as f:
            for entry in self.entries:
                try:
                    output_path = output_dir / entry.name
                    output_path.parent.mkdir(parents=True, exist_ok=True)

                    if entry.sub_type == 4:
                        f.seek(entry.offset)
                        data = f.read(entry.size + self.HEADER_SIZE)
                        image = self._decode_image(data, entry)
                        if image:
                            image.save(output_path.with_suffix('.png'))
                        else:
                            raise EmeDecodingError("Failed to decode image")
                    else:
                        f.seek(entry.offset)
                        with open(output_path, 'wb') as out:
                            out.write(f.read(entry.size))

                except (IOError, EmeError, struct.error) as e:
                    print(f"Error extracting {entry.name}: {e}")

    def _decode_image(self, data: bytes, entry: EmEntry) -> Image.Image:
        try:
            if len(data) < self.HEADER_SIZE:
                raise EmeDecodingError("Failed to decode header")

            header = bytearray(data[:self.HEADER_SIZE])
            self._decrypt(header, 0, self.HEADER_SIZE)

            bpp = struct.unpack_from('<H', header, 0)[0] & 0xFF
            width = struct.unpack_from('<H', header, 2)[0]
            height = struct.unpack_from('<H', header, 4)[0]
            colors = struct.unpack_from('<H', header, 6)[0]
            stride = struct.unpack_from('<i', header, 8)[0]
            offset_x = struct.unpack_from('<i', header, 0xC)[0]
            offset_y = struct.unpack_from('<i', header, 0x10)[0]
            data_offset = self.HEADER_SIZE

            palette = None
            if colors != 0 and (data[self.HEADER_SIZE] & 0xFF) != 7:
                palette = self._read_palette(data, data_offset, max(colors, 3))
                data_offset += max(colors, 3) * 4

            pixel_data = bytearray(stride * height)
            if entry.lzss_frame_size != 0:
                compressed_data = data[data_offset:data_offset + entry.size - data_offset]
                decompressed_data,_ = decompress(compressed_data)
                pixel_data[:len(decompressed_data)] = decompressed_data
            else:
                pixel_data_size = min(len(data) - data_offset, len(pixel_data))
                pixel_data[:pixel_data_size] = data[data_offset:data_offset + pixel_data_size]

            if bpp == 7:
                img = Image.frombytes('L', (width, height), bytes(pixel_data), 'raw', 'L')
            elif bpp == 32:
                img = Image.frombytes('RGBA', (width, height), bytes(pixel_data), 'raw', 'BGRA')
            elif bpp == 24:
                img = Image.frombytes('RGB', (width, height), bytes(pixel_data), 'raw', 'BGR')
            elif palette:
                img = Image.frombytes('P', (width, height), bytes(pixel_data), 'raw', 'P')
                img.putpalette([x for rgb in palette for x in rgb])
            else:
                raise EmeDecodingError("Unsupported image format")

            return img.transpose(Image.FLIP_TOP_BOTTOM) if bpp != 7 else img

        except (struct.error, ValueError, IOError) as e:
            raise EmeDecodingError(f"Image decoding error: {e}")

    @staticmethod
    def _read_palette(data: bytes, offset: int, colors: int) -> list:
        palette = []
        for i in range(colors):
            idx = offset + i * 4
            b, g, r, _ = struct.unpack_from('BBBB', data, idx)
            palette.append((r, g, b))
        return palette

def main():
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python eme_extract.py <archive.eme> <output_directory>")
        sys.exit(1)
    
    archive_path = Path(sys.argv[1])
    if not archive_path.exists():
        print(f"Archive file not found: {archive_path}")
        sys.exit(1)
    
    archive = EmeArchive(archive_path)
    if not archive.open():
        print("Failed to open archive")
        sys.exit(1)
    
    archive.extract(Path(sys.argv[2]))
    print("Extraction complete!")

if __name__ == '__main__':
    main()
