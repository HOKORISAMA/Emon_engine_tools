import os
import struct
import sys
import json
from io import BytesIO
import lzss


class EmeArchive:
    def __init__(self, path):
        self.path = path
        self.entries = []
        self.key = None
        self._load()

    def _load(self):
        with open(self.path, "rb") as f:
            # Check signature
            if f.read(4) != b"RRED":
                raise ValueError("Invalid archive signature")

            # Read entry count from end of file
            f.seek(-4, os.SEEK_END)
            count = struct.unpack("<I", f.read(4))[0]
            if not 0 < count < 100000:
                raise ValueError(f"Invalid entry count: {count}")

            # Read key and index
            index_size = count * 0x60
            index_offset = f.tell() - 4 - index_size
            f.seek(index_offset - 40)
            self.key = f.read(40)
            f.seek(index_offset)
            index = bytearray(f.read(index_size))

        # Parse entries
        for i in range(count):
            offset = i * 0x60
            self._decrypt(index, offset, 0x60)

            name = index[offset:offset + 0x40].split(b'\0', 1)[0].decode('ascii')
            lzss_frame_size = struct.unpack_from("<H", index, offset + 0x40)[0]
            lzss_init_pos = struct.unpack_from("<H", index, offset + 0x42)[0]

            if lzss_frame_size != 0:
                lzss_init_pos = (lzss_frame_size - lzss_init_pos) % lzss_frame_size

            entry = {
                'name': name,
                'sub_type': struct.unpack_from("<I", index, offset + 0x48)[0],
                'magic' : struct.unpack_from("<H", index, offset + 0x44)[0],
                'packed_size': struct.unpack_from("<I", index, offset + 0x4C)[0],
                'unpacked_size': struct.unpack_from("<I", index, offset + 0x50)[0],
                'offset': struct.unpack_from("<I", index, offset + 0x54)[0],
                'lzss_frame_size': lzss_frame_size,
                'lzss_init_pos': lzss_init_pos,
            }
            entry['is_packed'] = entry['unpacked_size'] != entry['packed_size']

            if entry['offset'] + entry['packed_size'] > os.path.getsize(self.path):
                raise ValueError(f"Entry {name} extends beyond file")

            self.entries.append(entry)

    def _decrypt(self, buffer, offset, length):
        data = memoryview(buffer)[offset:offset + length]
        key_index = len(self.key)

        for i in range(7, -1, -1):
            key_index -= 4
            key = struct.unpack_from("<I", self.key, key_index)[0]

            if self.key[i] == 1:
                for j in range(0, len(data), 4):
                    val = struct.unpack_from("<I", data, j)[0]
                    struct.pack_into("<I", data, j, val ^ key)

            elif self.key[i] == 2:
                for j in range(0, len(data), 4):
                    val = struct.unpack_from("<I", data, j)[0]
                    struct.pack_into("<I", data, j, val ^ key)
                    key = val

            elif self.key[i] == 4:
                for j in range(0, len(data), 4):
                    val = struct.unpack_from("<I", data, j)[0]
                    shift = 0
                    result = 0
                    for k in range(32):
                        shift += key
                        result |= ((val >> k) & 1) << (shift % 32)
                    struct.pack_into("<I", data, j, result)

            elif self.key[i] == 8:
                table = bytearray(len(data))
                x = 0
                for k in range(len(data)):
                    x = (x + key) % len(data)
                    table[x] = data[k]
                data[:] = table

    def extract(self, entry):
        with open(self.path, "rb") as f:
            # Read and decrypt 12-byte header
            f.seek(entry['offset'])
            header = bytearray(f.read(12))
            self._decrypt(header, 0, 12)

            # Case A — no compression
            if entry['lzss_frame_size'] == 0:
                f.seek(entry['offset'] + 12)
                raw = f.read(entry['packed_size'])
                return BytesIO(header + raw)

            # Read part2 unpacked size
            part2_unpacked_size = struct.unpack_from("<I", header, 4)[0]

            # Case B — split compression
            if part2_unpacked_size != 0 and part2_unpacked_size < entry['unpacked_size']:
                packed_size = struct.unpack_from("<I", header, 0)[0]

                f.seek(entry['offset'] + 12)
                # Read part2 first (smaller part), then part1 (main part)
                part2_compressed = f.read(packed_size)
                part1_compressed = f.read(entry['packed_size'])
                
                # Decompress in the same order as C# code
                part2_data = lzss.decode(part2_compressed, part2_unpacked_size)
                part1_data = lzss.decode(part1_compressed, entry['unpacked_size'])

                # Combine in correct order (part1 + part2)
                combined = part1_data + part2_data
                return BytesIO(combined)

            # Case C — normal compression (single part)
            f.seek(entry['offset'] + 12)
            compressed = f.read(entry['packed_size'])
            data = lzss.decode(compressed, entry['unpacked_size'])
            return BytesIO(data)

    def save_metadata(self, output_dir):
        metadata = {
            "key": self.key.hex().upper(),
            "entries": [
                {
                    "name": e['name'],
                    "path": "",
                    "offset": e['offset'],
                    "packed_size": e['packed_size'],
                    "unpacked_size": e['unpacked_size'],
                    "lzss_frame_size": e['lzss_frame_size'],
                    "lzss_init_pos": e['lzss_init_pos'],
                    "sub_type": e['sub_type'],
                    "magic" : e['magic'],
                    "is_packed": e['is_packed']
                }
                for e in self.entries
            ]
        }

        with open(os.path.join(output_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)

    def extract_all(self, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        self.save_metadata(output_dir)
        print(f"Created metadata.json")

        for entry in self.entries:
            stream = self.extract(entry)
            output_path = os.path.join(output_dir, entry['name'])
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(output_path, "wb") as f:
                f.write(stream.read())

            print(f"Extracted: {entry['name']}")


def main():
    if len(sys.argv) != 3:
        print("Usage: python eme_opener.py <archive_path> <output_directory>")
        sys.exit(1)

    archive_path = sys.argv[1]
    output_dir = sys.argv[2]

    if not os.path.exists(archive_path):
        print(f"Archive file not found: {archive_path}")
        sys.exit(1)

    try:
        archive = EmeArchive(archive_path)
        archive.extract_all(output_dir)
        print("Extraction completed.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
