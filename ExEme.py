import os
import struct
import sys
from io import BytesIO

class EmeOpener:
    def __init__(self):
        self.tag = "EME"
        self.description = "Emon Engine resource archive"
        self.signature = 0x44455252  # 'RREDATA'
        self.is_hierarchic = False
        self.can_write = True
        self.extensions = ["eme", "rre"]

    def try_open(self, file_path):
        with open(file_path, "rb") as f:
            if f.read(4) != b"RRED":
                return None
            
            f.seek(-4, 2)
            count = struct.unpack("<I", f.read(4))[0]
            if not self.is_sane_count(count):
                return None

            index_size = count * 0x60
            index_offset = f.tell() - 4 - index_size
            f.seek(index_offset - 40)
            key = f.read(40)
            f.seek(index_offset)
            index = bytearray(f.read(index_size))

        dir_entries = []
        for i in range(count):
            offset = i * 0x60
            self.decrypt(index, offset, 0x60, key)
            name = self.get_c_string(index[offset:offset+0x40])
            entry = EmEntry(name)
            entry.lzss_frame_size = struct.unpack_from("<H", index, offset + 0x40)[0]
            entry.lzss_init_pos = struct.unpack_from("<H", index, offset + 0x42)[0]
            if entry.lzss_frame_size != 0:
                entry.lzss_init_pos = (entry.lzss_frame_size - entry.lzss_init_pos) % entry.lzss_frame_size
            entry.sub_type = struct.unpack_from("<I", index, offset + 0x48)[0]
            entry.size = struct.unpack_from("<I", index, offset + 0x4C)[0]
            entry.unpacked_size = struct.unpack_from("<I", index, offset + 0x50)[0]
            entry.offset = struct.unpack_from("<I", index, offset + 0x54)[0]
            entry.is_packed = entry.unpacked_size != entry.size
            if not entry.check_placement(os.path.getsize(file_path)):
                return None
            if entry.sub_type == 3:
                entry.type = "script"
            elif entry.sub_type == 4:
                entry.type = "image"
            dir_entries.append(entry)

        return EmeArchive(file_path, self, dir_entries, key)

    def open_entry(self, arc, entry):
        if isinstance(entry, EmEntry) and isinstance(arc, EmeArchive):
            if entry.sub_type == 3:
                return self.open_script(arc, entry)
            elif entry.sub_type == 5 and entry.size > 4:
                return self.open_t5(arc, entry)
        
        with open(arc.file_path, "rb") as f:
            f.seek(entry.offset)
            return BytesIO(f.read(entry.size))

    def open_script(self, arc, entry):
        with open(arc.file_path, "rb") as f:
            f.seek(entry.offset)
            header = bytearray(f.read(12))
        self.decrypt(header, 0, 12, arc.key)
        
        if entry.lzss_frame_size == 0:
            with open(arc.file_path, "rb") as f:
                f.seek(entry.offset + 12)
                input_data = f.read(entry.size - 12)
            return BytesIO(header + input_data)
        
        unpacked_size = struct.unpack_from("<I", header, 4)[0]
        if unpacked_size != 0 and unpacked_size < entry.unpacked_size:
            packed_size = struct.unpack_from("<I", header, 0)[0]
            part1_size = entry.unpacked_size - unpacked_size
            data = bytearray(entry.unpacked_size)
            
            with open(arc.file_path, "rb") as f:
                f.seek(entry.offset + 12 + packed_size)
                lzss = LzssStream(BytesIO(f.read(entry.size - 12 - packed_size)))
                lzss.config.frame_size = entry.lzss_frame_size
                lzss.config.frame_init_pos = entry.lzss_init_pos
                data[:part1_size] = lzss.read(part1_size)
                
                f.seek(entry.offset + 12)
                lzss = LzssStream(BytesIO(f.read(packed_size)))
                lzss.config.frame_size = entry.lzss_frame_size
                lzss.config.frame_init_pos = entry.lzss_init_pos
                data[part1_size:] = lzss.read(unpacked_size)
            
            return BytesIO(data)
        else:
            with open(arc.file_path, "rb") as f:
                f.seek(entry.offset + 12)
                lzss = LzssStream(BytesIO(f.read(entry.size - 12)))
                lzss.config.frame_size = entry.lzss_frame_size
                lzss.config.frame_init_pos = entry.lzss_init_pos
                return lzss

    def open_t5(self, arc, entry):
        with open(arc.file_path, "rb") as f:
            f.seek(entry.offset)
            header = bytearray(f.read(4))
        self.decrypt(header, 0, 4, arc.key)
        
        with open(arc.file_path, "rb") as f:
            f.seek(entry.offset + 4)
            input_data = f.read(entry.size - 4)
        
        return BytesIO(header + input_data)

    @staticmethod
    def decrypt(buffer, offset, length, routine):
        data = memoryview(buffer)[offset:offset+length]
        key_index = len(routine)
        for i in range(7, -1, -1):
            key_index -= 4
            key = struct.unpack_from("<I", routine, key_index)[0]
            if routine[i] == 1:
                for j in range(0, len(data), 4):
                    struct.pack_into("<I", data, j, struct.unpack_from("<I", data, j)[0] ^ key)
            elif routine[i] == 2:
                for j in range(0, len(data), 4):
                    v = struct.unpack_from("<I", data, j)[0]
                    struct.pack_into("<I", data, j, v ^ key)
                    key = v
            elif routine[i] == 4:
                for j in range(0, len(data), 4):
                    v = struct.unpack_from("<I", data, j)[0]
                    struct.pack_into("<I", data, j, EmeOpener.shift_value(v, key))
            elif routine[i] == 8:
                EmeOpener.init_table(data, key)

    @staticmethod
    def shift_value(val, key):
        shift = 0
        result = 0
        for i in range(32):
            shift += key
            result |= ((val >> i) & 1) << (shift % 32)
        return result

    @staticmethod
    def init_table(buffer, key):
        length = len(buffer)
        table = bytearray(length)
        x = 0
        for i in range(length):
            x = (x + key) % length
            table[x] = buffer[i]
        buffer[:] = table

    @staticmethod
    def is_sane_count(count):
        return 0 < count < 100000

    @staticmethod
    def get_c_string(buffer):
        return buffer.split(b'\0', 1)[0].decode('ascii')

class EmEntry:
    def __init__(self, name):
        self.name = name
        self.lzss_frame_size = 0
        self.lzss_init_pos = 0
        self.sub_type = 0
        self.size = 0
        self.unpacked_size = 0
        self.offset = 0
        self.is_packed = False
        self.type = ""

    def check_placement(self, max_offset):
        return self.offset + self.size <= max_offset

class EmeArchive:
    def __init__(self, file_path, impl, dir_entries, key):
        self.file_path = file_path
        self.impl = impl
        self.dir = dir_entries
        self.key = key

class LzssStream:
    def __init__(self, input_stream):
        self.input_stream = input_stream
        self.config = LzssSettings()
        self.buffer = bytearray(4096)
        self.buffer_pos = 0
        self.buffer_length = 0
        self.window = bytearray(self.config.frame_size)
        self.window_pos = self.config.frame_init_pos

    def read(self, count):
        result = bytearray()
        while count > 0:
            if self.buffer_pos >= self.buffer_length:
                if not self.fill_buffer():
                    break
            to_copy = min(self.buffer_length - self.buffer_pos, count)
            result.extend(self.buffer[self.buffer_pos:self.buffer_pos+to_copy])
            self.buffer_pos += to_copy
            count -= to_copy
        return bytes(result)

    def fill_buffer(self):
        self.buffer_pos = 0
        self.buffer_length = 0

        flags = self.input_stream.read(1)
        if not flags:
            return False
        flags = flags[0]

        for i in range(8):
            if self.buffer_length >= len(self.buffer):
                break

            if flags & (1 << i) == 0:
                data = self.input_stream.read(2)
                if len(data) < 2:
                    break  # Not enough data to continue

                b1, b2 = data
                offset = ((b2 & 0xF0) << 4) | b1
                length = (b2 & 0x0F) + 3

                for j in range(length):
                    if self.buffer_length >= len(self.buffer):
                        break
                    b = self.window[(offset + j) % self.config.frame_size]
                    self.buffer[self.buffer_length] = b
                    self.buffer_length += 1
                    self.window[self.window_pos] = b
                    self.window_pos = (self.window_pos + 1) % self.config.frame_size
            else:
                b = self.input_stream.read(1)
                if not b:
                    break
                b = b[0]
                self.buffer[self.buffer_length] = b
                self.buffer_length += 1
                self.window[self.window_pos] = b
                self.window_pos = (self.window_pos + 1) % self.config.frame_size

        return self.buffer_length > 0

class LzssSettings:
    def __init__(self):
        self.frame_size = 0x1000
        self.frame_fill = 0
        self.frame_init_pos = 0xFEE

def close_stream(stream):
    if hasattr(stream, 'close'):
        stream.close()
    elif isinstance(stream, BytesIO):
        stream.close()

def main():
    if len(sys.argv) != 3:
        print("Usage: python eme_opener.py <archive_path> <output_directory>")
        return

    archive_path = sys.argv[1]
    output_directory = sys.argv[2]

    if not os.path.exists(archive_path):
        print(f"Archive file not found: {archive_path}")
        return

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    opener = EmeOpener()
    arc_file = opener.try_open(archive_path)
    if arc_file is None:
        print("Failed to open the archive.")
        return

    for entry in arc_file.dir:
        output_path = os.path.join(output_directory, entry.name)
        entry_stream = opener.open_entry(arc_file, entry)
        try:
            with open(output_path, "wb") as output_file:
                while True:
                    chunk = entry_stream.read(8192)  # Read in 8KB chunks
                    if not chunk:
                        break
                    output_file.write(chunk)
            print(f"Extracted: {entry.name}")
        finally:
            close_stream(entry_stream)

    print("Extraction completed.")

if __name__ == "__main__":
    main()
