#Will be updated soon

#!/usr/bin/env python3
import os
import io
import sys
import struct
import json
from PIL import Image
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass
from lzss import decompress, LZSSError

@dataclass
class EmEntry:
    name: str
    offset: int
    size: int
    unpacked_size: int
    lzss_frame_size: int
    lzss_init_pos: int
    sub_type: int
    is_packed: bool
    # New fields for split entries
    is_split: bool = False
    part2_packed_size: int = 0
    part2_unpacked_size: int = 0

@dataclass
class EmMetaData:
    bpp: int
    width: int
    height: int
    colors: int
    stride: int
    offset_x: int
    offset_y: int
    data_offset: int
    lzss_frame_size: int
    lzss_init_pos: int

class EmeImageDecoder:
    HEADER_SIZE = 32

    def __init__(self, data: bytes, key: bytes, entry: EmEntry):
        self.data = data
        self.key = key
        self.entry = entry
        self.meta: Optional[EmMetaData] = None

    def decode_header(self) -> bool:
        if len(self.data) < self.HEADER_SIZE:
            return False

        header = bytearray(self.data[:self.HEADER_SIZE])
        self.decrypt(header, 0, self.HEADER_SIZE, self.key)

        self.meta = EmMetaData(
            bpp=struct.unpack_from('<H', header, 0)[0] & 0xFF,
            width=struct.unpack_from('<H', header, 2)[0],
            height=struct.unpack_from('<H', header, 4)[0],
            colors=struct.unpack_from('<H', header, 6)[0],
            stride=struct.unpack_from('<i', header, 8)[0],
            offset_x=struct.unpack_from('<i', header, 0xC)[0],
            offset_y=struct.unpack_from('<i', header, 0x10)[0],
            data_offset=self.HEADER_SIZE,
            lzss_frame_size=self.entry.lzss_frame_size,
            lzss_init_pos=self.entry.lzss_init_pos
        )
        return True

    def decrypt(self, buffer: bytearray, offset: int, length: int, routine: bytes) -> None:
        data = memoryview(buffer)[offset:offset + length]
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
                    struct.pack_into("<I", data, j, self.shift_value(v, key))
            elif routine[i] == 8:
                self.init_table(data, key)

    def shift_value(self, val: int, key: int) -> int:
        shift = 0
        result = 0
        for i in range(32):
            shift += key
            result |= ((val >> i) & 1) << (shift % 32)
        return result

    def init_table(self, buffer: memoryview, key: int) -> None:
        length = len(buffer)
        table = bytearray(length)
        x = 0
        for i in range(length):
            x = (x + key) % length
            table[x] = buffer[i]
        buffer[:] = table

    def read_palette(self, data: bytes, offset: int, colors: int) -> list:
        palette = []
        for i in range(colors):
            idx = offset + i * 4
            b, g, r, _ = struct.unpack_from('BBBB', data, idx)
            palette.append((r, g, b))
        return palette

    def decode(self) -> Optional[Image.Image]:
        if not self.decode_header() or not self.meta:
            return None

        # Calculate sizes
        entry_size = self.entry.size + self.HEADER_SIZE
        if self.meta.colors != 0 and (self.data[self.HEADER_SIZE] & 0xFF) != 7:
            entry_size += max(self.meta.colors, 3) * 4

        # Read palette if needed
        palette = None
        data_offset = self.meta.data_offset
        if self.meta.colors != 0:
            palette = self.read_palette(self.data, data_offset, max(self.meta.colors, 3))
            data_offset += max(self.meta.colors, 3) * 4

        # Read pixel data
        pixel_data = bytearray(self.meta.stride * self.meta.height)
        if self.meta.lzss_frame_size != 0:
            try:
                compressed_data = self.data[data_offset:data_offset + self.entry.size - data_offset]
                decompressed_data, _ = decompress(compressed_data)
                pixel_data[:len(decompressed_data)] = decompressed_data
            except LZSSError as e:
                print(f"LZSS decompression error: {e}")
                return None
        else:
            pixel_data_size = min(len(self.data) - data_offset, len(pixel_data))
            pixel_data[:pixel_data_size] = self.data[data_offset:data_offset + pixel_data_size]

        # Create image based on format
        if self.meta.bpp == 7:
            # Grayscale image
            img = Image.frombytes('L', (self.meta.width, self.meta.height), bytes(pixel_data), 'raw', 'L')
        elif self.meta.bpp == 32:
            # BGR32 image
            img = Image.frombytes('RGBA', (self.meta.width, self.meta.height), bytes(pixel_data), 'raw', 'BGRA')
        elif self.meta.bpp == 24:
            # BGR24 image
            img = Image.frombytes('RGB', (self.meta.width, self.meta.height), bytes(pixel_data), 'raw', 'BGR')
        elif palette:
            # Indexed color image
            img = Image.frombytes('P', (self.meta.width, self.meta.height), bytes(pixel_data), 'raw', 'P')
            img.putpalette([x for rgb in palette for x in rgb])
        else:
            return None

        # Flip image if needed (based on original code's CreateFlipped usage)
        if self.meta.bpp not in (7,):
            img = img.transpose(Image.FLIP_TOP_BOTTOM)

        return img

def _extract_image(f, entry: EmEntry, key: bytes, output_path: Path) -> None:
    if entry.sub_type != 4:
        raise ValueError("Not an image entry")

    total_size = entry.size + EmeImageDecoder.HEADER_SIZE
    f.seek(entry.offset)
    data = f.read(total_size)
    
    decoder = EmeImageDecoder(data, key, entry)
    image = decoder.decode()
    
    if image:
        image.save(output_path.with_suffix('.png'))
    else:
        raise ValueError("Failed to decode image")



class EmeArchive(EmeImageDecoder):
    SIGNATURE = b'RRED'
    
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.key: Optional[bytes] = None
        self.entries: List[EmEntry] = []
        
    def read_uint32(self, f, offset: int) -> int:
        f.seek(offset)
        return struct.unpack('<I', f.read(4))[0]
    
    def read_uint16(self, f, offset: int) -> int:
        f.seek(offset)
        return struct.unpack('<H', f.read(2))[0]

    def decrypt(self, buffer: bytearray, offset: int, length: int, routine: bytes) -> None:
        data = memoryview(buffer)[offset:offset + length]
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
                    struct.pack_into("<I", data, j, self.shift_value(v, key))
            elif routine[i] == 8:
                self.init_table(data, key)

    def shift_value(self, val: int, key: int) -> int:
        shift = 0
        result = 0
        for i in range(32):
            shift += key
            result |= ((val >> i) & 1) << (shift % 32)
        return result

    def init_table(self, buffer: memoryview, key: int) -> None:
        length = len(buffer)
        table = bytearray(length)
        x = 0
        for i in range(length):
            x = (x + key) % length
            table[x] = buffer[i]
        buffer[:] = table

    def get_null_terminated_string(self, data: bytes, offset: int, max_length: int) -> str:
        end = data.find(b'\0', offset, offset + max_length)
        if end == -1:
            end = offset + max_length
        return data[offset:end].decode('utf-8', errors='replace')

    def open(self) -> bool:
        try:
            with open(self.filepath, 'rb') as f:
                if f.read(4) != self.SIGNATURE:
                    return False
                if f.read(4) != b'ATA ':
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
                
                current_offset = 0
                for _ in range(entry_count):
                    self.decrypt(index_data, current_offset, 0x60, self.key)
                    
                    name = self.get_null_terminated_string(index_data, current_offset, 0x40)
                    lzss_frame_size = struct.unpack_from('<H', index_data, current_offset + 0x40)[0]
                    lzss_init_pos = struct.unpack_from('<H', index_data, current_offset + 0x42)[0]
                    
                    if lzss_frame_size != 0:
                        lzss_init_pos = (lzss_frame_size - lzss_init_pos) % lzss_frame_size
                        
                    sub_type = struct.unpack_from('<I', index_data, current_offset + 0x48)[0]
                    size = struct.unpack_from('<I', index_data, current_offset + 0x4C)[0]
                    unpacked_size = struct.unpack_from('<I', index_data, current_offset + 0x50)[0]
                    offset = struct.unpack_from('<I', index_data, current_offset + 0x54)[0]
                    
                    entry = EmEntry(
                        name=name,
                        offset=offset,
                        size=size,
                        unpacked_size=unpacked_size,
                        lzss_frame_size=lzss_frame_size,
                        lzss_init_pos=lzss_init_pos,
                        sub_type=sub_type,
                        is_packed=unpacked_size != size
                    )
                    
                    self.entries.append(entry)
                    current_offset += 0x60
                
                return True
                
        except Exception as e:
            print(f"Error opening archive: {e}", file=sys.stderr)
            return False

    def extract(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_data = {
            "key": self.key.hex() if self.key else None,
            "entries": []
        }

        with open(self.filepath, 'rb') as f:
            for entry in self.entries:
                try:
                    output_path = output_dir / entry.name
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    print(f"Extracting: {entry.name}")
                    
                    header_info = None
                    if entry.sub_type == 3:  # Script
                        header_info = self._extract_script(f, entry, output_path)
                    elif entry.sub_type == 4:  # Image
                        _extract_image(f, entry, self.key, output_path)
                    else:
                        self._extract_regular(f, entry, output_path)
                    
                    # Add entry details to extracted data
                    entry_data = {
                        "name": entry.name,
                        "offset": entry.offset,
                        "size": entry.size,
                        "unpacked_size": entry.unpacked_size,
                        "lzss_frame_size": entry.lzss_frame_size,
                        "lzss_init_pos": entry.lzss_init_pos,
                        "sub_type": entry.sub_type,
                        "is_packed": entry.is_packed,
                    }

                    # Add header info for split entries
                    if header_info:
                        entry_data.update({
                            "is_split": True,
                            "header": {
                                "part2_packed_size": header_info[0],
                                "part2_unpacked_size": header_info[1],
                                "padding": header_info[2]
                            }
                        })
                    
                    extracted_data["entries"].append(entry_data)
                    
                except Exception as e:
                    print(f"Error extracting {entry.name}: {e}", file=sys.stderr)

        # Write extracted data to JSON file
        json_output_path = output_dir / "extracted_info.json"
        with open(json_output_path, 'w') as json_file:
            json.dump(extracted_data, json_file, indent=4)
        
        print(f"Extracted information saved to {json_output_path}")

    def _extract_script(self, f, entry: EmEntry, output_path: Path) -> Optional[tuple]:
        f.seek(entry.offset)
        header = bytearray(f.read(12))
        self.decrypt(header, 0, 12, self.key)
        
        # Extract header information
        part2_packed_size = struct.unpack_from('<I', header, 0)[0]
        part2_unpacked_size = struct.unpack_from('<I', header, 4)[0]
        padding = struct.unpack_from('<I', header, 8)[0]  # Should be 0

        if entry.lzss_frame_size == 0:
            # Not compressed
            with open(output_path, 'wb') as out:
                out.write(header)
                f.seek(entry.offset + 12)
                out.write(f.read(entry.size))
            return None
        else:
            if part2_unpacked_size != 0 and part2_unpacked_size < entry.unpacked_size:
                # Split compressed data
                part1_size = entry.unpacked_size - part2_unpacked_size
                
                # Read and decompress first part
                f.seek(entry.offset + 12 + part2_packed_size)
                compressed_part1 = f.read(entry.size - part2_packed_size)
                decompressed_part1, _ = decompress(compressed_part1)
                
                # Read and decompress second part
                f.seek(entry.offset + 12)
                compressed_part2 = f.read(part2_packed_size)
                decompressed_part2, _ = decompress(compressed_part2)
                
                # Combine parts
                with open(output_path, 'wb') as out:
                    out.write(decompressed_part1[:part1_size])
                    out.write(decompressed_part2)
                
                # Return header information for JSON
                return (part2_packed_size, part2_unpacked_size, padding)
            else:
                # Single compressed data
                f.seek(entry.offset + 12)
                compressed_data = f.read(entry.size)
                decompressed_data, _ = decompress(compressed_data)
                
                with open(output_path, 'wb') as out:
                    out.write(decompressed_data)
                return None

    def _extract_regular(self, f, entry: EmEntry, output_path: Path) -> None:
        f.seek(entry.offset)
        data = f.read(entry.size)
        
        with open(output_path, 'wb') as out:
            out.write(data)

def main():
    if len(sys.argv) != 3:
        print("Usage: python eme_extract.py <archive.eme> <output_directory>")
        sys.exit(1)
    
    archive_path = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    
    if not archive_path.exists():
        print(f"Archive file not found: {archive_path}", file=sys.stderr)
        sys.exit(1)
    
    archive = EmeArchive(archive_path)
    if not archive.open():
        print("Failed to open archive", file=sys.stderr)
        sys.exit(1)
    
    archive.extract(output_dir)
    print("Extraction complete!")

if __name__ == '__main__':
    main()

