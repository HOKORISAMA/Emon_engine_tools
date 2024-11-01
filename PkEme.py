#STILL NEEDS A LITTLE IMPROVEMENT

import os
import json
import struct
import argparse
from typing import List, Dict
from lzss import compress, LZSSError

class EmePacker:
    def __init__(self):
        self.signature = b"RREDATA "
        
    def shift_value(self, result: int, key: int) -> int:
        original_value = 0
        shift = 0
        for i in range(32):
            shift += key
            original_position = shift % 32
            bit = (result >> original_position) & 1
            original_value |= (bit << i)
        return original_value

    def init_table(self, buffer: memoryview, key: int) -> None:
        length = len(buffer)
        table = bytearray(length)
        
        # Compute the x sequence first
        x_sequence = [0] * length
        current_x = 0
        for i in range(length):
            current_x = (current_x + key) % length
            x_sequence[i] = current_x
        
        # Reverse mapping
        inv_x_sequence = [0] * length
        for i, x in enumerate(x_sequence):
            inv_x_sequence[x] = i
        
        # Reconstruct the original buffer
        for i in range(length):
            table[inv_x_sequence[i]] = buffer[i]
        
        buffer[:] = table

    def encrypt(self, buffer: bytearray, offset: int, length: int, routine: bytes) -> bytearray:
        data = bytearray(buffer[offset:offset + length])
        data_view = memoryview(data)
        
        for i in range(0, 8):
            key = struct.unpack_from("<I", routine, 8 + i * 4)[0]
            if routine[i] == 1:
                for j in range(0, len(data), 4):
                    v = struct.unpack_from("<I", data_view, j)[0]
                    struct.pack_into("<I", data_view, j, v ^ key)
                    
            elif routine[i] == 2:
                prev = 0
                for j in range(0, len(data), 4):
                    v = struct.unpack_from("<I", data_view, j)[0]
                    new_val = v ^ key ^ prev
                    struct.pack_into("<I", data_view, j, new_val)
                    prev = new_val

            elif routine[i] == 4:
                for j in range(0, len(data), 4):
                    v = struct.unpack_from("<I", data_view, j)[0]
                    result = self.shift_value(v, key)
                    struct.pack_into("<I", data_view, j, result)

            elif routine[i] == 8:
                self.init_table(data, key)
                    
        return data

    def apply_xor_mask(self, data: bytearray) -> bytearray:
        xor_mask = bytes.fromhex("ca96e2f800000000")
        transformed_data = bytearray(len(data))
        for i in range(len(data)):
            transformed_data[i] = data[i] ^ xor_mask[i % len(xor_mask)]
        return transformed_data

    def create_archive(self, input_dir: str, json_path: str, output_path: str) -> bool:
        try:
            with open(json_path, 'r') as f:
                archive_info = json.load(f)
            
            key = bytes.fromhex(archive_info['key'])
            entries = archive_info['entries']
            entries.sort(key=lambda x: x['name'])
            
            processed_entries = []
            file_data = []
            current_offset = 4
            
            for entry in entries:
                input_path = os.path.join(input_dir, entry['name'])
                if not os.path.exists(input_path):
                    print(f"Warning: Input file not found: {input_path}")
                    continue
                
                with open(input_path, 'rb') as f:
                    data = f.read()
                
                if entry['sub_type'] == 3:
                    processed_data = self._pack_script(data, entry)
                elif entry['sub_type'] == 5 and len(data) > 4:
                    processed_data = self._pack_type5(data, key)
                else:
                    processed_data = data
                
                entry_copy = entry.copy()
                entry_copy['offset'] = current_offset
                entry_copy['size'] = len(processed_data)
                processed_entries.append(entry_copy)
                
                file_data.append(processed_data)
                current_offset += len(processed_data)
            
            index = bytearray()
            for entry in processed_entries:
                entry_data = bytearray(0x60)
                name_bytes = entry['name'].encode('ascii')
                entry_data[0:len(name_bytes)] = name_bytes
                struct.pack_into("<H", entry_data, 0x40, entry['lzss_frame_size'])
                struct.pack_into("<H", entry_data, 0x42, entry['lzss_init_pos'])
                struct.pack_into("<I", entry_data, 0x48, entry['sub_type'])
                struct.pack_into("<I", entry_data, 0x4C, entry['size'])
                struct.pack_into("<I", entry_data, 0x50, entry['unpacked_size'])
                struct.pack_into("<I", entry_data, 0x54, entry['offset'])
                
                encrypted_entry = self.encrypt(entry_data, 0, 0x60, key)
                transformed_entry = self.apply_xor_mask(encrypted_entry)
                index.extend(transformed_entry)
            
            with open(output_path, 'wb') as archive:
                archive.write(self.signature)
                for data in file_data:
                    archive.write(data)
                archive.write(key)
                archive.write(index)
                archive.write(struct.pack("<I", len(processed_entries)))
            
            print(f"Successfully created archive: {output_path}")
            print(f"Total files packed: {len(processed_entries)}")
            return True
            
        except Exception as e:
            print(f"Error creating archive: {str(e)}")
            return False

    def _pack_script(self, data: bytes, entry: Dict) -> bytes:
        if not entry['lzss_frame_size']:
            header = bytearray(12)
            struct.pack_into("<I", header, 0, 0)
            struct.pack_into("<I", header, 4, len(data))
            struct.pack_into("<I", header, 8, 0)
            return header + data
        
        compressed_data, error = compress(data)
        if error != LZSSError.OK:
            raise RuntimeError(f"LZSS compression failed for {entry['name']}")
        
        header = bytearray(12)
        struct.pack_into("<I", header, 0, len(compressed_data))
        struct.pack_into("<I", header, 4, len(data))
        struct.pack_into("<I", header, 8, 1)
        
        return header + compressed_data

    def _pack_type5(self, data: bytes, key: bytes) -> bytes:
        header = bytearray(data[:4])
        encrypted_header = self.encrypt(header, 0, 4, key)
        return encrypted_header + data[4:]

def main():
    parser = argparse.ArgumentParser(description='Create EME archive from directory and JSON info')
    parser.add_argument('input_dir', help='Directory containing files to pack')
    parser.add_argument('json_path', help='Path to archive info JSON file')
    parser.add_argument('output_path', help='Output EME archive path')
    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"Error: Input directory does not exist: {args.input_dir}")
        return

    if not os.path.exists(args.json_path):
        print(f"Error: JSON file does not exist: {args.json_path}")
        return

    packer = EmePacker()
    packer.create_archive(args.input_dir, args.json_path, args.output_path)

if __name__ == "__main__":
    main()
