import os
import json
import struct
import argparse
from typing import List, Dict
import lzss

class EmePacker:
    def __init__(self):
        self.signature = b"RREDATA "
        
    def encrypt(self, buffer: bytearray, offset: int, length: int, routine: bytes) -> bytearray:
        data = bytearray(buffer[offset:offset + length])
        view = memoryview(data)

        # Apply operations in REVERSE order of decryptor (0 to 7) with forward operations
        for i in range(8):
            op = routine[i]
            # Get the key from the same position as decryptor but in forward order
            key_index = 8 + i * 4
            key = struct.unpack_from("<I", routine, key_index)[0]

            if op == 1:
                # Simple XOR (self-inverse)
                for j in range(0, len(data), 4):
                    if j + 4 <= len(data):
                        v = struct.unpack_from("<I", view, j)[0]
                        struct.pack_into("<I", view, j, v ^ key)

            elif op == 2:
                # Reverse chained XOR - match decryptor's behavior exactly
                # For encryption: current = plain ^ previous_encrypted
                prev = key
                for j in range(0, len(data), 4):
                    if j + 4 <= len(data):
                        v = struct.unpack_from("<I", view, j)[0]
                        enc = v ^ prev
                        struct.pack_into("<I", view, j, enc)
                        prev = enc

            elif op == 4:
                # Bit shift - use proper forward operation
                for j in range(0, len(data), 4):
                    if j + 4 <= len(data):
                        v = struct.unpack_from("<I", view, j)[0]
                        struct.pack_into("<I", view, j, self.shift_value_encrypt(v, key))

            elif op == 8:
                # Table permutation - use proper forward operation  
                self.table_permute_encrypt(data, key)

        return data

    def shift_value_encrypt(self, val: int, key: int) -> int:
        # The decryptor does: for each bit i, move it to position (accumulated_shift % 32)
        # where accumulated_shift = (i+1) * key
        # So we need to reverse this mapping
        
        # First, calculate where each bit would end up in the decryptor
        decryptor_positions = []
        shift = 0
        for i in range(32):
            shift = (shift + key) % 32
            decryptor_positions.append(shift)
        
        # Now create the inverse mapping for encryption
        # For each position in the output, which input bit should go there?
        encryptor_mapping = [0] * 32
        for original_bit_position in range(32):
            target_position = decryptor_positions[original_bit_position]
            encryptor_mapping[target_position] = original_bit_position
        
        # Apply the inverse mapping
        result = 0
        for output_position in range(32):
            input_bit_position = encryptor_mapping[output_position]
            bit = (val >> output_position) & 1
            result |= (bit << input_bit_position)
            
        return result

    def table_permute_encrypt(self, buffer: bytearray, key: int) -> None:
        # The decryptor's table operation is: table[x] = buffer[i] where x = (x + key) % length
        # The inverse operation for encryption is: table[i] = buffer[x] where x = (x + key) % length
        length = len(buffer)
        if length == 0:
            return
        
        # Build the same sequence as decryptor but use it for gathering instead of scattering
        table = bytearray(length)
        x = 0
        for i in range(length):
            x = (x + key) % length
            table[i] = buffer[x]
        buffer[:] = table
        
    def create_archive(self, input_dir: str, json_path: str, output_path: str) -> bool:
        try:
            with open(json_path, 'r') as f:
                archive_info = json.load(f)
            
            key = bytes.fromhex(archive_info['key'])
            entries = archive_info['entries']
            
            processed_entries = []
            file_data = []
            current_offset = 8
            
            for entry in entries:
                input_path = os.path.join(input_dir, entry['name'])
                if not os.path.exists(input_path):
                    print(f"Warning: Input file not found: {input_path}")
                    continue
                
                with open(input_path, 'rb') as f:
                    data = f.read()
                
                # Handle different file types
                if entry['sub_type'] == 3:
                    processed_data = self._pack_script(data, entry, key)
                # elif entry['sub_type'] == 4:
                    # processed_data = self._pack_bmp(data, entry, key)
                elif entry['sub_type'] == 5 and len(data) > 4:
                    processed_data = self._pack_type5(data, key)
                else:
                    processed_data = data  # Default case
                
                entry_copy = entry.copy()
                entry_copy['offset'] = current_offset
                entry_copy['packed_size'] = len(processed_data)
                processed_entries.append(entry_copy)
                
                file_data.append(processed_data)
                current_offset += len(processed_data)
            
            # Build index entries - FIXED VERSION
            index = bytearray()
            for entry in processed_entries:
                # Reverse LZSS init pos correction before writing
                lzss_init_pos = entry['lzss_init_pos']
                if entry['lzss_frame_size'] != 0:
                    lzss_init_pos = (entry['lzss_frame_size'] - lzss_init_pos) % entry['lzss_frame_size']
                
                entry_data = bytearray(0x60)
                name_bytes = entry['name'].encode('ascii')

                struct.pack_into("64s", entry_data, 0x00, name_bytes)
                struct.pack_into("<H", entry_data, 0x40, entry['lzss_frame_size'])
                struct.pack_into("<H", entry_data, 0x42, lzss_init_pos)
                struct.pack_into("<I", entry_data, 0x44, entry['magic'])  # ADDED THIS
                struct.pack_into("<H", entry_data, 0x48, entry['sub_type'])  # Changed from <I to <H
                struct.pack_into("<I", entry_data, 0x4C, entry['packed_size'])
                struct.pack_into("<I", entry_data, 0x50, entry['unpacked_size'])
                struct.pack_into("<I", entry_data, 0x54, entry['offset'])

                encrypted_entry = self.encrypt(entry_data, 0, len(entry_data), key)
                index.extend(encrypted_entry)  # Use encrypted entry
            
            # Write archive
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
            import traceback
            traceback.print_exc()
            return False

    def _pack_script(self, data: bytes, entry: Dict, key: bytes) -> bytes:
        """Pack script files (sub_type 3) with optional compression"""
        header = bytearray(12)
        
        if not entry['lzss_frame_size']:
            # No compression case
            struct.pack_into("<I", header, 0, 0)
            struct.pack_into("<I", header, 4, len(data))
            struct.pack_into("<I", header, 8, 0)
            encrypted_header = self.encrypt(header, 0, len(header), key)
            return encrypted_header + data
        
        # Compression case
        buffer_size = len(data) * 2 + 1024
        
        try:
            compressed_data = lzss.encode(data, buffer_size)
        except RuntimeError as e:
            print(f"LZSS compression failed for {entry.get('name', 'unknown')}: {e}")
            raise
        
        if not compressed_data:
            raise RuntimeError(f"LZSS compression returned empty data for {entry.get('name', 'unknown')}")
        
        # SET THE HEADER FIELDS FOR COMPRESSED DATA
        # struct.pack_into("<I", header, 0, len(compressed_data))
        # struct.pack_into("<I", header, 4, len(data))
        # struct.pack_into("<I", header, 8, 1)  # Compression flag
        
        encrypted_header = self.encrypt(header, 0, len(header), key)
        return encrypted_header + compressed_data
        
    def _pack_type5(self, data: bytes, key: bytes) -> bytes:
        """Pack type 5 files (only first 4 bytes encrypted)"""
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
