import struct

class Encryptor:
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


class Decryptor:
    def decrypt(self, buffer: bytearray, offset: int, length: int, routine: bytes) -> bytearray:
        data = bytearray(buffer[offset:offset + length])
        data_view = memoryview(data)
        
        key_index = len(routine)
        for i in range(7, -1, -1):
            key_index -= 4
            key = struct.unpack_from("<I", routine, key_index)[0]
            if routine[i] == 1:
                for j in range(0, len(data), 4):
                    v = struct.unpack_from("<I", data_view, j)[0]
                    struct.pack_into("<I", data_view, j, v ^ key)
            elif routine[i] == 2:
                for j in range(0, len(data), 4):
                    v = struct.unpack_from("<I", data_view, j)[0]
                    struct.pack_into("<I", data_view, j, v ^ key)
                    key = v
            elif routine[i] == 4:
                for j in range(0, len(data), 4):
                    v = struct.unpack_from("<I", data_view, j)[0]
                    struct.pack_into("<I", data_view, j, self.shift_value(v, key))
            elif routine[i] == 8:
                self.init_table(data, key)
        return data

    def shift_value(self, val: int, key: int) -> int:
        shift = 0
        result = 0
        for i in range(32):
            shift += key
            result |= ((val >> i) & 1) << (shift % 32)
        return result

    def init_table(self, buffer: bytearray, key: int) -> None:
        length = len(buffer)
        table = bytearray(length)
        x = 0
        for i in range(length):
            x = (x + key) % length
            table[x] = buffer[i]
        buffer[:] = table


def test_shift_operation_independent():
    """Test that the shift operation works without depending on the decryptor"""
    print("=== Testing Independent Shift Operation ===")
    
    encryptor = Encryptor()
    
    test_value = 0x12345678
    shift_key = 5
    
    print(f"Original value: 0x{test_value:08x}")
    
    # Test individual bits to verify the mapping is correct
    print(f"Testing individual bit mapping for key={shift_key}:")
    for i in range(32):
        test_bit = 1 << i
        encrypted = encryptor.shift_value_encrypt(test_bit, shift_key)
        print(f"  Bit {i:2d}: 0x{test_bit:08x} -> 0x{encrypted:08x}")
    print()


def test_full_routine():
    """Test the full routine with all operations"""
    print("=== Testing Full Routine ===")
    
    routine = bytes.fromhex("0104020800000000f962a8ec11000000f8e296ca0700000000000000000000000000000000000000")
    
    plain_text = b"Hello, World! This is a test of encryption!!"
    print(f"Original: {plain_text}")
    print(f"Original (hex): {plain_text.hex()}")
    
    encryptor = Encryptor()
    encrypted = encryptor.encrypt(bytearray(plain_text), 0, len(plain_text), routine)
    print(f"Encrypted (hex): {encrypted.hex()}")
    
    decryptor = Decryptor()
    decrypted = decryptor.decrypt(encrypted, 0, len(encrypted), routine)
    print(f"Decrypted: {decrypted.decode('latin-1')}")
    print(f"Success: {decrypted == plain_text}")
    print()


def test_known_encrypted_data():
    """Test with the known encrypted data"""
    print("=== Testing Known Encrypted Data ===")
    
    routine = bytes.fromhex("0104020800000000f962a8ec11000000f8e296ca0700000000000000000000000000000000000000")
    
    # The known encrypted data
    original_encrypted = bytearray.fromhex("CB90016879C497140580E390B64697EC050601907C527514CF9001C87CC4979C")
    print(f"Original encrypted: {original_encrypted.hex()}")
    
    decryptor = Decryptor()
    decrypted = decryptor.decrypt(original_encrypted, 0, len(original_encrypted), routine)
    print(f"Decrypted: {decrypted.hex()}")
    
    encryptor = Encryptor()
    re_encrypted = encryptor.encrypt(decrypted, 0, len(decrypted), routine)
    print(f"Re-encrypted: {re_encrypted.hex()}")
    print(f"Round trip successful: {re_encrypted == original_encrypted}")
    print()


def main():
    test_shift_operation_independent()
    test_full_routine()
    test_known_encrypted_data()


if __name__ == "__main__":
    main()
