# -----------------------------------------------------------------------------
# IMPORT MODUL
# Modul bawaan Python untuk mengelola direktori dan jalur fail di sistem
# -----------------------------------------------------------------------------
import os

# -----------------------------------------------------------------------------
# PENENTUAN JALUR FAIL (FILE PATH)
# -----------------------------------------------------------------------------
# os.path.join membuat jalur fail yang fleksibel (misal: "key/obfuscated_payload.bin")[cite: 10, 12]
file_path = os.path.join("key", "obfuscated_payload.bin")

# os.path.exists mengecek apakah fail tersedia di dalam folder "key"
if not os.path.exists(file_path):
    # Jika program dijalankan langsung dari dalam folder "key",
    # gunakan nama failnya tanpa awalan folder "key/"
    file_path = "obfuscated_payload.bin"

# -----------------------------------------------------------------------------
# MEMBACA FAIL BINER TERENKRIPSI/TERPENGARUH XOR
# -----------------------------------------------------------------------------
# open(..., "rb") membuka fail dalam mode Read Binary ('rb')
# f.read() membaca seluruh isi biner payload ke dalam variabel
with open(file_path, "rb") as f:
    payload = f.read()

print("=== TASK C: XOR OBFUSCATION ANALYSIS ===")

# -----------------------------------------------------------------------------
# C1: EKSTRAKSI KUNCI XOR (XOR KEY)
# -----------------------------------------------------------------------------
# Catatan: Jika byte asli pada offset 0x00 adalah Null Byte (0x00),
# maka operasi (0x00 ^ Kunci) akan menghasilkan nilai kunci itu sendiri[cite: 10].
# payload[0] mengambil bait pertama pada offset 0x00 sebagai kunci XOR[cite: 10].
xor_key = payload[0]

# f"0x{xor_key:02X}" menampilkan kunci dalam format Hexadecimal 2 digit kapital (misal: 0x5A)
print(f"C1: Extracted XOR Key = 0x{xor_key:02X} (Decimal: {xor_key})")

# -----------------------------------------------------------------------------
# C2 & C3: MENYAHKOD (DECODE) SELURUH PAYLOAD DENGAN OPERASI XOR
# -----------------------------------------------------------------------------
# List comprehension [b ^ xor_key for b in payload] melakukan operasi bitwise XOR (^)
# pada setiap bait 'b' di dalam payload menggunakan kunci 'xor_key'.
# bytes(...) mengonversi kembali daftar angka tersebut menjadi data biner (bytes).
decoded_payload = bytes([b ^ xor_key for b in payload])

# -----------------------------------------------------------------------------
# C2: MENAMPILKAN HASIL DEKODE 8 BAIT PERTAMA (Offset 0x01 hingga 0x08)
# -----------------------------------------------------------------------------
print("\nC2: First 8 Decoded Bytes (Offsets 0x01 to 0x08):")

# range(1, 9) melakukan perulangan untuk offset 1, 2, 3, 4, 5, 6, 7, 8[cite: 10]
for offset in range(1, 9):
    enc_byte = payload[offset]  # Bait asli yang masih terenkripsi (hex)
    dec_byte = decoded_payload[offset]  # Bait yang sudah didekode (hex)

    # chr(dec_byte) mengubah kode desimal byte menjadi karakter teks terbaca (ASCII).
    # Ternary operation (if 32 <= dec_byte <= 126) memastikan hanya karakter ASCII terbaca
    # (seperti huruf/angka) yang ditampilkan, jika tidak maka ditampilkan sebagai titik ('.').
    ascii_char = chr(dec_byte) if 32 <= dec_byte <= 126 else "."

    print(
        f"  Offset 0x{offset:02X}: Enc = 0x{enc_byte:02X} ^ Key 0x{xor_key:02X} -> Dec = 0x{dec_byte:02X} ('{ascii_char}')"
    )

# -----------------------------------------------------------------------------
# C3: MEMERIKSA MAGIC BYTES HASIL DEKODE UNTUK MENGETAHUI FORMAT FAIL ASLI
# -----------------------------------------------------------------------------
# decoded_payload[1:5] mengambil 4 bait pertama isi fail sebenarnya (setelah offset kunci)[cite: 10, 11].
magic_decoded = decoded_payload[1:5]

# .hex().upper() menampilkan 4 bait pertama dalam format Hexadecimal kapital[cite: 11]
print(f"\nC3: Decoded Magic Bytes (Hex)   = {magic_decoded.hex().upper()}")

# .decode('ascii', errors='ignore') mencoba membaca 4 bait tersebut sebagai teks ASCII[cite: 11]
# (misalnya jika fail aslinya adalah ELF, PDF, PK, atau MZ)[cite: 11].
print(
    f"    Decoded Magic Bytes (ASCII) = {magic_decoded.decode('ascii', errors='ignore')}"
)