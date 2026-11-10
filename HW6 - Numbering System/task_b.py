# -----------------------------------------------------------------------------
# IMPORT MODUL
# Modul bawaan Python yang dibutuhkan untuk mengolah waktu, fail, dan biner
# -----------------------------------------------------------------------------
from datetime import datetime, timezone  # Mengolah format tanggal & waktu UTC (B2)
import os  # Memeriksa dan mengelola jalur direktori fail di sistem
import struct  # Membongkar/mengonversi data biner ke tipe data Python (B2, B4)

# -----------------------------------------------------------------------------
# PENENTUAN JALUR FAIL (FILE PATH)
# -----------------------------------------------------------------------------
# os.path.join membuat jalur fail yang fleksibel (misal: "key/mystery.bin")
file_path = os.path.join("key", "mystery.bin")

# os.path.exists mengecek apakah fail ada di folder "key"
if not os.path.exists(file_path):
    # Jika program dijalankan dari dalam folder "key" itu sendiri,
    # gunakan langsung nama failnya tanpa awalan folder "key/"
    file_path = "mystery.bin"

# -----------------------------------------------------------------------------
# MEMBACA FAIL BINER
# -----------------------------------------------------------------------------
# open(..., "rb") membuka fail dalam mode Read Binary ('rb')
# f.read() membaca seluruh isi fail ke dalam memori sebagai kumpulan bait (bytes)
with open(file_path, "rb") as f:
    data = f.read()

print("=== TASK B: FILE INVESTIGATION ===")

# -----------------------------------------------------------------------------
# B1: MEMBACA MAGIC BYTES (Offset 0x00)
# Magic Bytes adalah 4 bait pertama yang menandai format asli suatu fail.
# -----------------------------------------------------------------------------
# data[0x00:0x04] mengambil 4 bait pertama dari indeks 0 hingga sebelum 4.
magic_bytes = data[0x00:0x04]

# .hex() mengonversi biner ke teks hexadecimal, .upper() diubah ke huruf kapital.
print(f"B1: Raw Magic Bytes at 0x00 = {magic_bytes.hex().upper()}")

# -----------------------------------------------------------------------------
# B2: MEMBACA UNIX TIMESTAMP (Offset 0x10)
# Membaca 4 bait pada offset 0x10 untuk mengetahui catatan waktu pembuatan/modifikasi.
# -----------------------------------------------------------------------------
# Memotong 4 bait data mulai dari offset 0x10 hingga sebelum 0x14.
ts_raw = data[0x10:0x14]

# struct.unpack("<I", ...) membongkar biner:
# '<' = Format Little-Endian (urutan bait dibalik dari kanan ke kiri)
# 'I' = Unsigned Integer 32-bit (angka bulat positif 4-byte)
# [0] = Mengambil hasil nilai angka dari tuple pengembalian struct.unpack
ts_dec = struct.unpack("<I", ts_raw)[0]

# datetime.fromtimestamp mengonversi detik Unix menjadi format tanggal/waktu nyata
# tz=timezone.utc memastikan zona waktu ditaruh pada UTC
# .strftime() memformat bentuk tampilan teks: Tahun-Bulan-Hari Jam:Menit:Saat UTC
utc_time = datetime.fromtimestamp(ts_dec, tz=timezone.utc).strftime(
    "%Y-%m-%d %H:%M:%S UTC"
)

print(f"B2: Timestamp Hex = {ts_raw.hex().upper()}")
print(f"    Decimal = {ts_dec}")
print(f"    UTC Time = {utc_time}")

# -----------------------------------------------------------------------------
# B3: DEKODE TEKS UTF-16LE (Offset 0x20)
# Membaca teks tersembunyi yang disimpan dalam format pengodean UTF-16LE.
# -----------------------------------------------------------------------------
# Mengambil seluruh bait mulai dari offset 0x20 hingga akhir fail.
str_data = data[0x20:]

# Pada UTF-16, karakter penanda akhir teks (Null Terminator) ditandai dengan 2 byte nol: b"\x00\x00"
null_pos = str_data.find(b"\x00\x00")

if null_pos != -1:
    # Potong data hanya sampai sebelum penanda b"\x00\x00" ditemukan
    str_bytes = str_data[:null_pos]
else:
    # Jika tidak ada penanda, ambil seluruh sisa data
    str_bytes = str_data

# .decode("utf-16le") mengubah bait biner menjadi teks terbaca mengggunakan aturan UTF-16LE
# errors="ignore" mengabaikan karakter rusak jika ada
decoded_str = str_bytes.decode("utf-16le", errors="ignore")
print(f"B3: UTF-16LE Decoded String = '{decoded_str}'")

# -----------------------------------------------------------------------------
# B4: MEMBACA INTEGER 32-BIT / NOMOR PORT (Offset 0x30)
# Membaca angka port layanan jaringan pada offset 0x30.
# -----------------------------------------------------------------------------
# Memotong 4 bait data pada offset 0x30.
port_raw = data[0x30:0x34]

# Membongkar biner Little-Endian 32-bit integer menjadi desimal angka port
port_dec = struct.unpack("<I", port_raw)[0]

# port_raw[::-1] membalikkan urutan bait agar tampil dalam urutan Big-Endian yang mudah dibaca manusia
print(f"B4: 32-bit Int Hex at 0x30 = 0x{port_raw[::-1].hex().upper()}")
print(f"    Decimal / Port Number = {port_dec}")