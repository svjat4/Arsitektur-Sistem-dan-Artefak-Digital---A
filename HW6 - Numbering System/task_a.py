#!/usr/bin/env python3
"""
Task A: Number Conversion Drill
Master of Informatics - Universitas Islam Indonesia
"""


def task_a():
    # Mencetak garis pembatas berupa karakter sama dengan (=) sebanyak 60 kali
    print("=" * 60)
    print("TASK A: NUMBER CONVERSION DRILL RESULTS")
    print("=" * 60)

    # -------------------------------------------------------------------------
    # Q1: Mengonversi Hexadecimal (Basis 16) "0x4A" ke Decimal (Basis 10)
    # -------------------------------------------------------------------------
    # int("4A", 16) memberitahu Python untuk mengubah string "4A" ber-basis 16 menjadi angka desimal biasa.
    val_q1 = int("4A", 16)
    print(f"Q1  | 0x4A to Decimal                   : {val_q1}")

    # -------------------------------------------------------------------------
    # Q2: Mengonversi Hexadecimal "0x4A" ke Binary (Basis 2 / Angka Biner)
    # -------------------------------------------------------------------------
    # 1. bin(0x4A) mengubah angka hex menjadi biner bertipe string (hasilnya: '0b1001010').
    # 2. [2:] memotong 2 karakter pertama ('0b') yang merupakan awalan penanda biner di Python.
    # 3. .zfill(8) menambahkan angka nol di depan jika panjang biner kurang dari 8 bit (1 byte).
    val_q2 = bin(0x4A)[2:].zfill(8)
    print(f"Q2  | 0x4A to Binary                    : {val_q2}")

    # -------------------------------------------------------------------------
    # Q3: Mengonversi Desimal 42 ke Binary
    # -------------------------------------------------------------------------
    # Sama seperti Q2, bin(42) menghasilkan '0b101010'.
    # Kita buang '0b'-nya dengan [2:], lalu kita genapkan jadi 8 bit dengan .zfill(8).
    val_q3 = bin(42)[2:].zfill(8)
    print(f"Q3  | 42 Decimal to Binary              : {val_q3}")

    # -------------------------------------------------------------------------
    # Q4: Mengonversi Biner "11010110" ke Hexadecimal
    # -------------------------------------------------------------------------
    # 1. int("11010110", 2) mengubah string biner (basis 2) menjadi desimal terlebih dahulu (214).
    # 2. hex(...) mengubah nilai desimal tersebut menjadi format hex (hasilnya: '0xd6').
    # 3. [2:] membuang awalan '0x'.
    # 4. .upper() mengubah huruf kecil menjadi huruf kapital ('d6' -> 'D6').
    val_q4 = hex(int("11010110", 2))[2:].upper()
    print(f"Q4  | 11010110_2 to Hex                 : 0x{val_q4}")

    # -------------------------------------------------------------------------
    # Q5: Mengonversi Biner "11010110" ke Decimal
    # -------------------------------------------------------------------------
    # int("...", 2) langsung mengubah biner (basis 2) menjadi angka desimal biasa.
    val_q5 = int("11010110", 2)
    print(f"Q5  | 11010110_2 to Decimal             : {val_q5}")

    # -------------------------------------------------------------------------
    # Q6: Memahami Nilai 0xFF pada Unsigned vs Signed int8 (Two's Complement)
    # -------------------------------------------------------------------------
    # 0xFF mewakili nilai biner 11111111 (8-bit).
    unsigned_q6 = 0xFF  # Nilai tanpa tanda (unsigned) selalu positif (0 hingga 255)

    # Untuk nilai bertanda (signed 8-bit), jangkauannya adalah -128 sampai +127.
    # Jika nilainya lebih besar dari 127, kita kurangi 256 untuk mendapatkan nilai negatifnya.
    signed_q6 = unsigned_q6 if unsigned_q6 <= 127 else unsigned_q6 - 256

    print(f"Q6  | 0xFF Unsigned int8                : {unsigned_q6}")
    print(f"    | 0xFF Signed int8 (Two's Complement)  : {signed_q6}")

    # -------------------------------------------------------------------------
    # Q7: Mengonversi Hak Akses Linux "chmod 755" (Octal/Basis 8) ke Binary
    # -------------------------------------------------------------------------
    octal_str = "755"
    # Mengambil setiap digit ("7", "5", "5"), diubah ke int, diubah ke biner via bin(),
    # dipotong '0b'-nya, lalu diisi nol di depan hingga 3 digit (.zfill(3)).
    # Hasil per digit digabungkan menjadi satu string dengan "".join(...).
    binary_chmod = "".join(bin(int(d))[2:].zfill(3) for d in octal_str)
    print(f"Q7  | chmod 755 in Binary               : {binary_chmod}")

    # -------------------------------------------------------------------------
    # Q8: Mengonversi Port Rangkaian 443 (Desimal) ke Hexadecimal
    # -------------------------------------------------------------------------
    # hex(443) menghasilkan '0x1bb'.
    # [2:] menghapus '0x', dan .upper() mengubahnya jadi '1BB'.
    val_q8 = hex(443)[2:].upper()
    print(f"Q8  | Port 443 to Hexadecimal           : 0x{val_q8}")

    # -------------------------------------------------------------------------
    # Q9: Mengonversi Alamat IP "10.0.0.1" ke Format Hexadecimal
    # -------------------------------------------------------------------------
    ip_parts = [10, 0, 0, 1]  # Memecah 4 oktek IP ke dalam bentuk list angka
    # f"{p:02X}" mengubah tiap angka jadi hex 2 digit kapital (10 -> "0A", 0 -> "00", 1 -> "01").
    # Lalu digabungkan dan diberi awalan "0x".
    hex_ip = "0x" + "".join(f"{p:02X}" for p in ip_parts)
    print(f"Q9  | IPv4 10.0.0.1 to Hex              : {hex_ip}")

    # -------------------------------------------------------------------------
    # Q10: Mengoreksi Urutan Byte Little-Endian
    # -------------------------------------------------------------------------
    # Membuat sekumpulan byte mentah.
    raw_bytes = bytes([0x76, 0x56, 0x34, 0x12])
    # int.from_bytes(..., byteorder='little') membaca urutan byte dengan aturan Little-Endian
    # (byte paling kanan/akhir dibaca sebagai nilai paling signifikan).
    le_val = int.from_bytes(raw_bytes, byteorder="little")
    # :08X menampilkan hasil sebagai hex 8 digit kapital.
    print(
        f"Q10 | Little-Endian Bytes (56 78 34 12)    : 0x{le_val:08X} ({le_val})"
    )
    print("=" * 60)


# Penanda standar Python: Fungsi task_a() hanya akan dipanggil/dijalankan
# jika file ini dieksekusi secara langsung (bukan di-import sebagai modul oleh file lain).
if __name__ == "__main__":
    task_a()