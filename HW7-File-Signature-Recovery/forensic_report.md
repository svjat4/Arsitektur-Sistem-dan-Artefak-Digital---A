# Laporan Pemeriksaan Forensik Digital

## HW7 - File Signature and Recovery

**Nama tool:** Digital Forensics File Recovery Tool  
**Tanggal pemeriksaan:** 6 November 2026  
**Berkas bukti:** `evidence.img`  
**Ukuran:** 524.288 byte (512 KiB)

## 1. Tujuan

Pemeriksaan dilakukan untuk mengidentifikasi signature JPEG, PDF, ELF, ZIP, PNG, dan PE/MZ di seluruh raw image, kemudian melakukan carving terhadap kandidat yang batas file-nya dapat ditentukan secara bertanggung jawab.

## 2. Integritas bukti

Image dibaca dengan mode `rb` (*read-only*). Program tidak menulis ke `evidence.img`.

| Properti | Hasil |
|---|---|
| Ukuran image | 524.288 byte |
| SHA-256 | `4faa6236c18577909f61fa595b9401bc3439a74be1e020f3f3b902f13f91d095` |
| Hash salinan proyek | Sama dengan image sumber |

## 3. Metodologi

1. Membaca seluruh byte image dan menghitung SHA-256.
2. Memindai keenam magic bytes sesuai instruksi HW7 dari awal sampai akhir image.
3. Memvalidasi kandidat berdasarkan struktur format, bukan hanya mengandalkan signature awal.
4. Menentukan batas akhir sesuai karakteristik format: EOI JPEG, `%%EOF` PDF, chunk `IEND` PNG, EOCD ZIP, atau ukuran berbasis header ELF/PE.
5. Mengekstrak byte dalam rentang yang telah ditentukan dan menghitung SHA-256 setiap file.
6. Memeriksa hasil dengan utilitas pembaca format sebagai validasi eksternal.

Offset menggunakan indeks byte berbasis nol. `offset_end` dalam JSON adalah offset inklusif.

## 4. Hasil signature scanning

Ditemukan **8 kecocokan signature raw**.

| No. | Format | Offset | Magic bytes | Interpretasi |
|---:|---|---:|---|---|
| 1 | JPEG | `0x00000800` | `FF D8 FF` | Header JPEG teridentifikasi |
| 2 | PDF | `0x00004000` | `25 50 44 46` | Header versi PDF valid |
| 3 | ELF | `0x00006800` | `7F 45 4C 46` | ELF64 valid |
| 4 | ZIP | `0x00007000` | `50 4B 03 04` | Arsip ZIP dengan EOCD valid |
| 5 | ZIP | `0x00007088` | `50 4B 03 04` | Header local file anggota ZIP, bukan arsip mandiri |
| 6 | PNG | `0x00009000` | `89 50 4E 47` | Chunk PNG dan CRC valid |
| 7 | PDF | `0x0000B000` | `25 50 44 46` | Kecocokan raw; header PDF tidak valid |
| 8 | JPEG | `0x0000E000` | `FF D8 FF` | Header JPEG teridentifikasi |

Signature `PE/MZ` (`4D 5A`) **tidak ditemukan**.

### Catatan anomali di sekitar offset `0x0000B000`

Kecocokan `%PDF` pada offset tersebut tidak diikuti pola header versi `%PDF-x.y` dan tidak memiliki footer `%%EOF`. Karena itu, kandidat ini tidak diekstrak sebagai PDF. Pemeriksaan tambahan menemukan byte `PE\0\0` pada `0x0000B080`, sementara field `e_lfanew` pada header kandidat menunjuk ke offset relatif `0x80`. Dua fakta ini konsisten dengan kemungkinan header DOS/PE yang rusak atau signature awal yang tertimpa, tetapi signature DOS `MZ` yang diwajibkan tidak ada. Tool mencatatnya sebagai anomali dan **tidak** mengklaim file PE berhasil dipulihkan.

## 5. Hasil carving

| File hasil | Format | Offset awal | Offset akhir (inklusif) | Ukuran | Status |
|---|---|---:|---:|---:|---|
| `recovered_001.jpg` | JPEG | `0x00000800` | `0x00000CED` | 1.262 byte | complete |
| `recovered_002.pdf` | PDF | `0x00004000` | `0x00004317` | 792 byte | complete |
| `recovered_003.elf` | ELF | `0x00006800` | `0x0000687F` | 128 byte | complete |
| `recovered_004.zip` | ZIP | `0x00007000` | `0x00007160` | 353 byte | complete |
| `recovered_005.png` | PNG | `0x00009000` | `0x0000994B` | 2.380 byte | complete |
| `recovered_006.jpg` | JPEG | `0x0000E000` | `0x000104F6` | 9.463 byte | complete |

Kecocokan ZIP pada `0x00007088` dilewati sebagai file carving terpisah karena merupakan local file header kedua di dalam arsip ZIP yang sudah berhasil divalidasi dari `0x00007000`. Ini mencegah satu arsip menghasilkan duplikat.

Kandidat PDF pada `0x0000B000` dicatat dengan status **failed** dan tidak menghasilkan file, karena header versi dan footer PDF tidak ditemukan. Tidak ada kandidat yang diberi status `partial` pada image ini.

## 6. Validasi file hasil

Validasi dilakukan setelah proses carving. Utilitas eksternal berikut hanya digunakan untuk pengujian; bukan dependensi `recovery_tool.py`.

| File | Pemeriksaan | Hasil |
|---|---|---|
| `recovered_001.jpg` | `file`, `identify`, konversi baca ke PNG | Dikenali sebagai JPEG grayscale 64×64 dan berhasil didekode; decoder memberi peringatan 4 byte ekstra sebelum SOS dan 319 byte ekstra sebelum EOI. |
| `recovered_002.pdf` | `file`, `pdfinfo` | PDF 1.7, 1 halaman, ukuran 792 byte. |
| `recovered_003.elf` | `file`, `readelf -h` | ELF64 little-endian, executable, x86-64, 1 program header, tanpa section header. |
| `recovered_004.zip` | `file`, `unzip -t` | Arsip memiliki 2 anggota (`readme.txt`, `data.csv`); keduanya lolos uji kompresi. |
| `recovered_005.png` | `file`, `identify`, CRC chunk | PNG RGB 32×32; seluruh CRC chunk valid dan IEND ditemukan. |
| `recovered_006.jpg` | `file`, `identify`, konversi baca ke PNG | Dikenali sebagai JPEG grayscale 32×32 dan berhasil didekode; decoder memberi peringatan 4 byte ekstra sebelum SOS dan 8.853 byte ekstra sebelum EOI. |

Peringatan JPEG menunjukkan adanya byte ekstra/non-kanonis pada data sebelum marker, meskipun decoder dapat membaca dan menghasilkan raster gambar. Oleh sebab itu, status `complete` di sini berarti rentang byte dari SOI sampai EOI berhasil diambil; status tersebut **tidak** menyatakan isi JPEG bebas dari anomali.

Pengujian SHA-256 memastikan keenam file hasil sama persis dengan byte pada rentang sumbernya. Untuk setiap file, rumus `offset_end - offset_start + 1` sama dengan `size_bytes`, dan `offset_end` berada di dalam batas image.

## 7. Ringkasan

| Metrik | Jumlah |
|---|---:|
| Signature ditemukan | 8 |
| File berhasil dipulihkan (complete) | 6 |
| Partial recovery | 0 |
| Failed recovery | 1 |
| Signature nested yang dilewati | 1 |

Jumlah recovery tidak sama dengan jumlah signature karena header ZIP kedua merupakan anggota dari arsip yang sama, sedangkan kecocokan PDF kedua gagal validasi.

## 8. Keterbatasan dan kesimpulan

Carving berbasis signature tidak memulihkan nama file asli dan tidak dapat menjamin keberhasilan pada file yang terfragmentasi. Batas PDF dan JPEG ditentukan dari footer; PNG dari chunk; ZIP dari central directory/EOCD; ELF dari ukuran struktur header/segment. PE/MZ tidak dipulihkan karena magic `MZ` tidak ditemukan.

Berdasarkan validasi struktural dan pemeriksaan eksternal, enam file berhasil diekstrak pada rentang byte yang sesuai. Satu kecocokan PDF dinyatakan gagal, satu signature ZIP nested dilewati agar tidak menghasilkan duplikasi, dan anomali PE-like pada area PDF palsu hanya dicatat sebagai temuan tambahan.

## 9. Artefak keluaran

- `findings.json`: semua kecocokan signature, hasil carving, signature yang dilewati, anomali struktural, dan ringkasan.
- `recovery_log.json`: nama file, format, offset awal/akhir, ukuran, SHA-256, status, dan waktu recovery.
- `recovered/`: enam file hasil ekstraksi.
