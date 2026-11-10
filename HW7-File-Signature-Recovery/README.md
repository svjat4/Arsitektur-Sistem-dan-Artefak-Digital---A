# Digital Forensics File Recovery Tool

**HW7 - File Signature and Recovery**  
Bahasa pemrograman: **Python 3.x**  
Ketergantungan: **Python Standard Library saja**

## 1. Tujuan aplikasi

Aplikasi ini membaca raw disk image `evidence.img`, mencari magic bytes dari enam format file yang ditentukan dalam instruksi HW7, lalu mencoba mengambil file yang batasnya dapat ditentukan dari struktur formatnya. Image bukti dibuka menggunakan mode `rb` (*read binary*), sehingga program hanya membaca dan tidak menulis ke image asli.

Aplikasi menghasilkan:

- `findings.json`: hasil signature scanning dan keputusan carving terstruktur, sesuai nama output pada struktur GitHub Classroom di PDF.
- `recovery_log.json`: log bonus yang berisi metadata file hasil recovery, offset, ukuran, SHA-256, status, dan waktu proses.
- `recovered/`: file yang berhasil diekstrak.
- `forensic_report.md`: laporan pemeriksaan singkat.

## 2. Struktur folder

```text
HW7-File-Signature-Recovery/
├── recovery_tool.py
├── evidence.img
├── forensic_report.md
├── findings.json
├── recovery_log.json
├── recovered/
│   ├── recovered_001.jpg
│   ├── recovered_002.pdf
│   ├── recovered_003.elf
│   ├── recovered_004.zip
│   ├── recovered_005.png
│   └── recovered_006.jpg
└── README.md
```

Nama file dan jumlah file di atas merupakan hasil pemeriksaan terhadap image yang disertakan. Ketika program dijalankan terhadap image lain, hasilnya dapat berbeda.

## 3. Magic bytes, offset, dan signature

**Magic bytes** adalah pola byte khusus yang umum digunakan untuk mengenali jenis file. Contohnya, file JPEG umumnya diawali `FF D8 FF`, sedangkan PNG diawali `89 50 4E 47`.

**Offset** adalah posisi suatu byte dihitung dari awal file atau image. Offset pertama adalah `0`. Contohnya, jika signature ditemukan pada offset `2048`, artinya byte pertama signature tersebut berada 2.048 byte setelah awal image. Program menghitung offset dengan pencarian byte, bukan dengan menuliskan lokasi file secara manual.

Signature yang dipindai:

| Format | Magic bytes (hex) |
|---|---|
| JPEG | `FF D8 FF` |
| PDF | `25 50 44 46` (`%PDF`) |
| ELF | `7F 45 4C 46` |
| ZIP | `50 4B 03 04` |
| PNG | `89 50 4E 47` |
| PE/MZ | `4D 5A` (`MZ`) |

Pencocokan magic bytes hanya menunjukkan **kandidat**. Sebuah pola dapat muncul sebagai data biasa, header yang rusak, atau bagian dari file lain. Karena itu, program tidak langsung menganggap setiap kecocokan sebagai file yang valid.

## 4. Cara kerja aplikasi

### A. Image information

Program membaca image dengan `open(..., "rb")`, menghitung ukuran byte, dan menghitung SHA-256. Hash dicatat sebelum proses carving agar identitas image dapat diperiksa kembali.

### B. File signature scanning

Fungsi `scan_signatures()` mencari setiap pola signature pada keseluruhan byte image. Pencarian dilanjutkan dari satu byte setelah posisi sebelumnya sehingga seluruh kemunculan, termasuk pola yang tumpang tindih, dapat ditemukan. Setiap hasil mencatat format, magic bytes, offset desimal, dan offset heksadesimal.

### C. Header/footer carving sesuai format

| Format | Cara menentukan batas file |
|---|---|
| JPEG | Memeriksa struktur marker SOF dan SOS, lalu mencari EOI `FF D9`. |
| PDF | Memeriksa header versi `%PDF-x.y`, lalu mencari footer `%%EOF`. Baris akhir setelah footer ikut disertakan jika ada. |
| PNG | Membaca chunk berdasarkan field panjang, memeriksa CRC32, dan berhenti setelah chunk `IEND`. |
| ZIP | Memeriksa local file header, central directory, dan End of Central Directory (EOCD). Header anggota ZIP di dalam arsip tidak diperlakukan sebagai arsip baru. |
| ELF | Membaca class 32/64-bit dan endianness, kemudian menghitung batas berdasarkan ELF header, program header/segment, serta section header jika tersedia. |
| PE/MZ | Memerlukan signature DOS `MZ`, membaca `e_lfanew`, PE/COFF header, optional header, dan ukuran data section. |

Format tidak diperlakukan seolah-olah semuanya memiliki footer sederhana. ZIP dan ELF, misalnya, memerlukan pemeriksaan struktur internal.

### D. Status recovery

- **complete**: batas file berhasil ditentukan menggunakan struktur/penanda format, lalu byte diekstrak sampai batas tersebut.
- **partial**: header kandidat cukup masuk akal, tetapi batas akhir format tidak ditemukan; data yang diambil hanya sampai batas aman perkiraan. Status ini bukan klaim bahwa file dapat dibuka sempurna.
- **failed**: kandidat tidak memenuhi validasi minimum atau tidak ada byte yang dapat diambil secara bertanggung jawab. File tidak dibuat.

Status `complete` menyatakan keberhasilan menentukan batas ekstraksi, bukan jaminan bahwa isi file bebas dari kerusakan. Catatan validasi tambahan tetap perlu dibaca.

### E. SHA-256 dan pencegahan duplikasi

Setiap hasil ekstraksi dihitung SHA-256-nya. Program memeriksa hash file yang sudah ada pada `recovered/`; jika konten identik ditemukan, program menggunakan file yang sudah ada dan tidak menulis salinan kedua. Program juga tidak menimpa file yang namanya sudah digunakan oleh konten berbeda.

## 5. Persyaratan dan instalasi

1. Install Python 3.8 atau lebih baru dari situs resmi Python: <https://www.python.org/downloads/>.
2. Tidak diperlukan `pip install` karena program memakai standard library Python.
3. Ekstrak folder proyek, kemudian buka terminal/Command Prompt pada folder tersebut.
4. Pastikan `evidence.img` berada di direktori yang sama dengan `recovery_tool.py`.

## 6. Cara menjalankan

Jalankan perintah berikut dari direktori proyek:

```bash
python3 recovery_tool.py evidence.img
```

Di Windows, perintah berikut juga dapat digunakan jika `python3` tidak terdaftar:

```powershell
python recovery_tool.py evidence.img
```

Folder `recovered/`, `findings.json`, dan `recovery_log.json` dibuat atau diperbarui oleh program. File evidence tidak diubah.

## 7. Membaca output scanning

Bagian `[2] FILE SIGNATURE SCANNING` menampilkan:

- `Format`: jenis signature yang ditemukan.
- `Offset`: lokasi signature di dalam image dalam heksadesimal.
- `Magic Bytes`: byte yang cocok dengan tabel tugas.
- `Confidence/Status`: indikasi validasi awal. `HIGH` berarti struktur dasar format lolos pemeriksaan; `LOW` menunjukkan kecocokan raw yang gagal validasi; `MEDIUM` dapat menunjukkan header anggota/container yang belum terbukti sebagai file mandiri.

Total signature dapat lebih banyak daripada jumlah file recovery. Sebagai contoh, ZIP menyimpan local file header untuk setiap anggota arsip. Header anggota di dalam ZIP bukan file ZIP mandiri kedua.

## 8. Memeriksa hasil recovery

Bandingkan ukuran dan SHA-256 hasil ekstraksi dengan nilai pada `recovery_log.json`. Offset akhir yang dicatat bersifat **inklusif**, sehingga rumus ukuran adalah:

```text
ukuran = offset_akhir - offset_awal + 1
```

Pemeriksaan tambahan dapat dilakukan menggunakan aplikasi yang sesuai, misalnya:

```bash
file recovered/*
unzip -t recovered/recovered_004.zip
pdfinfo recovered/recovered_002.pdf
readelf -h recovered/recovered_003.elf
identify recovered/recovered_001.jpg recovered/recovered_006.jpg recovered/recovered_005.png
```

Perintah di atas merupakan pemeriksaan eksternal opsional, bukan dependensi program. Program recovery itu sendiri tetap hanya menggunakan Python Standard Library.

## 9. Fungsi utama di dalam kode

| Fungsi | Tugas |
|---|---|
| `read_image_readonly()` | Membaca image dalam mode read-only. |
| `sha256_bytes()` dan `sha256_file()` | Menghitung hash SHA-256. |
| `find_all()` | Menemukan semua kemunculan pola byte. |
| `scan_signatures()` | Memindai enam signature yang diminta. |
| `parse_jpeg_header()` | Memeriksa marker SOF/SOS JPEG. |
| `parse_png()` | Membaca chunk PNG, CRC32, dan IEND. |
| `parse_zip_archive()` | Memvalidasi central directory dan EOCD ZIP. |
| `parse_elf_extent()` | Memperkirakan ukuran ELF dari header dan tabelnya. |
| `parse_pe_extent()` | Memperkirakan ukuran PE dari struktur DOS/PE. |
| `carve_candidate()` | Menentukan batas dan menyiapkan hasil ekstraksi per kandidat. |
| `save_recovered_content()` | Menyimpan hasil tanpa menimpa atau menggandakan konten. |
| `write_json()` | Menulis output JSON. |
| `main()` | Mengatur seluruh alur aplikasi dan menampilkan ringkasan. |

Setiap fungsi memiliki docstring di source code.

## 10. Keterbatasan

1. File carving berbasis signature tidak dapat memulihkan nama file atau metadata filesystem yang telah hilang.
2. Fragmentasi file dapat membuat metode header/footer sederhana mengambil data yang tidak utuh. Program ini tidak melakukan rekonstruksi fragmentasi.
3. PDF yang tidak memiliki header versi yang valid atau `%%EOF` tidak dinyatakan berhasil.
4. ZIP memerlukan central directory dan EOCD yang konsisten. Local file header saja tidak cukup untuk mengklaim satu arsip lengkap.
5. ELF tanpa ukuran segmen/section yang dapat dihitung tidak dapat dinyatakan lengkap dengan yakin.
6. PE/MZ hanya dapat diproses jika signature DOS `MZ` ada; ditemukannya `PE\0\0` saja tidak membuktikan file PE lengkap.
7. SHA-256 membuktikan identitas byte yang diekstrak, bukan validitas semantik atau keamanan file.
8. Tool ini merupakan implementasi praktikum, bukan pengganti validasi forensik mendalam atau pemeriksaan menggunakan parser format khusus.

## 11. Integritas evidence

`evidence.img` disertakan sebagai salinan kerja. Program hanya membukanya dengan mode baca (`rb`). Hash image sebelum dan setelah pengujian harus sama. Jangan mengedit atau menimpa evidence asli saat melakukan pemeriksaan.
