# LAPORAN PEMERIKSAAN FORENSIK DIGITAL

## HW7 – File Signature and Recovery

**Nama aplikasi:** Digital Forensics File Recovery Tool (DFR) v2.0  
**Jenis pemeriksaan:** File signature scanning dan file carving  
**Berkas bukti:** `evidence.img`  
**Tanggal pelaksanaan pengujian:** 21 November 2026  
**Lingkungan pengujian:** Python 3.13.5  
**Identitas pemeriksa:** ........................................................  
**NIM:** ........................................................

---

## Abstrak

Pemeriksaan ini dilakukan untuk mengidentifikasi dan mengekstrak artefak file dari sebuah raw disk image bernama `evidence.img` dengan ukuran 524.288 byte (512 KiB). Pemeriksaan menggunakan aplikasi Digital Forensics File Recovery Tool (DFR) v2.0 yang dibangun dengan Python 3 dan Python Standard Library. Proses terdiri atas pemeriksaan informasi serta integritas image, pemindaian enam signature yang ditentukan dalam instruksi HW7, dan file carving berdasarkan struktur masing-masing format. Hasil pemindaian menunjukkan delapan kecocokan signature mentah, yaitu dua JPEG, dua PDF, satu ELF, dua ZIP, dan satu PNG. Tidak ditemukan signature PE/MZ. Setelah pemeriksaan struktur, enam file berhasil diekstrak, satu kandidat PDF dinyatakan gagal, dan satu signature ZIP dilewati karena merupakan local file header anggota dari arsip ZIP yang telah dipulihkan. Validasi menunjukkan seluruh hasil ekstraksi sama persis dengan rentang byte sumber dan memiliki SHA-256 yang sesuai dengan log. Dua file JPEG dapat didekode, tetapi decoder memberikan peringatan byte ekstra. Oleh karena itu, status complete dalam laporan ini merujuk pada keberhasilan penentuan batas dan ekstraksi menurut algoritma, bukan jaminan bahwa seluruh konten file bebas anomali.

**Kata kunci:** digital forensics, file signature, magic bytes, file carving, raw disk image, SHA-256, file recovery.

## 1. Pendahuluan

File yang dihapus atau tidak lagi memiliki entri sistem berkas dapat meninggalkan data pada media penyimpanan. Salah satu pendekatan pemeriksaan adalah mencari pola byte yang menjadi penanda awal format file (*file signature* atau *magic bytes*), kemudian memperkirakan batas file menggunakan karakteristik struktur format tersebut. Pendekatan ini dikenal sebagai file carving.

Instruksi praktikum HW7 meminta pembuatan perkakas berbasis Python 3 yang memindai seluruh raw image untuk signature JPEG, PDF, ELF, ZIP, PNG, dan PE/MZ. Tugas juga meminta ekstraksi kandidat file ke direktori `recovered/`, tanpa menggunakan Foremost, Binwalk, Scalpel, atau library forensik pihak ketiga. Setiap fungsi program diwajibkan memiliki dokumentasi/docstring, dan offset harus ditemukan secara programatik, bukan ditulis secara manual.

Laporan ini mendokumentasikan pelaksanaan tugas terhadap `evidence.img` yang disertakan bersama proyek. Antarmuka ASCII dan menu interaktif Step 1–3 merupakan pengaturan alur penggunaan aplikasi; proses analisis tetap dilakukan oleh fungsi scanner dan carving di dalam source code.

## 2. Tujuan Pemeriksaan

Pemeriksaan memiliki tujuan sebagai berikut:

1. Menghitung ukuran dan SHA-256 image sebelum analisis.
2. Memindai seluruh byte image untuk mencari enam magic bytes yang ditentukan dalam tugas.
3. Memeriksa kandidat berdasarkan struktur format sebelum mengekstrak data.
4. Menentukan offset awal, offset akhir, dan ukuran hasil carving tanpa melewati batas image.
5. Menghindari penulisan file duplikat, termasuk menghindari anggapan bahwa signature ZIP di dalam arsip merupakan arsip mandiri.
6. Mencatat temuan, hash file hasil, status recovery, dan waktu proses pada berkas JSON.

## 3. Ruang Lingkup dan Batasan

Pemeriksaan dibatasi pada satu berkas raw image, yaitu `evidence.img`, dan enam signature yang disebutkan dalam instruksi HW7. Pemindaian dilakukan terhadap seluruh isi image sebagai rangkaian byte, bukan melalui analisis filesystem atau pemulihan metadata direktori.

File carving berbasis signature memiliki keterbatasan. Signature yang ditemukan belum tentu merupakan file mandiri atau file yang valid. File yang terfragmentasi, rusak, atau tidak memiliki struktur akhir yang dapat ditentukan mungkin tidak dapat dipulihkan secara utuh. Program ini tidak melakukan rekonstruksi fragmentasi dan tidak mengubah byte hasil ekstraksi untuk memperbaiki file.

## 4. Integritas dan Identifikasi Barang Bukti

Image dibuka menggunakan mode `rb` (*read binary*). Mode ini digunakan untuk membaca data dan tidak menyediakan operasi penulisan melalui file handle yang dipakai aplikasi.

| Properti | Hasil |
|---|---|
| Nama barang bukti | `evidence.img` |
| Ukuran | 524.288 byte |
| Ukuran dalam KiB | 512 KiB |
| SHA-256 | `4faa6236c18577909f61fa595b9401bc3439a74be1e020f3f3b902f13f91d095` |
| Mode pembacaan aplikasi | `rb` (read-only) |
| Versi tool pada log | 2.0 |

SHA-256 image yang diperiksa sama dengan SHA-256 salinan `evidence.img` yang ditempatkan di direktori proyek. Nilai hash tersebut dicatat pada `findings.json` dan `recovery_log.json` untuk membantu pemeriksaan konsistensi barang bukti.

## 5. Metodologi Pemeriksaan

### 5.1 Tahap 1 – Image Information & Integrity

Aplikasi membaca image menggunakan fungsi `read_image_readonly()`, menghitung ukuran byte, dan menghitung SHA-256 dengan `sha256_bytes()`. Program tidak menulis data ke image sumber.

### 5.2 Tahap 2 – File Signature Scanner

Fungsi `scan_signatures()` memeriksa keenam pola byte pada seluruh data image. Pencarian dilakukan menggunakan operasi pencarian byte dan dilanjutkan dari posisi setelah kecocokan sebelumnya, sehingga seluruh kemunculan pola dapat dicatat. Offset dihitung dari indeks byte pertama image, yaitu indeks 0.

Signature yang digunakan adalah:

| Format | Magic bytes (hex) | Representasi |
|---|---|---|
| JPEG | `FF D8 FF` | Awalan JPEG / SOI dan byte berikutnya |
| PDF | `25 50 44 46` | `%PDF` |
| ELF | `7F 45 4C 46` | Identitas ELF |
| ZIP | `50 4B 03 04` | Local file header ZIP |
| PNG | `89 50 4E 47` | Empat byte awal signature PNG |
| PE/MZ | `4D 5A` | `MZ` pada DOS header |

Pemindaian mencakup offset 0 hingga 524.287. Untuk hasil tampilan, offset ditulis dalam format heksadesimal agar mudah ditelusuri pada pemeriksaan biner.

### 5.3 Tahap 3 – File Recovery / Header-Structure Carving

Kandidat tidak langsung diekstrak hanya karena magic bytes ditemukan. Aplikasi terlebih dahulu menjalankan pemeriksaan khusus format:

| Format | Dasar penentuan batas dan pemeriksaan |
|---|---|
| JPEG | Memeriksa marker SOF dan SOS, lalu mencari marker akhir EOI (`FF D9`). Parser mencatat byte ekstra yang ditoleransi saat membaca header. |
| PDF | Memeriksa header versi `%PDF-x.y` dan mencari penanda akhir `%%EOF`. Kandidat tanpa header versi yang benar tidak diekstrak sebagai PDF. |
| PNG | Membaca struktur chunk berdasarkan field panjang, menghitung CRC32, memastikan IHDR ditemukan, dan berhenti setelah chunk IEND. |
| ZIP | Memeriksa central directory dan End of Central Directory (EOCD). Offset dan ukuran arsip diturunkan dari struktur ZIP, bukan dengan menebak footer. |
| ELF | Membaca kelas ELF, endianness, ELF header, tabel program header, dan rentang segment untuk menentukan ukuran yang didukung struktur header. |
| PE/MZ | Memerlukan signature DOS `MZ`, kemudian membaca pointer `e_lfanew`, PE signature, dan struktur header/section untuk menilai ukuran. |

Rentang hasil menggunakan `offset_start` dan `offset_end` inklusif. Ukuran dihitung dengan rumus:

```text
size_bytes = offset_end - offset_start + 1
```

Sebelum file ditulis, program menghitung SHA-256 konten. Jika konten identik sudah tersedia pada direktori `recovered/`, program menggunakan file yang telah ada dan tidak menulis duplikat.

### 5.4 Tahap 4 – Logging dan Pelaporan

Setelah proses carving, aplikasi menghasilkan:

- `findings.json` untuk menyimpan informasi image, seluruh signature, hasil carving, signature nested yang dilewati, temuan struktural tambahan, dan ringkasan.
- `recovery_log.json` untuk mencatat nama file, format, offset awal/akhir, ukuran, SHA-256, status, alasan, serta timestamp recovery.

`forensic_report.md` ini merupakan dokumentasi hasil pemeriksaan pada image yang disertakan. File Markdown laporan tidak dibuat ulang secara otomatis oleh menu Step 3.

## 6. Hasil File Signature Scanning

Pemindaian menghasilkan **8 kecocokan signature mentah**. Rincian hasil adalah sebagai berikut:

| No. | Format | Offset heksadesimal | Offset desimal | Magic bytes | Status/interpretasi awal |
|---:|---|---:|---:|---|---|
| 1 | JPEG | `0x00000800` | 2.048 | `FF D8 FF` | HIGH – struktur SOF/SOS ditemukan |
| 2 | PDF | `0x00004000` | 16.384 | `25 50 44 46` | HIGH – header versi PDF ditemukan |
| 3 | ELF | `0x00006800` | 26.624 | `7F 45 4C 46` | HIGH – struktur header ELF ditemukan |
| 4 | ZIP | `0x00007000` | 28.672 | `50 4B 03 04` | HIGH – EOCD dan central directory tervalidasi |
| 5 | ZIP | `0x00007088` | 28.808 | `50 4B 03 04` | MEDIUM – local header anggota arsip, bukan arsip terpisah |
| 6 | PNG | `0x00009000` | 36.864 | `89 50 4E 47` | HIGH – chunk dan CRC tervalidasi |
| 7 | PDF | `0x0000B000` | 45.056 | `25 50 44 46` | LOW – kecocokan mentah, header versi tidak valid |
| 8 | JPEG | `0x0000E000` | 57.344 | `FF D8 FF` | HIGH – struktur SOF/SOS ditemukan |

Signature PE/MZ (`4D 5A`) **tidak ditemukan** pada image.

### 6.1 Analisis signature ZIP kedua

Signature ZIP pada `0x00007088` berada di dalam rentang arsip ZIP yang dimulai pada `0x00007000`. Pemeriksaan struktur arsip menunjukkan terdapat dua anggota, yaitu `readme.txt` dan `data.csv`. Local file header anggota kedua berada pada offset relatif 136 byte dari awal arsip, yang sesuai dengan offset absolut `0x00007088`. Oleh karena itu, signature tersebut dicatat sebagai signature nested dan tidak diperlakukan sebagai arsip ZIP mandiri. Tindakan ini menghindari ekstraksi ganda terhadap bagian dari arsip yang sama.

### 6.2 Analisis kandidat pada offset `0x0000B000`

Pada offset `0x0000B000` ditemukan byte `%PDF`, tetapi byte berikutnya tidak membentuk pola header versi `%PDF-x.y` yang diwajibkan oleh pemeriksaan PDF. Kandidat ini juga tidak memiliki footer PDF `%%EOF` yang dapat digunakan untuk menetapkan batas dokumen. Karena itu, kandidat tidak disimpan sebagai file PDF.

Pemeriksaan diagnostik tambahan menemukan pola `PE\0\0` pada offset `0x0000B080`. Nilai `e_lfanew` yang terbaca pada kandidat tersebut adalah 128 (`0x80`), yang menunjuk ke posisi `PE\0\0` relatif terhadap awal kandidat. Akan tetapi, signature DOS `MZ` (`4D 5A`) tidak ada. Temuan ini hanya dicatat sebagai anomali struktural yang menyerupai sebagian struktur PE; temuan tersebut **tidak cukup untuk menyatakan bahwa sebuah file PE valid berhasil ditemukan atau dipulihkan**.

## 7. Hasil File Recovery

Dari delapan kecocokan signature mentah, enam kandidat menghasilkan file dengan status `complete`, satu kandidat berstatus `failed`, dan satu signature ZIP nested dilewati. Tidak ada hasil berstatus `partial`.
Nama file hasil menggunakan pola `file_001.ext`, `file_002.ext`, dan seterusnya, sesuai contoh penamaan pada struktur folder `recovered/` di halaman 1 instruksi HW7.

| No. | Nama file hasil | Format | Offset awal | Offset akhir (inklusif) | Ukuran | Status |
|---:|---|---|---:|---:|---:|---|
| 1 | `file_001.jpg` | JPEG | `0x00000800` | `0x00000CED` | 1.262 byte | complete |
| 2 | `file_002.pdf` | PDF | `0x00004000` | `0x00004317` | 792 byte | complete |
| 3 | `file_003.elf` | ELF | `0x00006800` | `0x0000687F` | 128 byte | complete |
| 4 | `file_004.zip` | ZIP | `0x00007000` | `0x00007160` | 353 byte | complete |
| 5 | `file_005.png` | PNG | `0x00009000` | `0x0000994B` | 2.380 byte | complete |
| 6 | `file_006.jpg` | JPEG | `0x0000E000` | `0x000104F6` | 9.463 byte | complete |

Kandidat PDF pada `0x0000B000` dicatat sebagai `failed`, tanpa file hasil, karena header versi PDF tidak valid dan batas akhir PDF tidak dapat ditentukan secara andal. Signature ZIP pada `0x00007088` dilewati sebagai signature nested dan bukan kegagalan carving file mandiri.

## 8. Validasi Hasil Ekstraksi

Validasi dilakukan setelah proses carving. Utilitas di bawah merupakan alat bantu pemeriksaan hasil; utilitas tersebut **bukan dependensi aplikasi Python** dan tidak dipanggil oleh algoritma recovery.

| File | Pemeriksaan | Hasil validasi |
|---|---|---|
| `file_001.jpg` | `file`, `identify`, konversi decode | Dikenali sebagai JPEG grayscale 64×64 dan dapat didekode. Decoder memberi peringatan 4 byte ekstra sebelum SOS dan 319 byte ekstra sebelum EOI. |
| `file_002.pdf` | `file`, `pdfinfo` | Dikenali sebagai PDF 1.7, 1 halaman, ukuran 792 byte. |
| `file_003.elf` | `file`, `readelf -h` | Dikenali sebagai ELF64 little-endian executable untuk x86-64; satu program header dan tanpa section header. |
| `file_004.zip` | `file`, `unzip -t` | Arsip dikenali dengan dua anggota (`readme.txt`, `data.csv`); keduanya lolos uji integritas kompresi. |
| `file_005.png` | `file`, `identify`, pemeriksaan CRC oleh parser | Dikenali sebagai PNG RGB 32×32; chunk IHDR, tEXt, IDAT, dan IEND ditemukan, tanpa kesalahan CRC. |
| `file_006.jpg` | `file`, `identify`, konversi decode | Dikenali sebagai JPEG grayscale 32×32 dan dapat didekode. Decoder memberi peringatan 4 byte ekstra sebelum SOS dan 8.853 byte ekstra sebelum EOI. |

### 8.1 Verifikasi hash dan batas ekstraksi

Setiap file hasil dibandingkan dengan rentang byte yang bersesuaian pada `evidence.img`. Seluruh pemeriksaan berikut berhasil untuk keenam file:

1. SHA-256 file hasil sama dengan nilai SHA-256 yang dicatat dalam `recovery_log.json`.
2. Byte file hasil sama persis dengan potongan image dari `offset_start` sampai `offset_end` inklusif.
3. Ukuran file sama dengan hasil perhitungan `offset_end - offset_start + 1`.
4. Offset akhir setiap file berada di dalam batas image.

SHA-256 masing-masing file hasil:

| File | SHA-256 |
|---|---|
| `file_001.jpg` | `b430a365a194c9dfe9ecb2813a0467d48c78fbc5f374963d63a4008359d0eb5c` |
| `file_002.pdf` | `799cc2e0490bde7115f4e637584d16f2d6f27f41338b1d3c90228c1df8f1289d` |
| `file_003.elf` | `fb576091ad47db88c14b293753291201887d59576bdb972d0949187cdfac8ff9` |
| `file_004.zip` | `cfc3c40ea346973a6924344df14acb19a5bb499a3b75e7efb2ac1cdd77765e5c` |
| `file_005.png` | `50f78d1ddb752facdad4733a314d624de837e26d6d00c6cdf090139a836f500a` |
| `file_006.jpg` | `03ec5a46324e52b8fef2d2b0ec1a02b0e36f5178f5c07b259ba42e40bd4db2f1` |

### 8.2 Catatan khusus JPEG

Kedua JPEG dikenali oleh pemeriksa file dan dapat didekode menjadi raster gambar. Namun, ImageMagick memberikan peringatan byte ekstra sebelum marker SOS dan EOI. Peringatan tersebut tidak dihapus atau diperbaiki oleh program. Dalam implementasi ini, status `complete` untuk JPEG berarti parser menemukan struktur SOF/SOS, menemukan marker EOI, dan mengekstrak rentang dari awal hingga akhir tersebut. Status itu bukan jaminan bahwa JPEG bebas dari anomali internal atau sepenuhnya kanonis.

## 9. Ringkasan Hasil

| Metrik | Jumlah |
|---|---:|
| Total signature mentah ditemukan | 8 |
| File berhasil diekstrak (`complete`) | 6 |
| Partial recovery | 0 |
| Failed recovery | 1 |
| Signature nested yang dilewati | 1 |
| File baru yang ditulis pada pengujian bersih | 6 |

Jumlah signature mentah tidak sama dengan jumlah file hasil recovery. Satu signature ZIP kedua merupakan local file header untuk anggota dari arsip ZIP yang telah dipulihkan, sedangkan satu kecocokan PDF tidak memenuhi validasi header versi dan footer. Oleh karena itu, enam file ditulis ke direktori `recovered/`.

## 10. Keterbatasan Pemeriksaan

1. **Fragmentasi file:** carving berbasis signature mengasumsikan data file berada dalam rentang yang dapat dibaca secara berurutan. Program tidak merekonstruksi fragmen file yang tersebar.
2. **False positive:** kemunculan magic bytes dapat terjadi di dalam data biasa atau sebagai bagian dari file lain. Validasi struktur diperlukan sebelum menganggapnya sebagai file mandiri.
3. **Batas format:** PDF dan JPEG menggunakan penanda akhir sebagai salah satu dasar batas; PNG menggunakan struktur chunk; ZIP menggunakan central directory dan EOCD; ELF menggunakan informasi header dan segment. Kesalahan atau kerusakan struktur dapat menyebabkan batas tidak dapat ditentukan.
4. **PE/MZ:** tidak ditemukan signature MZ. Adanya byte `PE\0\0` pada area kandidat lain tidak cukup untuk memvalidasi executable PE.
5. **Status complete:** status ini adalah hasil keputusan algoritma atas batas dan ekstraksi, bukan sertifikasi bahwa seluruh isi file tidak rusak. Peringatan pada JPEG menjadi contoh keterbatasan tersebut.
6. **Nama dan metadata asli:** file carving tidak otomatis memulihkan nama file asli, direktori asal, timestamp filesystem, atau metadata penghapusan.
7. **Cakupan pengujian:** validasi pembukaan file dilakukan menggunakan utilitas pembaca format yang tersedia pada lingkungan pengujian. Hasil tersebut tidak menggantikan pemeriksaan manual seluruh konten file.

## 11. Kesimpulan

Berdasarkan pemeriksaan `evidence.img` menggunakan DFR v2.0, ditemukan delapan kecocokan signature mentah dari enam jenis signature yang menjadi ruang lingkup tugas. Tidak ditemukan signature PE/MZ. Setelah validasi struktur dan proses carving, enam file berhasil diekstrak ke direktori `recovered/`, yaitu dua JPEG, satu PDF, satu ELF, satu ZIP, dan satu PNG. Satu kandidat PDF dinyatakan gagal karena header versi dan batas akhir yang dipersyaratkan tidak ditemukan. Satu signature ZIP lain dilewati karena merupakan local file header anggota arsip ZIP yang telah dipulihkan.

Hasil validasi menunjukkan ukuran, rentang offset, dan SHA-256 keenam file konsisten dengan byte sumber pada image. PDF, ELF, ZIP, dan PNG lolos pemeriksaan format yang dilakukan. Kedua JPEG dapat didekode, tetapi tetap memiliki peringatan byte ekstra sehingga kondisi internalnya perlu dipahami secara hati-hati. Dengan demikian, hasil akhir yang dapat dipertanggungjawabkan adalah enam hasil ekstraksi berstatus `complete` menurut algoritma, tanpa partial recovery, dan satu kandidat gagal; bukan klaim bahwa seluruh signature yang ditemukan merupakan file valid.

## 12. Daftar Artefak dan Referensi

### Artefak proyek

- `recovery_tool.py` – source code aplikasi interaktif dengan ASCII banner dan menu Step 1–3.
- `evidence.img` – raw disk image yang diperiksa.
- `recovered/` – enam file hasil ekstraksi.
- `findings.json` – hasil signature scanning, temuan struktural, dan ringkasan carving.
- `recovery_log.json` – log proses recovery termasuk offset, ukuran, SHA-256, status, alasan, dan timestamp.
- `README.md` – dokumentasi penggunaan aplikasi.
- `forensic_report.md` – laporan pemeriksaan ini.

### Dokumen acuan

- *HW7 – File Signature and Recovery.pdf*, instruksi praktikum resmi, halaman 1–2. Dokumen tersebut menjadi acuan untuk signature standar, pemindaian seluruh image, ketentuan Python Standard Library, larangan penggunaan tools forensik pihak ketiga, file carving, dan bonus JSON recovery log.

---

**Akhir laporan.**
