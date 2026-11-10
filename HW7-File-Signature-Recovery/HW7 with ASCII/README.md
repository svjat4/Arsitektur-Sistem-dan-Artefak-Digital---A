# Digital Forensics File Recovery Tool (DFR) v2.0

**Praktikum:** HW7 – File Signature and Recovery  
**Bahasa:** Python 3.x  
**Antarmuka:** Terminal interaktif dengan ASCII banner dan menu Step 1–3  
**Dependensi:** Python Standard Library saja

---

## 1. Tujuan aplikasi

Digital Forensics File Recovery Tool (DFR) adalah aplikasi Python untuk memeriksa raw disk image, menemukan file signature (magic bytes), dan mencoba mengekstrak file berdasarkan struktur formatnya.

Versi ini menggunakan antarmuka terminal interaktif. Saat program dijalankan, aplikasi menampilkan ASCII banner DFR, informasi singkat mengenai tool, dan menu tiga tahapan:

1. **STEP 1 – IMAGE INFORMATION & INTEGRITY**
2. **STEP 2 – FILE SIGNATURE SCANNER**
3. **STEP 3 – FILE RECOVERY / CARVING**

Urutan menu membantu pengguna memahami proses pemeriksaan. Program membaca image menggunakan mode `rb` (*read binary*) dan tidak menulis atau mengubah `evidence.img`.

## 2. Tampilan aplikasi

Contoh tampilan menu utama:

```text
 ____  _____ ____
|  _ \|  ___|  _ \
| | | | |_  | |_) |
| |_| |  _| |  _ <
|____/|_|   |_| \_\

[ DFR ]  DIGITAL FORENSICS FILE RECOVERY TOOL  v2.0
HW7 // FILE SIGNATURE & RECOVERY
Python 3.x | Standard Library | Read-only Evidence
--------------------------------------------------------------------
[!] FORENSIC NOTICE
Evidence image dibuka dalam mode read-only (rb).
Tool tidak mengubah byte pada evidence image asli.
--------------------------------------------------------------------

MAIN MENU / WORKFLOW
Evidence : evidence.img

  [1]  STEP 1 - IMAGE INFORMATION & INTEGRITY  [WAIT]
  [2]  STEP 2 - FILE SIGNATURE SCANNER          [WAIT]
  [3]  STEP 3 - FILE RECOVERY / CARVING         [WAIT]
  [0]  EXIT
--------------------------------------------------------------------
Pilih step [0-3]:
```

Warna teks ditampilkan jika terminal mendukung ANSI color. Jika output diarahkan ke file atau terminal tidak mendukung warna, program tetap berjalan dengan teks biasa.

## 3. Struktur folder proyek

```text
HW7-File-Signature-Recovery/
├── recovery_tool.py
├── evidence.img
├── forensic_report.md
├── findings.json
├── recovery_log.json
├── README.md
└── recovered/
    ├── recovered_001.jpg
    ├── recovered_002.pdf
    ├── recovered_003.elf
    ├── recovered_004.zip
    ├── recovered_005.png
    └── recovered_006.jpg
```

Keenam nama file di atas adalah hasil pemeriksaan terhadap `evidence.img` yang disertakan dalam proyek ini. Jika image diganti, jumlah, jenis, dan nama hasil recovery dapat berbeda.

Keterangan file keluaran:

- `recovery_tool.py`: program utama beserta ASCII banner dan menu interaktif.
- `evidence.img`: raw disk image yang diperiksa.
- `recovered/`: folder untuk file hasil carving.
- `findings.json`: hasil scan, temuan signature, hasil carving, signature yang dilewati, anomali tambahan, dan ringkasan.
- `recovery_log.json`: log recovery yang memuat nama file, format, offset, ukuran, SHA-256, status, alasan, dan waktu proses.
- `forensic_report.md`: laporan hasil pemeriksaan pada image yang disertakan.
- `README.md`: dokumentasi aplikasi ini.

## 4. Persyaratan

1. Gunakan Python 3.x. Python 3.8 atau lebih baru direkomendasikan.
2. Tidak perlu memasang package dengan `pip`.
3. Pastikan `recovery_tool.py` dan `evidence.img` tersedia pada folder proyek yang sama.
4. Jalankan aplikasi melalui Command Prompt, PowerShell, Terminal, atau terminal dari editor kode.

Program menggunakan modul Python Standard Library, antara lain:

| Modul | Kegunaan |
|---|---|
| `os` | Operasi sistem dan membersihkan terminal interaktif. |
| `sys` | Membaca argumen dan mengatur keluarnya aplikasi. |
| `struct` | Membaca struktur biner ELF, ZIP, dan PE. |
| `hashlib` | Menghitung SHA-256. |
| `json` | Menulis hasil scan dan log recovery. |
| `datetime` | Membuat waktu proses recovery. |
| `binascii` | Menghitung CRC32 pada chunk PNG. |
| `pathlib` | Mengelola path file dan folder. |
| `typing` | Type hints untuk memperjelas fungsi. |
| `ctypes` | Mengaktifkan dukungan ANSI color pada Windows Console yang mendukungnya. |

Tidak digunakan Foremost, Binwalk, Scalpel, atau library forensik pihak ketiga.

## 5. Cara menjalankan aplikasi

### Windows

Buka Command Prompt atau PowerShell pada folder proyek. Periksa instalasi Python:

```powershell
py -3 --version
```

Jalankan program dengan image sebagai argumen:

```powershell
py -3 recovery_tool.py evidence.img
```

Alternatif jika perintah `python` sudah mengarah ke Python 3:

```powershell
python recovery_tool.py evidence.img
```

### Linux atau macOS

```bash
python3 --version
python3 recovery_tool.py evidence.img
```

### Menjalankan tanpa argumen image

Program juga dapat dijalankan tanpa menyertakan nama image:

```bash
python3 recovery_tool.py
```

Aplikasi akan meminta pengguna memasukkan path image, misalnya `evidence.img`. Setelah path diterima, menu interaktif akan ditampilkan.

## 6. Panduan menu Step 1–3

Jalankan tahapan secara berurutan. Masukkan angka pilihan, kemudian tekan Enter.

### STEP 1 – IMAGE INFORMATION & INTEGRITY

Pilih `1` untuk membaca image dan menampilkan informasi dasar:

- Nama dan lokasi image.
- Ukuran image dalam byte dan KB.
- SHA-256 image.
- Mode akses `read-only (rb)`.

Pada tahap ini image dibaca sebagai data biner. Hash SHA-256 menjadi nilai pembanding untuk pemeriksaan integritas. Menjalankan Step 1 kembali akan membaca ulang image dan mengharuskan Step 2 serta Step 3 dijalankan kembali.

### STEP 2 – FILE SIGNATURE SCANNER

Setelah Step 1 selesai, pilih `2`. Program memindai seluruh isi image, mulai dari byte pertama hingga byte terakhir, untuk mencari enam signature yang ditentukan pada tugas HW7.

| Format | Magic bytes (hex) | Keterangan |
|---|---|---|
| JPEG | `FF D8 FF` | Awal kandidat JPEG. |
| PDF | `25 50 44 46` | Teks `%PDF`. |
| ELF | `7F 45 4C 46` | Identitas file ELF. |
| ZIP | `50 4B 03 04` | Local file header ZIP. |
| PNG | `89 50 4E 47` | Awal signature PNG. |
| PE/MZ | `4D 5A` | DOS header pada file PE. |

**Magic bytes** adalah pola byte yang menjadi petunjuk awal untuk mengenali format file. Magic bytes bukan bukti tunggal bahwa keseluruhan file valid.

**Offset** adalah posisi byte dihitung dari awal image dengan indeks pertama `0`. Program mencari offset secara otomatis; tidak ada offset evidence yang ditulis secara manual di source code.

Hasil scanning menampilkan format, offset heksadesimal, magic bytes, serta confidence/status awal:

- `HIGH`: signature dan pemeriksaan struktur dasar yang dilakukan program mendukung format tersebut.
- `MEDIUM`: signature ditemukan, tetapi belum dapat dipastikan sebagai file mandiri atau terdapat catatan validasi.
- `LOW`: kecocokan byte mentah ditemukan, tetapi pemeriksaan awal menunjukkan struktur tidak valid atau tidak lengkap.
- `NOT FOUND`: signature format tersebut tidak ditemukan pada image.

Satu jenis signature dapat ditemukan lebih dari sekali. Jumlah signature karena itu tidak selalu sama dengan jumlah file yang dapat dipulihkan.

### STEP 3 – FILE RECOVERY / CARVING

Setelah Step 2 selesai, pilih `3`. Program mengevaluasi kandidat dan menentukan rentang byte berdasarkan struktur masing-masing format. Hasil yang memenuhi kondisi ekstraksi ditulis ke folder `recovered/` dengan pola nama `recovered_001.ext`, `recovered_002.ext`, dan seterusnya.

Algoritma batas file yang digunakan:

| Format | Pendekatan penentuan batas |
|---|---|
| JPEG | Memeriksa marker SOF dan SOS pada header, lalu mencari marker akhir EOI (`FF D9`). |
| PDF | Memvalidasi header versi `%PDF-x.y`, lalu mencari `%%EOF`. CR/LF tepat setelah footer turut disertakan. |
| PNG | Membaca panjang dan tipe setiap chunk, memeriksa CRC32, lalu berhenti setelah chunk `IEND` yang valid secara struktur. |
| ZIP | Memeriksa local file header, central directory, dan End of Central Directory (EOCD). Header anggota yang berada di dalam arsip yang sudah dikenali dilewati agar tidak dianggap arsip mandiri lain. |
| ELF | Membaca kelas ELF32/ELF64, endianness, ELF header, program header/segment, dan section header untuk memperkirakan batas ukuran file. |
| PE/MZ | Memerlukan `MZ`, membaca pointer `e_lfanew`, PE signature, COFF/optional header, dan ukuran raw section. |

Format tidak diperlakukan seolah-olah semuanya mempunyai footer sederhana. Untuk ELF dan PE, ukuran diturunkan dari struktur header; ZIP menggunakan EOCD dan central directory.

### Status recovery

- **`complete`**: program menemukan batas ekstraksi berdasarkan struktur atau penanda akhir format dan mengekstrak rentang tersebut.
- **`partial`**: kandidat cukup memenuhi pemeriksaan awal, tetapi batas akhir yang dapat dipercaya tidak ditemukan. Hasil parsial tidak berarti file pasti dapat dibuka.
- **`failed`**: validasi minimum atau batas ekstraksi tidak terpenuhi. Program tidak membuat file hasil untuk kandidat tersebut.

Status `complete` menyatakan bahwa proses penentuan batas dan ekstraksi berhasil menurut pemeriksaan program. Status ini bukan jaminan bahwa seluruh konten file bebas kerusakan.

### Kembali ke menu

Setelah Step 1, Step 2, atau Step 3 selesai, tekan Enter ketika diminta untuk kembali ke menu. Pilih `0` untuk keluar.

Program mencegah urutan yang tidak tepat:

- Step 2 memerlukan Step 1.
- Step 3 memerlukan Step 1 dan Step 2.
- Jika Step 1 dijalankan ulang, hasil scan dan status recovery sebelumnya di-reset pada sesi tersebut.

## 7. Output yang dihasilkan

Setelah Step 3 selesai, aplikasi menghasilkan atau memperbarui:

### `recovered/`

Berisi file yang berhasil diekstrak. Program menghitung SHA-256 setiap konten dan memeriksa file hasil yang sudah ada. Jika konten identik sudah tersimpan, program menggunakan file yang sudah ada dan tidak menulis salinan dengan isi identik. File bernama sama tidak ditimpa jika kontennya berbeda.

### `findings.json`

Berisi informasi image, semua signature yang ditemukan, hasil carving setiap kandidat, signature nested yang dilewati, observasi struktural tambahan, serta ringkasan jumlah hasil.

### `recovery_log.json`

Berisi informasi image dan daftar hasil recovery. Setiap record hasil memuat:

- Nama file hasil recovery.
- Format file.
- Offset awal dan offset akhir.
- Ukuran file dalam byte.
- SHA-256 file hasil.
- Status recovery.
- Waktu recovery.
- Alasan atau catatan hasil carving.

Offset akhir di dalam JSON bersifat **inklusif**. Oleh karena itu, ukuran rentang dihitung dengan rumus:

```text
ukuran = offset_akhir - offset_awal + 1
```

### `forensic_report.md`

Laporan pemeriksaan yang disertakan dalam proyek ini mendokumentasikan hasil pengujian `evidence.img`. Script interaktif tidak membuat ulang file laporan Markdown ini; Step 3 menghasilkan `findings.json` dan `recovery_log.json`.

## 8. Hasil uji pada evidence.img yang disertakan

Pada pemeriksaan image contoh berukuran 524.288 byte (512 KiB), hasil yang tercatat adalah:

| Hasil | Jumlah |
|---|---:|
| Signature mentah ditemukan | 8 |
| Recovery berstatus `complete` | 6 |
| Recovery berstatus `partial` | 0 |
| Recovery berstatus `failed` | 1 |
| Signature nested yang dilewati | 1 |

Enam file yang berhasil diekstrak pada image contoh adalah:

1. `recovered_001.jpg`
2. `recovered_002.pdf`
3. `recovered_003.elf`
4. `recovered_004.zip`
5. `recovered_005.png`
6. `recovered_006.jpg`

Satu kecocokan ZIP kedua berada di dalam arsip ZIP pertama sehingga tidak diperlakukan sebagai arsip terpisah. Satu kecocokan `%PDF` tidak lolos validasi header versi dan tidak memiliki footer `%%EOF`, sehingga recovery dinyatakan `failed`.

Hasil tersebut khusus untuk `evidence.img` yang disertakan. Jangan menganggap angka di atas akan selalu sama ketika program dijalankan pada image lain.

## 9. Pemeriksaan hasil recovery

Periksa hasil ekstraksi dan nilai SHA-256 pada `recovery_log.json`. Ukuran file dapat diperiksa dengan membandingkan `size_bytes` dengan selisih offset awal dan akhir ditambah satu.

Untuk validasi tambahan, pengguna dapat memakai aplikasi atau utilitas pemeriksa format yang tersedia di sistem, misalnya pembaca PDF, aplikasi gambar, atau penguji arsip ZIP. Utilitas eksternal tersebut hanya untuk validasi manual dan bukan dependensi program.

Apabila suatu decoder memberikan peringatan, catat peringatan tersebut dalam laporan. Jangan mengubah byte hasil ekstraksi hanya agar file terlihat valid. Hash SHA-256 menunjukkan identitas byte hasil ekstraksi, bukan jaminan bahwa struktur internalnya sempurna.

## 10. Integritas dan batasan forensik

- `evidence.img` dibuka hanya dengan mode `rb`; program tidak menulis ke image bukti.
- Offset dihitung dari hasil pencarian signature, bukan di-hardcode.
- Batas akhir ekstraksi dibatasi agar tidak melewati akhir image.
- File hasil tidak dimodifikasi untuk memperbaiki signature atau membuatnya seolah-olah valid.
- Duplikasi konten dicegah menggunakan SHA-256.
- File carving berbasis signature tidak otomatis memulihkan nama file, direktori, timestamp filesystem asli, atau metadata filesystem yang hilang.
- File yang terfragmentasi mungkin tidak dapat direkonstruksi dengan benar oleh metode carving ini.
- Kemunculan magic bytes dapat terjadi di dalam file lain atau pada data biasa. Karena itu, signature mentah harus dibedakan dari hasil recovery.
- Perhitungan ukuran ELF/PE bergantung pada konsistensi header dan tabel internal. Jika struktur tidak konsisten atau melewati batas image, program tidak boleh mengklaim file berhasil dipulihkan secara utuh.

Tool ini dibuat untuk praktikum HW7 dan pembelajaran dasar signature scanning serta file carving. Hasilnya perlu ditafsirkan bersama catatan validasi, bukan dianggap sebagai pengganti pemeriksaan forensik mendalam.

## 11. Troubleshooting

**`python` atau `python3` tidak dikenali**  
Pastikan Python 3 sudah terpasang dan PATH sudah dikonfigurasi. Pada Windows, coba `py -3`.

**`evidence.img` tidak ditemukan**  
Pastikan terminal sedang berada di folder proyek, atau berikan path lengkap ke image. Contoh:

```powershell
py -3 recovery_tool.py "C:\HW7-File-Signature-Recovery\evidence.img"
```

**Step 2 meminta menjalankan Step 1 terlebih dahulu**  
Pilih menu `1`, tunggu informasi image ditampilkan, tekan Enter untuk kembali ke menu, lalu pilih `2`.

**Step 3 meminta menjalankan Step 2 terlebih dahulu**  
Jalankan menu `1` lalu `2` sebelum memilih `3`.

**Warna tidak muncul**  
Pastikan aplikasi dijalankan melalui terminal interaktif modern. Ketiadaan warna tidak memengaruhi pemindaian atau recovery.

---

**Catatan:** Gunakan salinan kerja untuk eksperimen. Pertahankan file evidence asli dan catat hash-nya sebelum serta setelah pemeriksaan.
