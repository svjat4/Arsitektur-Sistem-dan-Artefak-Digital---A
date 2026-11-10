# Numbering Systems & Digital Artifact Analysis

![Master of Informatics](https://img.shields.io/badge/University-Universitas%20Islam%20Indonesia-blue?style=for-the-badge)
![Course](https://img.shields.io/badge/Course-System%20Architecture%20%26%20Digital%20Artifacts-orange?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.x-green?style=for-the-badge)

Repositori ini berisi solusi lengkap, skrip Python, dan dokumen analisis forensik digital untuk Tugas **Numbering Systems** pada Program Magister Informatika, Universitas Islam Indonesia (UII).

---

## 👤 Informasi Mahasiswa

| Detail | Keterangan |
|---|---|
| **Nama Lengkap** | Rahmat Rifai Arsandi |
| **NIM** | 26917022 |
| **Program Studi** | Magister Informatika |
| **Institusi** | Universitas Islam Indonesia |

---

## 📌 Ringkasan Tugas

Tugas ini dirancang untuk mendalami dasar-dasar sistem bilangan dalam arsitektur komputer, struktur file biner pada level memori, serta teknik analisis forensik digital terhadap data ter-obfusikasi.

Tugas dibagi menjadi tiga bagian utama:
1. **Task A: Number Conversion Drill** — Konversi manual dan otomatis antar-sistem bilangan (Desimal, Biner, Heksadesimal, Oktal), pemahaman *Signed vs Unsigned int8*, format IPv4, permisi Linux (`chmod`), serta endianness memori.
2. **Task B: File Investigation** — Investigasi *file header/magic bytes*, parsing nilai *Unix Timestamp*, dekode string UTF-16LE, dan analisis port jaringan dari artefak biner.
3. **Task C: XOR Obfuscation Analysis** — Analisis forensik untuk ekstraksi kunci XOR, dekripsi *payload*, sifat *pattern visibility*, serta identifikasi biner tersembunyi (*Linux ELF Executable*).

---

## 📁 Struktur Repositori

```text
.
├── task_a.py            # Skrip Python untuk Task A (Konversi Bilangan)
├── task_b.py            # Skrip Python untuk Task B (Investigasi File Biner)
├── task_c.py            # Skrip Python untuk Task C (Dekripsi XOR & Analisis Forensik)
├── README.md            # Dokumentasi proyek
└── report.pdf           # Laporan resmi (sudah terisi tabel & analisis)
```

---

## 🚀 Cara Menjalankan Kode Python

### Prasyarat
- Python 3.8 atau versi yang lebih baru.
- Tidak memerlukan pustaka pihak ketiga (*standard library only*).

### Eksekusi Skrip

1. **Jalankan Task A (Number Conversion Drill):**
   ```bash
   python3 task_a.py
   ```

2. **Jalankan Task B (File Investigation):**
   ```bash
   python3 task_b.py
   ```

3. **Jalankan Task C (XOR Obfuscation Analysis):**
   ```bash
   python3 task_c.py
   ```

---

## 🛠️ Rincian Analisis Forensik & Hasil Utama

### 🔹 Task A: Number Conversion Drill (`task_a.py`)
- **Q1:** $0\text{x}4\text{A} \rightarrow 74_{10}$ (Positional sum basis 16)
- **Q2:** $0\text{x}4\text{A} \rightarrow 01001010_2$ (Nibble grouping)
- **Q3:** $42_{10} \rightarrow 00101010_2$ (Repeated division by 2)
- **Q4:** $11010110_2 \rightarrow 0\text{xD6}$ (4-bit binary grouping)
- **Q5:** $11010110_2 \rightarrow 214_{10}$ (Positional sum basis 2)
- **Q6:** `0xFF` Unsigned $= 255$, Signed int8 (Two's complement) $= -1$.
- **Q7:** Permisi Linux `chmod 755` $\rightarrow$ `111101101` (`rwxr-xr-x`).
- **Q8:** Port $443_{10} \rightarrow 0\text{x1BB}$.
- **Q9:** Alamat IPv4 `10.0.0.1` $\rightarrow$ `0x0A000001`.
- **Q10:** Koreksi Little-Endian memori (`78 56 34 12`) $\rightarrow$ `0x12345678` ($305.419.896_{10}$).

---

### 🔹 Task B: File Investigation (`task_b.py`)
- **B1 (Magic Bytes):** Byte offset `0x00` (`FF D8 FF E0`) mengindikasikan format gambar **JPEG / JFIF**.
- **B2 (Unix Timestamp):** Raw bytes offset `0x10` (`00 C3 D4 67`) setelah pembacaan Little-Endian (`0x67D4C300`) bernilai desimal `1741996800`, yang setara dengan tanggal UTC **2025-03-15 00:00:00 UTC**.
- **B3 (UTF-16LE String):** String terdekode pada offset `0x20` adalah `"CYBE"`.
- **B4 (32-bit LE Integer):** Offset `0x30` (`3D 0D 00 00`) setelah dibalik menjadi `0x00000D3D` (Desimal: `3389`), merujuk pada layanan jaringan **RDP (Remote Desktop Protocol)**.

---

### 🔹 Task C: XOR Obfuscation Analysis (`task_c.py`)
- **C1 (Ekstraksi Kunci XOR):** Kunci ter-ekstrak adalah `0x41` (Desimal: `65`).
  - *Sifat Self-Inverse:* $0\text{x}41 \oplus 0\text{x}41 = 0\text{x}00$. Hal ini membuktikan bahwa enkripsi dan dekripsi XOR bersifat simetris ($(P \oplus K) \oplus K = P$).
  - *Pattern Visibility Property:* Disebabkan oleh melimpahnya byte null (`0x00`) pada file biner, operasi $0\text{x}00 \oplus K = K$ menyebabkan kunci XOR berulang secara kasat mata pada *hex dump*.
- **C2 & C3 (Identifikasi File Tersembunyi):**
  - Dekripsi 4 byte pertama menghasilkan `7F 45 4C 46` (ASCII: `\x7fELF`).
  - Tipe file tersembunyi diidentifikasi sebagai **ELF (Executable and Linkable Format / Linux Executable)**.
  - *Interpretasi Forensik:* Penyerang memanfaatkan enkripsi XOR sederhana untuk menyamarkan file eksekutif berbahaya (*malware payload*) guna melewati pemindaian statis sistem antivirus/YARA.

---

## 📜 Deklarasi Integritas Akademik

> *Saya menyatakan bahwa repositori ini berisi hasil karya original saya sendiri. Seluruh kode program ditulis secara mandiri tanpa membagikan atau menduplikasi karya dari pihak manapun.*
