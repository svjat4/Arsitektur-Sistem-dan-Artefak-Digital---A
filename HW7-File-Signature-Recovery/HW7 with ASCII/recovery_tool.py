#!/usr/bin/env python3
"""Digital Forensics File Recovery Tool - HW7 File Signature and Recovery.

The program scans a raw image for the signatures required by the assignment,
then attempts conservative format-aware carving using Python's standard library.
The evidence image is opened in read-only mode and is never modified.
"""

import os
import sys
import struct
import hashlib
import json
import datetime
import binascii
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


TOOL_VERSION = "2.0"
SIGNATURES = [
    ("JPEG", bytes.fromhex("FF D8 FF"), ".jpg"),
    ("PDF", bytes.fromhex("25 50 44 46"), ".pdf"),
    ("ELF", bytes.fromhex("7F 45 4C 46"), ".elf"),
    ("ZIP", bytes.fromhex("50 4B 03 04"), ".zip"),
    ("PNG", bytes.fromhex("89 50 4E 47"), ".png"),
    ("PE/MZ", bytes.fromhex("4D 5A"), ".exe"),
]


def timestamp_now() -> str:
    """Return the current local time as an ISO-8601 timestamp with timezone."""
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_bytes(content: bytes) -> str:
    """Calculate and return the SHA-256 digest of a bytes object."""
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    """Calculate a file's SHA-256 digest by reading it in read-only chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def read_image_readonly(image_path: Path) -> bytes:
    """Read the image using read-only mode and return its bytes unchanged."""
    with image_path.open("rb") as image_file:
        return image_file.read()


def find_all(data: bytes, needle: bytes) -> List[int]:
    """Find every occurrence of a byte pattern, including overlapping matches."""
    offsets: List[int] = []
    position = 0
    while True:
        found = data.find(needle, position)
        if found < 0:
            break
        offsets.append(found)
        position = found + 1
    return offsets


def scan_signatures(data: bytes) -> List[Dict[str, Any]]:
    """Scan the complete image and return every assignment-defined signature hit."""
    detections: List[Dict[str, Any]] = []
    for file_format, magic, extension in SIGNATURES:
        for offset in find_all(data, magic):
            detections.append({
                "format": file_format,
                "magic_hex": magic.hex(" ").upper(),
                "offset": offset,
                "offset_hex": "0x{:08X}".format(offset),
                "extension": extension,
            })
    detections.sort(key=lambda item: (item["offset"], item["format"]))
    return detections


def parse_jpeg_header(data: bytes, start: int) -> Tuple[bool, Dict[str, Any], str]:
    """Validate JPEG marker segments up to SOS and return basic image dimensions."""
    if data[start:start + 2] != b"\xFF\xD8":
        return False, {}, "SOI marker is missing"

    position = start + 2
    dimensions: Dict[str, Any] = {}
    saw_sof = False
    saw_sos = False
    sof_markers = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                   0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}

    header_gap_bytes = 0
    while position < len(data):
        if data[position] != 0xFF:
            # Some damaged JPEGs contain a few stray bytes between header segments.
            # Accept only a small gap immediately before the next marker and record it.
            next_marker = data.find(b"\xFF", position, min(position + 17, len(data)))
            if next_marker < 0:
                return False, dimensions, "Unexpected data before a JPEG marker"
            header_gap_bytes += next_marker - position
            position = next_marker
        while position < len(data) and data[position] == 0xFF:
            position += 1
        if position >= len(data):
            return False, dimensions, "Truncated JPEG marker"

        marker = data[position]
        position += 1
        if marker in (0xD8, 0xD9, 0x01) or 0xD0 <= marker <= 0xD7:
            if marker == 0xD9:
                return False, dimensions, "EOI appeared before a scan segment"
            continue

        if position + 2 > len(data):
            return False, dimensions, "Truncated JPEG segment length"
        segment_length = int.from_bytes(data[position:position + 2], "big")
        if segment_length < 2 or position + segment_length > len(data):
            return False, dimensions, "Invalid or truncated JPEG segment"

        if marker in sof_markers:
            if segment_length < 8:
                return False, dimensions, "SOF segment is too short"
            height = int.from_bytes(data[position + 3:position + 5], "big")
            width = int.from_bytes(data[position + 5:position + 7], "big")
            components = data[position + 7]
            dimensions = {
                "width": width,
                "height": height,
                "components": components,
                "sof_marker": "0x{:02X}".format(marker),
            }
            saw_sof = True

        position += segment_length
        if marker == 0xDA:
            saw_sos = True
            break

    if not saw_sof:
        return False, dimensions, "JPEG SOF frame header was not found"
    if not saw_sos:
        return False, dimensions, "JPEG SOS scan header was not found"
    dimensions["header_gap_bytes"] = header_gap_bytes
    reason = "JPEG SOF and SOS structures are present"
    if header_gap_bytes:
        reason += "; {} extraneous header byte(s) tolerated".format(header_gap_bytes)
    return True, dimensions, reason


def parse_png(data: bytes, start: int) -> Tuple[Optional[int], Dict[str, Any], str]:
    """Walk PNG chunks, verify CRC values, and return the exclusive IEND boundary."""
    png_signature = b"\x89PNG\r\n\x1a\n"
    if data[start:start + 8] != png_signature:
        return None, {}, "PNG signature validation failed"

    position = start + 8
    chunks: List[str] = []
    crc_errors: List[str] = []
    width: Optional[int] = None
    height: Optional[int] = None
    saw_ihdr = False

    while position + 12 <= len(data):
        chunk_start = position
        chunk_length = int.from_bytes(data[position:position + 4], "big")
        chunk_type = data[position + 4:position + 8]
        data_start = position + 8
        crc_position = data_start + chunk_length
        chunk_end = crc_position + 4

        if chunk_end > len(data):
            return None, {"chunks": chunks, "crc_errors": crc_errors}, "PNG chunk exceeds image boundary"

        chunk_data = data[data_start:crc_position]
        expected_crc = int.from_bytes(data[crc_position:chunk_end], "big")
        calculated_crc = binascii.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        chunk_name = chunk_type.decode("ascii", errors="replace")
        chunks.append(chunk_name)
        if expected_crc != calculated_crc:
            crc_errors.append("{} at 0x{:X}".format(chunk_name, chunk_start))

        if chunk_type == b"IHDR":
            if chunk_length != 13:
                return None, {"chunks": chunks, "crc_errors": crc_errors}, "PNG IHDR length is not 13"
            width = int.from_bytes(chunk_data[0:4], "big")
            height = int.from_bytes(chunk_data[4:8], "big")
            saw_ihdr = True
        elif chunk_type == b"IEND":
            if chunk_length != 0:
                return None, {"chunks": chunks, "crc_errors": crc_errors}, "PNG IEND chunk must be empty"
            if not saw_ihdr:
                return None, {"chunks": chunks, "crc_errors": crc_errors}, "PNG IHDR chunk is missing"
            details = {
                "width": width,
                "height": height,
                "chunks": chunks,
                "crc_errors": crc_errors,
            }
            if crc_errors:
                return chunk_end, details, "PNG IEND found, but one or more CRC checks failed"
            return chunk_end, details, "PNG chunks and CRC values are valid"

        position = chunk_end

    return None, {"chunks": chunks, "crc_errors": crc_errors}, "PNG IEND chunk was not found"


def parse_zip_archive(data: bytes, start: int) -> Tuple[Optional[int], Dict[str, Any], str]:
    """Validate ZIP central directory and EOCD; return the exclusive archive boundary."""
    local_signature = b"PK\x03\x04"
    central_signature = b"PK\x01\x02"
    eocd_signature = b"PK\x05\x06"

    if data[start:start + 4] != local_signature:
        return None, {}, "ZIP local file header is missing"
    if start + 30 > len(data):
        return None, {}, "ZIP local file header is truncated"

    search_limit = min(len(data), start + 22 + 65535)
    eocd_position = data.find(eocd_signature, start + 4, search_limit)
    valid_eocd: Optional[Tuple[int, Tuple[Any, ...]]] = None

    while eocd_position >= 0:
        if eocd_position + 22 <= len(data):
            eocd = struct.unpack_from("<4s4H2LH", data, eocd_position)
            comment_length = eocd[7]
            archive_end = eocd_position + 22 + comment_length
            disk_number, cd_disk, entries_on_disk, total_entries = eocd[1:5]
            cd_size, cd_offset = eocd[5:7]
            cd_absolute = start + cd_offset
            if (archive_end <= len(data) and disk_number == 0 and cd_disk == 0
                    and entries_on_disk == total_entries and total_entries > 0
                    and cd_absolute >= start and cd_absolute + cd_size == eocd_position):
                valid_eocd = (eocd_position, eocd)
                break
        eocd_position = data.find(eocd_signature, eocd_position + 1, search_limit)

    if valid_eocd is None:
        return None, {}, "A matching ZIP EOCD/central directory was not found"

    eocd_position, eocd = valid_eocd
    total_entries = eocd[4]
    cd_size = eocd[5]
    cd_offset = eocd[6]
    cd_position = start + cd_offset
    cursor = cd_position
    entries: List[Dict[str, Any]] = []

    for _ in range(total_entries):
        if cursor + 46 > eocd_position or data[cursor:cursor + 4] != central_signature:
            return None, {}, "ZIP central directory entry is invalid or truncated"
        central = struct.unpack_from("<4s6H3L5H2L", data, cursor)
        name_length, extra_length, comment_length = central[10:13]
        local_offset = central[16]
        record_end = cursor + 46 + name_length + extra_length + comment_length
        if record_end > eocd_position:
            return None, {}, "ZIP central directory record exceeds EOCD boundary"
        filename_bytes = data[cursor + 46:cursor + 46 + name_length]
        filename = filename_bytes.decode("utf-8", errors="replace")
        local_position = start + local_offset
        if local_position + 30 > cd_position or data[local_position:local_position + 4] != local_signature:
            return None, {}, "ZIP central directory points to an invalid local header"
        local = struct.unpack_from("<4s5H3L2H", data, local_position)
        local_name_length, local_extra_length = local[9:11]
        local_name = data[local_position + 30:local_position + 30 + local_name_length]
        if local_name != filename_bytes:
            return None, {}, "ZIP local and central filenames do not match"
        data_position = local_position + 30 + local_name_length + local_extra_length
        compressed_size = central[8]
        if data_position + compressed_size > cd_position:
            return None, {}, "ZIP member data exceeds central directory boundary"
        entries.append({
            "filename": filename,
            "compressed_size": compressed_size,
            "uncompressed_size": central[9],
            "compression_method": central[4],
            "local_header_offset": local_offset,
        })
        cursor = record_end

    if cursor != cd_position + cd_size:
        return None, {}, "ZIP central directory size does not match its records"

    archive_end = eocd_position + 22 + eocd[7]
    details = {
        "entry_count": total_entries,
        "entries": entries,
        "central_directory_offset": cd_offset,
        "central_directory_size": cd_size,
        "eocd_offset": eocd_position,
    }
    return archive_end, details, "ZIP EOCD and central directory are structurally consistent"


def parse_elf_extent(data: bytes, start: int) -> Tuple[Optional[int], Dict[str, Any], str]:
    """Determine ELF size from ELF headers, program segments, and section headers."""
    if data[start:start + 4] != b"\x7FELF" or start + 16 > len(data):
        return None, {}, "ELF identification header is invalid"

    elf_class = data[start + 4]
    data_encoding = data[start + 5]
    if elf_class not in (1, 2) or data_encoding not in (1, 2):
        return None, {}, "Unsupported ELF class or byte order"
    endian = "<" if data_encoding == 1 else ">"

    if elf_class == 2:
        header_format = endian + "HHIQQQIHHHHHH"
        header_size = 64
        program_format = endian + "IIQQQQQQ"
        section_format = endian + "IIQQQQIIQQ"
        minimum_ph_size = 56
        minimum_sh_size = 64
    else:
        header_format = endian + "HHIIIIIHHHHHH"
        header_size = 52
        program_format = endian + "IIIIIIII"
        section_format = endian + "IIIIIIIIII"
        minimum_ph_size = 32
        minimum_sh_size = 40

    if start + 16 + struct.calcsize(header_format) > len(data):
        return None, {}, "ELF header is truncated"
    header = struct.unpack_from(header_format, data, start + 16)
    if elf_class == 2:
        (elf_type, machine, version, entry, phoff, shoff, flags, ehsize,
         phentsize, phnum, shentsize, shnum, _shstrndx) = header
    else:
        (elf_type, machine, version, entry, phoff, shoff, flags, ehsize,
         phentsize, phnum, shentsize, shnum, _shstrndx) = header

    if ehsize < header_size or start + ehsize > len(data):
        return None, {}, "ELF e_ehsize is invalid"

    extent = ehsize
    if phnum:
        if phentsize < minimum_ph_size:
            return None, {}, "ELF program header entry size is invalid"
        table_end = phoff + phentsize * phnum
        if table_end > len(data) - start:
            return None, {}, "ELF program header table exceeds image boundary"
        extent = max(extent, table_end)
        for index in range(phnum):
            ph_position = start + phoff + index * phentsize
            program = struct.unpack_from(program_format, data, ph_position)
            if elf_class == 2:
                p_offset, p_filesz = program[2], program[5]
            else:
                p_offset, p_filesz = program[1], program[4]
            if p_filesz:
                extent = max(extent, p_offset + p_filesz)

    if shnum:
        if shentsize < minimum_sh_size:
            return None, {}, "ELF section header entry size is invalid"
        table_end = shoff + shentsize * shnum
        if table_end > len(data) - start:
            return None, {}, "ELF section header table exceeds image boundary"
        extent = max(extent, table_end)
        for index in range(shnum):
            sh_position = start + shoff + index * shentsize
            section = struct.unpack_from(section_format, data, sh_position)
            section_type = section[1]
            sh_offset = section[4]
            sh_size = section[5]
            if section_type != 8 and sh_size:  # SHT_NOBITS occupies no bytes in the file.
                extent = max(extent, sh_offset + sh_size)

    if extent <= 0 or start + extent > len(data):
        return None, {}, "ELF-derived file boundary exceeds the image"

    details = {
        "elf_class": "ELF64" if elf_class == 2 else "ELF32",
        "endianness": "little" if data_encoding == 1 else "big",
        "machine": machine,
        "elf_type": elf_type,
        "entry_point": entry,
        "program_header_count": phnum,
        "section_header_count": shnum,
        "derived_size": extent,
    }
    return start + extent, details, "ELF size derived from header/table/segment extents"


def parse_pe_extent(data: bytes, start: int) -> Tuple[Optional[int], Dict[str, Any], str]:
    """Determine a PE file boundary using e_lfanew, SizeOfHeaders, and section data."""
    if data[start:start + 2] != b"MZ":
        return None, {}, "DOS MZ signature is missing"
    if start + 64 > len(data):
        return None, {}, "DOS header is truncated"

    pe_relative = struct.unpack_from("<I", data, start + 0x3C)[0]
    pe_position = start + pe_relative
    if pe_position + 24 > len(data) or data[pe_position:pe_position + 4] != b"PE\x00\x00":
        return None, {}, "PE signature referenced by e_lfanew is invalid"

    coff = struct.unpack_from("<4sHHIIIHH", data, pe_position)
    section_count = coff[2]
    optional_size = coff[6]
    optional_position = pe_position + 24
    optional_end = optional_position + optional_size
    if optional_end > len(data):
        return None, {}, "PE optional header exceeds image boundary"
    if optional_size < 64:
        return None, {}, "PE optional header is too short"

    optional_magic = struct.unpack_from("<H", data, optional_position)[0]
    if optional_magic not in (0x10B, 0x20B):
        return None, {}, "PE optional-header magic is not PE32 or PE32+"
    size_of_headers = struct.unpack_from("<I", data, optional_position + 60)[0]
    extent = max(pe_relative + 24 + optional_size, size_of_headers)
    section_table = optional_end

    for index in range(section_count):
        section_position = section_table + index * 40
        if section_position + 40 > len(data):
            return None, {}, "PE section table exceeds image boundary"
        raw_size, raw_pointer = struct.unpack_from("<II", data, section_position + 16)
        if raw_size:
            extent = max(extent, raw_pointer + raw_size)

    if extent <= 0 or start + extent > len(data):
        return None, {}, "PE-derived file boundary exceeds the image"
    details = {
        "pe_type": "PE32+" if optional_magic == 0x20B else "PE32",
        "section_count": section_count,
        "e_lfanew": pe_relative,
        "derived_size": extent,
    }
    return start + extent, details, "PE size derived from DOS/PE headers and section table"


def next_candidate_boundary(data_size: int, start: int,
                            detections: List[Dict[str, Any]]) -> int:
    """Return the next detected signature offset, or image end as a partial boundary."""
    later_offsets = [item["offset"] for item in detections if item["offset"] > start]
    return min(later_offsets) if later_offsets else data_size


def carve_candidate(data: bytes, detection: Dict[str, Any],
                    detections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Carve one top-level candidate using its format-specific structural boundary."""
    file_format = detection["format"]
    start = detection["offset"]
    details: Dict[str, Any] = {}
    status = "failed"
    reason = "No carving method was selected"
    end_exclusive: Optional[int] = None
    extension = detection["extension"]

    if file_format == "JPEG":
        valid, details, reason = parse_jpeg_header(data, start)
        if valid:
            eoi = data.find(b"\xFF\xD9", start + 3)
            if eoi >= 0:
                end_exclusive = eoi + 2
                status = "complete"
                reason = "JPEG SOF/SOS validated and EOI footer found"
            else:
                end_exclusive = next_candidate_boundary(len(data), start, detections)
                status = "partial"
                reason = "JPEG header is valid, but EOI footer is missing"

    elif file_format == "PDF":
        header = data[start:start + 8]
        version_valid = (len(header) == 8 and header[:5] == b"%PDF-"
                         and header[5:6].isdigit() and header[6:7] == b"."
                         and header[7:8].isdigit())
        if not version_valid:
            reason = "Raw %PDF bytes found, but the required %PDF-x.y header is invalid"
            status = "failed"
        else:
            eof_position = data.find(b"%%EOF", start + 8)
            if eof_position >= 0:
                end_exclusive = eof_position + 5
                while end_exclusive < len(data) and data[end_exclusive] in (0x0A, 0x0D):
                    end_exclusive += 1
                status = "complete"
                reason = "PDF version header and %%EOF footer found"
                details = {"pdf_version": header[5:8].decode("ascii")}
            else:
                end_exclusive = next_candidate_boundary(len(data), start, detections)
                status = "partial"
                reason = "PDF header is valid, but %%EOF footer is missing"
                details = {"pdf_version": header[5:8].decode("ascii")}

    elif file_format == "ELF":
        end_exclusive, details, reason = parse_elf_extent(data, start)
        if end_exclusive is not None:
            status = "complete"

    elif file_format == "ZIP":
        end_exclusive, details, reason = parse_zip_archive(data, start)
        if end_exclusive is not None:
            status = "complete"
        else:
            # A valid local-file header without a matching EOCD is only a partial candidate.
            if data[start:start + 4] == b"PK\x03\x04" and start + 30 <= len(data):
                end_exclusive = next_candidate_boundary(len(data), start, detections)
                status = "partial"
                reason = "ZIP local header found, but no matching complete archive EOCD"

    elif file_format == "PNG":
        end_exclusive, details, reason = parse_png(data, start)
        if end_exclusive is not None:
            status = "partial" if details.get("crc_errors") else "complete"
        else:
            end_exclusive = next_candidate_boundary(len(data), start, detections)
            status = "partial"

    elif file_format == "PE/MZ":
        end_exclusive, details, reason = parse_pe_extent(data, start)
        if end_exclusive is not None:
            status = "complete"

    if end_exclusive is None or end_exclusive <= start:
        return {
            "format": file_format,
            "offset_start": start,
            "offset_end": None,
            "size_bytes": 0,
            "filename": None,
            "sha256": None,
            "status": "failed",
            "details": details,
            "reason": reason,
            "recovery_timestamp": timestamp_now(),
        }

    end_exclusive = min(end_exclusive, len(data))
    extracted = data[start:end_exclusive]
    if not extracted:
        return {
            "format": file_format,
            "offset_start": start,
            "offset_end": None,
            "size_bytes": 0,
            "filename": None,
            "sha256": None,
            "status": "failed",
            "details": details,
            "reason": "No bytes were available within the calculated boundary",
            "recovery_timestamp": timestamp_now(),
        }

    return {
        "format": file_format,
        "offset_start": start,
        "offset_end": end_exclusive - 1,
        "end_exclusive": end_exclusive,
        "size_bytes": len(extracted),
        "filename": None,
        "sha256": sha256_bytes(extracted),
        "status": status,
        "details": details,
        "reason": reason,
        "recovery_timestamp": timestamp_now(),
        "_content": extracted,
    }


def save_recovered_content(content: bytes, extension: str, sequence: int,
                           recovered_dir: Path, seen_hashes: Dict[str, str]) -> Tuple[str, bool, str]:
    """Save carved bytes without overwriting files or creating duplicate content."""
    digest = sha256_bytes(content)
    if digest in seen_hashes:
        existing_name = seen_hashes[digest]
        return existing_name, False, "Identical content already exists; duplicate file was not written"

    candidate = sequence
    while True:
        filename = "recovered_{:03d}{}".format(candidate, extension)
        output_path = recovered_dir / filename
        if not output_path.exists():
            with output_path.open("xb") as output_file:
                output_file.write(content)
            seen_hashes[digest] = filename
            return filename, True, "File saved"
        if sha256_file(output_path) == digest:
            seen_hashes[digest] = filename
            return filename, False, "Existing output has identical SHA-256; it was reused"
        candidate += 1


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    """Write a JSON document as UTF-8 with indentation and a trailing newline."""
    with path.open("w", encoding="utf-8", newline="\n") as output_file:
        json.dump(payload, output_file, indent=2, ensure_ascii=False)
        output_file.write("\n")


def format_offset(offset: Optional[int]) -> str:
    """Format a decimal offset as an eight-digit hexadecimal value."""
    return "N/A" if offset is None else "0x{:08X}".format(offset)


def diagnose_pe_without_mz(data: bytes,
                           detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check suspicious headers for an e_lfanew pointer to PE without an MZ signature."""
    anomalies: List[Dict[str, Any]] = []
    for detection in detections:
        candidate_start = detection["offset"]
        if candidate_start + 0x40 > len(data):
            continue
        # e_lfanew is a standard DOS-header field at relative byte 0x3C.
        relative_pe_offset = struct.unpack_from("<I", data, candidate_start + 0x3C)[0]
        pe_position = candidate_start + relative_pe_offset
        if (relative_pe_offset >= 0x40 and pe_position + 4 <= len(data)
                and data[pe_position:pe_position + 4] == b"PE\x00\x00"
                and data[candidate_start:candidate_start + 2] != b"MZ"):
            anomalies.append({
                "candidate_offset": candidate_start,
                "candidate_offset_hex": format_offset(candidate_start),
                "pe_signature_offset": pe_position,
                "pe_signature_offset_hex": format_offset(pe_position),
                "e_lfanew": relative_pe_offset,
                "observation": "e_lfanew points to PE\x00\x00, but the required DOS MZ bytes are absent",
            })
    return anomalies


COLOR_ENABLED = False


def enable_terminal_colors() -> bool:
    """Enable ANSI colors on an interactive terminal, including modern Windows consoles."""
    if not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return os.environ.get("TERM", "") not in ("", "dumb")
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        stdout_handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint()
        if kernel32.GetConsoleMode(stdout_handle, ctypes.byref(mode)):
            return bool(kernel32.SetConsoleMode(stdout_handle, mode.value | 0x0004))
    except Exception:
        return False
    return False


def paint(value: Any, color_code: str) -> str:
    """Return terminal-colored text when ANSI color support is available."""
    if not COLOR_ENABLED:
        return str(value)
    return "{}{}{}".format(color_code, value, "\033[0m")


def clear_console() -> None:
    """Clear an interactive terminal without affecting redirected output or files."""
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


def print_banner() -> None:
    """Display the DFR tool banner and forensic-use warning."""
    cyan = "\033[96m"
    blue = "\033[94m"
    green = "\033[92m"
    magenta = "\033[95m"
    art = r"""
 ____  _____ ____
|  _ \|  ___|  _ \
| | | | |_  | |_) |
| |_| |  _| |  _ <
|____/|_|   |_| \_\
"""
    print(paint(art, cyan))
    print("{}  DIGITAL FORENSICS FILE RECOVERY TOOL  {}".format(
        paint("[ DFR ]", blue), paint("v2.0", green)))
    print(paint("HW7 // FILE SIGNATURE & RECOVERY", magenta))
    print(paint("Python 3.x | Standard Library | Read-only Evidence", green))
    print("-" * 68)
    print(paint("[!] FORENSIC NOTICE", cyan))
    print("Evidence image dibuka dalam mode read-only (rb).")
    print("Tool tidak mengubah byte pada evidence image asli.")
    print("-" * 68)


def print_menu(image_path: Optional[Path], image_loaded: bool,
               scan_ready: bool, recovery_done: bool) -> None:
    """Display the three-step workflow and current execution state."""
    def state_label(done: bool) -> str:
        """Return a compact status label for a completed or pending step."""
        return paint("[DONE]", "\033[92m") if done else paint("[WAIT]", "\033[93m")

    print("\n{}".format(paint("MAIN MENU / WORKFLOW", "\033[96m")))
    print("Evidence : {}".format(image_path if image_path else "Belum dipilih"))
    print("\n  {}  STEP 1 - IMAGE INFORMATION & INTEGRITY  {}".format(
        paint("[1]", "\033[94m"), state_label(image_loaded)))
    print("  {}  STEP 2 - FILE SIGNATURE SCANNER        {}".format(
        paint("[2]", "\033[94m"), state_label(scan_ready)))
    print("  {}  STEP 3 - FILE RECOVERY / CARVING       {}".format(
        paint("[3]", "\033[94m"), state_label(recovery_done)))
    print("  {}  EXIT".format(paint("[0]", "\033[91m")))
    print("-" * 68)


def show_image_information(image_path: Path, image_data: bytes) -> None:
    """Print image metadata, read-only access mode, and the image SHA-256."""
    print("\n{}".format(paint("[1] IMAGE INFORMATION & INTEGRITY", "\033[96m")))
    print("Nama file       : {}".format(image_path.name))
    print("Lokasi          : {}".format(image_path))
    print("Ukuran image    : {:,} bytes ({:.2f} KB)".format(
        len(image_data), len(image_data) / 1024.0))
    print("SHA-256 image   : {}".format(sha256_bytes(image_data)))
    print("Mode akses      : read-only (rb)")
    print(paint("[OK] Image berhasil dibaca tanpa modifikasi.", "\033[92m"))


def show_signature_results(image_data: bytes,
                           detections: List[Dict[str, Any]]) -> None:
    """Display all required magic-byte matches and their initial validation status."""
    print("\n{}".format(paint("[2] FILE SIGNATURE SCANNING", "\033[96m")))
    print("Pemindaian mencakup byte 0 sampai byte {:,}.".format(len(image_data) - 1))
    print("\n{:<10} {:<14} {:<16} {}".format(
        "Format", "Offset", "Magic Bytes", "Confidence / Status"))
    print("-" * 82)

    for detection in detections:
        file_format = detection["format"]
        offset = detection["offset"]
        confidence = "HIGH"
        note = "signature matched"
        if file_format == "PDF":
            header = image_data[offset:offset + 8]
            if not (len(header) == 8 and header[:5] == b"%PDF-"
                    and header[5:6].isdigit() and header[6:7] == b"."
                    and header[7:8].isdigit()):
                confidence = "LOW"
                note = "raw match; invalid PDF version header"
            else:
                note = "PDF version header validated"
        elif file_format == "ZIP":
            zip_end, _zip_info, _zip_reason = parse_zip_archive(image_data, offset)
            if zip_end is None:
                confidence = "MEDIUM"
                note = "local member header; not a standalone archive"
            else:
                note = "EOCD and central directory validated"
        elif file_format == "ELF":
            elf_end, _elf_info, elf_reason = parse_elf_extent(image_data, offset)
            if elf_end is None:
                confidence = "LOW"
                note = elf_reason
            else:
                note = "ELF header structure validated"
        elif file_format == "PNG":
            _png_end, png_info, png_reason = parse_png(image_data, offset)
            if _png_end is None or png_info.get("crc_errors"):
                confidence = "MEDIUM"
                note = png_reason
            else:
                note = "PNG chunks / CRC validated"
        elif file_format == "JPEG":
            jpeg_valid, jpeg_info, jpeg_reason = parse_jpeg_header(image_data, offset)
            if not jpeg_valid:
                confidence = "LOW"
                note = jpeg_reason
            else:
                note = "JPEG SOF/SOS validated; {} header gap byte(s)".format(
                    jpeg_info.get("header_gap_bytes", 0))
        print("{:<10} {:<14} {:<16} {} ({})".format(
            file_format, format_offset(offset), detection["magic_hex"],
            confidence, note))

    found_formats = {item["format"] for item in detections}
    for file_format, _magic, _extension in SIGNATURES:
        if file_format not in found_formats:
            print("{:<10} {:<14} {:<16} NOT FOUND".format(
                file_format, "-", "-", ""))
    print("\nTotal signature ditemukan: {}".format(len(detections)))
    print(paint("[OK] Signature scanning selesai.", "\033[92m"))


def perform_recovery(image_data: bytes,
                     detections: List[Dict[str, Any]],
                     image_path: Path,
                     tool_dir: Path) -> Dict[str, Any]:
    """Carve detected files, prevent duplicate outputs, and write JSON findings/logs."""
    recovered_dir = tool_dir / "recovered"
    recovered_dir.mkdir(parents=True, exist_ok=True)

    print("\n{}".format(paint("[3] FILE RECOVERY / HEADER-FOOTER CARVING", "\033[96m")))
    results: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    claimed_zip_ranges: List[Tuple[int, int]] = []
    seen_hashes: Dict[str, str] = {}
    for existing_file in sorted(recovered_dir.glob("recovered_*")):
        if existing_file.is_file():
            seen_hashes[sha256_file(existing_file)] = existing_file.name

    sequence = 1
    for detection in detections:
        offset = detection["offset"]
        if any(start < offset < end for start, end in claimed_zip_ranges):
            skipped.append({
                "format": detection["format"],
                "offset": offset,
                "offset_hex": format_offset(offset),
                "reason": "Signature is inside an already validated ZIP archive; not a separate file",
            })
            print("{} {} pada {}: signature berada di dalam arsip ZIP; dilewati.".format(
                paint("[SKIP]", "\033[93m"), detection["format"], format_offset(offset)))
            continue

        result = carve_candidate(image_data, detection, detections)
        if result["status"] in ("complete", "partial") and result.get("_content"):
            extension = detection["extension"]
            content = result.pop("_content")
            filename, was_written, save_note = save_recovered_content(
                content, extension, sequence, recovered_dir, seen_hashes)
            result["filename"] = "recovered/{}".format(filename)
            result["save_note"] = save_note
            result["new_file_written"] = was_written
            sequence += 1
            if result["format"] == "ZIP" and result["status"] == "complete":
                claimed_zip_ranges.append((result["offset_start"], result["offset_end"] + 1))

        results.append(result)
        status_color = "\033[92m" if result["status"] == "complete" else (
            "\033[93m" if result["status"] == "partial" else "\033[91m")
        print("\nNama file       : {}".format(result.get("filename") or "(tidak dibuat)"))
        print("Format          : {}".format(result["format"]))
        print("Offset awal     : {}".format(format_offset(result["offset_start"])))
        print("Offset akhir    : {}".format(format_offset(result["offset_end"])))
        print("Ukuran          : {:,} bytes".format(result["size_bytes"]))
        print("Status recovery : {}".format(paint(result["status"].upper(), status_color)))
        print("Keterangan      : {}".format(result["reason"]))
        if result.get("save_note"):
            print("Penyimpanan     : {}".format(result["save_note"]))
        print("-" * 68)

    complete_count = sum(1 for item in results if item["status"] == "complete")
    partial_count = sum(1 for item in results if item["status"] == "partial")
    failed_count = sum(1 for item in results if item["status"] == "failed")
    written_count = sum(1 for item in results if item.get("new_file_written"))

    scan_info = {
        "image_path": image_path.name,
        "image_size": len(image_data),
        "image_sha256": sha256_bytes(image_data),
        "scan_timestamp": timestamp_now(),
        "tool_version": TOOL_VERSION,
        "read_mode": "rb",
    }
    public_results = [
        {key: value for key, value in item.items()
         if key not in ("end_exclusive", "new_file_written", "_content")}
        for item in results
    ]
    summary = {
        "total_signatures_found": len(detections),
        "complete_recoveries": complete_count,
        "partial_recoveries": partial_count,
        "failed_recoveries": failed_count,
        "new_files_written": written_count,
        "skipped_nested_signatures": len(skipped),
    }
    findings_payload = {
        "scan_info": scan_info,
        "signature_matches": detections,
        "carving_results": public_results,
        "skipped_signatures": skipped,
        "additional_structural_observations": diagnose_pe_without_mz(image_data, detections),
        "summary": summary,
    }
    write_json(tool_dir / "findings.json", findings_payload)

    recovery_log_payload = {
        "scan_info": scan_info,
        "recovered_files": [
            {
                "filename": item.get("filename"),
                "format": item["format"],
                "offset_start": item["offset_start"],
                "offset_end": item["offset_end"],
                "size_bytes": item["size_bytes"],
                "sha256": item["sha256"],
                "status": item["status"],
                "recovery_timestamp": item["recovery_timestamp"],
                "reason": item["reason"],
            }
            for item in results
        ],
        "skipped_signatures": skipped,
        "summary": summary,
    }
    write_json(tool_dir / "recovery_log.json", recovery_log_payload)

    print("\n{}".format(paint("[4] RECOVERY SUMMARY", "\033[96m")))
    print("Total signature ditemukan         : {}".format(len(detections)))
    print("Total file berhasil dipulihkan    : {}".format(complete_count))
    print("Total partial recovery            : {}".format(partial_count))
    print("Total gagal                       : {}".format(failed_count))
    print("Total file baru yang ditulis      : {}".format(written_count))
    print("Signature nested/duplikat dilewati: {}".format(len(skipped)))
    print("\nOutput: recovered/ | findings.json | recovery_log.json")
    print(paint("[OK] Proses recovery dan pembuatan laporan selesai.", "\033[92m"))
    return summary


def main() -> int:
    """Run the interactive three-step HW7 workflow or accept an image path argument."""
    global COLOR_ENABLED
    COLOR_ENABLED = enable_terminal_colors()
    clear_console()
    print_banner()

    if len(sys.argv) > 2:
        print(paint("[ERROR] Format penggunaan tidak sesuai.", "\033[91m"))
        print("Usage: python3 recovery_tool.py evidence.img")
        return 2

    supplied_path = sys.argv[1] if len(sys.argv) == 2 else None
    image_path: Optional[Path] = None
    if supplied_path:
        image_path = Path(supplied_path).expanduser().resolve()
        if not image_path.is_file():
            print(paint("[ERROR] Image tidak ditemukan: {}".format(image_path), "\033[91m"))
            return 2
    else:
        while image_path is None:
            typed_path = input("Masukkan path evidence image (contoh: evidence.img): ").strip().strip('"')
            if not typed_path:
                print(paint("Path tidak boleh kosong.", "\033[93m"))
                continue
            candidate = Path(typed_path).expanduser().resolve()
            if not candidate.is_file():
                print(paint("File tidak ditemukan: {}".format(candidate), "\033[91m"))
            else:
                image_path = candidate

    tool_dir = Path(__file__).resolve().parent
    image_data: Optional[bytes] = None
    detections: Optional[List[Dict[str, Any]]] = None
    recovery_done = False

    while True:
        print_menu(image_path, image_data is not None,
                   detections is not None, recovery_done)
        try:
            choice = input("Pilih step [0-3]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nKeluar dari aplikasi.")
            return 0

        if choice == "0":
            print(paint("\n[EXIT] Evidence tetap tidak dimodifikasi. Sampai jumpa.", "\033[92m"))
            return 0
        elif choice == "1":
            try:
                image_data = read_image_readonly(image_path)
                show_image_information(image_path, image_data)
                detections = None
                recovery_done = False
            except OSError as error:
                print(paint("[ERROR] Gagal membaca image: {}".format(error), "\033[91m"))
        elif choice == "2":
            if image_data is None:
                print(paint("[!] Jalankan STEP 1 terlebih dahulu.", "\033[93m"))
            else:
                detections = scan_signatures(image_data)
                show_signature_results(image_data, detections)
                recovery_done = False
        elif choice == "3":
            if image_data is None:
                print(paint("[!] Jalankan STEP 1 terlebih dahulu.", "\033[93m"))
            elif detections is None:
                print(paint("[!] Jalankan STEP 2 terlebih dahulu.", "\033[93m"))
            else:
                perform_recovery(image_data, detections, image_path, tool_dir)
                recovery_done = True
        else:
            print(paint("Pilihan tidak dikenal. Masukkan 0, 1, 2, atau 3.", "\033[93m"))

        try:
            input("\nTekan Enter untuk kembali ke menu...")
        except (EOFError, KeyboardInterrupt):
            print("\nKeluar dari aplikasi.")
            return 0


if __name__ == "__main__":
    sys.exit(main())

if __name__ == "__main__":
    sys.exit(main())
