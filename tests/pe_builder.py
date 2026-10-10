"""Build tiny, harmless PE32 files in memory for tests.

Nothing here is executable in any meaningful sense: the "code" sections are
zeros or seeded random bytes. The point is to give pefile well-formed headers,
sections with chosen permissions/entropy, and an import table with chosen
DLL/function names, without committing or downloading any binary.
"""

import struct
from typing import Dict, List, Optional, Sequence, Tuple

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
IMAGE_BASE = 0x400000

SCN_CODE = 0x00000020
SCN_INIT_DATA = 0x00000040
SCN_EXEC = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000

TEXT = SCN_CODE | SCN_EXEC | SCN_READ          # R-X
DATA = SCN_INIT_DATA | SCN_READ | SCN_WRITE    # RW-
RWX = SCN_CODE | SCN_EXEC | SCN_READ | SCN_WRITE

FILE_HEADER_CHARS_EXE = 0x0102  # EXECUTABLE_IMAGE | 32BIT_MACHINE
FILE_HEADER_DLL = 0x2000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _import_section(rva: int, imports: Dict[str, List[str]]) -> Tuple[bytes, int]:
    """Lay out an import directory at `rva`. Returns (raw bytes, directory size)."""
    dlls = list(imports.items())
    desc_size = 20 * (len(dlls) + 1)  # + null terminator descriptor

    # First pass: offsets of every structure within the section.
    offset = desc_size
    layout = []
    for dll, funcs in dlls:
        ilt = offset
        offset += 4 * (len(funcs) + 1)
        iat = offset
        offset += 4 * (len(funcs) + 1)
        name = offset
        offset += len(dll) + 1
        offset = _align(offset, 2)
        hints = []
        for func in funcs:
            hints.append(offset)
            offset += 2 + len(func) + 1
            offset = _align(offset, 2)
        layout.append((ilt, iat, name, hints))

    buf = bytearray(offset)
    for i, ((dll, funcs), (ilt, iat, name, hints)) in enumerate(zip(dlls, layout)):
        struct.pack_into("<IIIII", buf, 20 * i, rva + ilt, 0, 0, rva + name, rva + iat)
        for j, hint_off in enumerate(hints):
            struct.pack_into("<I", buf, ilt + 4 * j, rva + hint_off)
            struct.pack_into("<I", buf, iat + 4 * j, rva + hint_off)
            struct.pack_into("<H", buf, hint_off, 0)
            buf[hint_off + 2:hint_off + 2 + len(funcs[j])] = funcs[j].encode()
        buf[name:name + len(dll)] = dll.encode()
    return bytes(buf), desc_size


def build_pe(
    sections: Sequence[Tuple[str, int, bytes]] = ((".text", TEXT, b"\x00" * 0x200),),
    imports: Optional[Dict[str, List[str]]] = None,
    timestamp: int = 1_600_000_000,  # 2020-09-13
    dll: bool = False,
    machine: int = 0x14C,  # i386
) -> bytes:
    """Return the bytes of a minimal PE32 image."""
    sections = list(sections)
    n_sections = len(sections) + (1 if imports else 0)
    headers_size = _align(0x40 + 4 + 20 + 224 + 40 * n_sections, FILE_ALIGN)

    # Place sections: raw data back to back, VAs on SECT_ALIGN boundaries.
    placed = []
    raw_ptr = headers_size
    va = SECT_ALIGN
    for name, chars, data in sections:
        raw_size = _align(max(len(data), 1), FILE_ALIGN)
        placed.append((name, chars, data, va, raw_ptr, raw_size))
        raw_ptr += raw_size
        va += _align(max(len(data), 1), SECT_ALIGN)

    import_dir = (0, 0)
    if imports:
        data, dir_size = _import_section(va, imports)
        raw_size = _align(len(data), FILE_ALIGN)
        placed.append((".idata", DATA, data, va, raw_ptr, raw_size))
        import_dir = (va, dir_size)
        raw_ptr += raw_size
        va += _align(len(data), SECT_ALIGN)

    size_of_image = va
    characteristics = FILE_HEADER_CHARS_EXE | (FILE_HEADER_DLL if dll else 0)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    file_header = struct.pack(
        "<HHIIIHH", machine, n_sections, timestamp, 0, 0, 224, characteristics
    )
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0,                      # Magic (PE32), linker version
        0x200, 0x200, 0,                   # SizeOfCode / InitializedData / Uninitialized
        placed[0][3], placed[0][3], 0,     # AddressOfEntryPoint, BaseOfCode, BaseOfData
        IMAGE_BASE, SECT_ALIGN, FILE_ALIGN,
        6, 0, 0, 0, 6, 0,                  # OS / image / subsystem versions
        0, size_of_image, headers_size, 0,
        3, 0,                              # Subsystem: console, DllCharacteristics
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16,                             # LoaderFlags, NumberOfRvaAndSizes
    )
    dirs = bytearray(16 * 8)
    struct.pack_into("<II", dirs, 8 * 1, *import_dir)  # IMAGE_DIRECTORY_ENTRY_IMPORT

    section_table = b"".join(
        struct.pack(
            "<8sIIIIIIHHI",
            name.encode()[:8], max(len(data), 1), sect_va, raw_size, ptr, 0, 0, 0, 0, chars,
        )
        for name, chars, data, sect_va, ptr, raw_size in placed
    )

    image = bytearray(dos + b"PE\x00\x00" + file_header + optional + dirs + section_table)
    image += b"\x00" * (headers_size - len(image))
    for _name, _chars, data, _va, _ptr, raw_size in placed:
        image += data + b"\x00" * (raw_size - len(data))
    return bytes(image)
