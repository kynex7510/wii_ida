import ida_loader
import ida_segment
import ida_bytes
import ida_entry
import ida_lines

# Global

MAX_TEXT = 7
MAX_DATA = 11
SCRIPT_NAME = "dol_loader.py"
REPO_URL = "https://github.com/kynex7510/wii_ida"

# Helpers

def read_bytes(f, off, size):
    f.seek(off)
    b = f.read(size)
    if len(b) < size:
        raise Exception("Could not read bytes from file")
    return b

def read_dword(f, off):
    return int.from_bytes(read_bytes(f, off, 0x4), 'big')

def add_segment(start, size, name, perms) -> None:
    if perms & ida_segment.SEGPERM_EXEC:
        sclass = "CODE"
    elif perms == ida_segment.SEGPERM_READ:
        sclass = "CONST"
    elif name == ".bss":
        sclass = "BSS"
    else:
        sclass = "DATA"
    if not ida_segment.add_segm(0, start, start + size, name, sclass):
        raise Exception(f"Could not add segment {name}")
    seg = ida_segment.get_segm_by_name(name)
    ida_segment.set_segm_addressing(seg, 1)
    seg.perm = perms

# Section

class Section:
    def __init__(self):
        self._offset = 0
        self._base = 0
        self._size = 0

    @staticmethod
    def load_text(f, index):
        sec = Section()
        sec._offset = read_dword(f, (index * 0x4))
        sec._base = read_dword(f, 0x48 + (index * 0x4))
        sec._size = read_dword(f, 0x90 + (index * 0x4))
        return sec

    @staticmethod
    def load_data(f, index):
        sec = Section()
        sec._offset = read_dword(f, 0x1C + (index * 0x4))
        sec._base = read_dword(f, 0x64 + (index * 0x4))
        sec._size = read_dword(f, 0xAC + (index * 0x4))
        return sec
    
    @staticmethod
    def load_bss(f):
        sec = Section()
        sec._offset = 0
        sec._base = read_dword(f, 0xD8)
        sec._size = read_dword(f, 0xDC)
        return sec

    def valid(self):
        return self._base != 0 and self._size != 0

    def get_offset(self):
        return self._offset
    
    def get_base(self):
        return self._base
    
    def get_size(self):
        return self._size

# Loader

def accept_file(f, path):
    if path.lower().endswith(".dol"):
        return {
            "format" : "Wii Executable (DOL)",
            "processor" : "PPC",
            "options" : 1 | ida_loader.ACCEPT_FIRST,
        }
    
    return 0

def load_file(f, neflags, format_string):
    first_sec = 0

    # Load .text sections.
    for i in range(MAX_TEXT):
        sec = Section.load_text(f, i)
        if not sec.valid():
            break

        if not first_sec or sec.get_base() < first_sec:
            first_sec = sec.get_base()

        add_segment(sec.get_base(), sec.get_size(), f".text{i}", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC)
        text_bytes = read_bytes(f, sec.get_offset(), sec.get_size())
        ida_bytes.put_bytes(sec.get_base(), text_bytes)

    # Load .data sections.
    for i in range(MAX_DATA):
        sec = Section.load_data(f, i)
        if not sec.valid():
            break

        if sec.get_base() < first_sec:
            first_sec = sec.get_base()

        add_segment(sec.get_base(), sec.get_size(), f".data{i}", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)
        data_bytes = read_bytes(f, sec.get_offset(), sec.get_size())
        ida_bytes.put_bytes(sec.get_base(), data_bytes)

    # Load .bss section.
    sec = Section.load_bss(f)
    if sec.valid():
        if sec.get_base() < first_sec:
            first_sec = sec.get_base()
        add_segment(sec.get_base(), sec.get_size(), ".bss", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)

    # Set entrypoint.
    entry = read_dword(f, 0xE0)
    ida_entry.add_entry(entry, entry, "start", True)

    # Add comments.
    ida_lines.add_extra_line(first_sec, True, f"; Loaded with {SCRIPT_NAME}")
    ida_lines.add_extra_line(first_sec, True, f"; {REPO_URL}")
    return 1
