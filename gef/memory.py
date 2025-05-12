# fmt: off
from typing import (Any, ByteString, Callable, Dict, Generator, Iterable,
                    Iterator, List, NoReturn, Optional, Sequence, Set, Tuple, Type,
                    Union)
# fmt: on

import enum
from gef.color import Color
from gef.gef import gef
import lldb
from lldb import SBDebugger, SBCommandReturnObject, SBExecutionContext


class Permission(enum.Flag):
    """GEF representation of Linux permission."""

    NONE = 0
    EXECUTE = 1
    WRITE = 2
    READ = 4
    ALL = 7

    def __str__(self) -> str:
        perm_str = ""
        perm_str += "r" if self & Permission.READ else "-"
        perm_str += "w" if self & Permission.WRITE else "-"
        perm_str += "x" if self & Permission.EXECUTE else "-"
        return perm_str

    @classmethod
    def from_info_sections(cls, *args: str) -> "Permission":
        perm = cls(0)
        for arg in args:
            if "READONLY" in arg:
                perm |= Permission.READ
            if "DATA" in arg:
                perm |= Permission.WRITE
            if "CODE" in arg:
                perm |= Permission.EXECUTE
        return perm

    @classmethod
    def from_process_maps(cls, perm_str: str) -> "Permission":
        perm = cls(0)
        if perm_str[0] == "r":
            perm |= Permission.READ
        if perm_str[1] == "w":
            perm |= Permission.WRITE
        if perm_str[2] == "x":
            perm |= Permission.EXECUTE
        return perm

    @classmethod
    def from_info_mem(cls, perm_str: str) -> "Permission":
        perm = cls(0)
        # perm_str[0] shows if this is a user page, which
        # we don't track
        if perm_str[1] == "r":
            perm |= Permission.READ
        if perm_str[2] == "w":
            perm |= Permission.WRITE
        return perm


class Section:
    """GEF representation of process memory sections."""

    def __init__(self, **kwargs: Any) -> None:
        self.page_start: int = kwargs.get("page_start", 0)
        self.page_end: int = kwargs.get("page_end", 0)
        self.offset: int = kwargs.get("offset", 0)
        self.permission: Permission = kwargs.get("permission", Permission(0))
        self.inode: int = kwargs.get("inode", 0)
        self.path: str = kwargs.get("path", "")
        return

    def is_readable(self) -> bool:
        return bool(self.permission & Permission.READ)

    def is_writable(self) -> bool:
        return bool(self.permission & Permission.WRITE)

    def is_executable(self) -> bool:
        return bool(self.permission & Permission.EXECUTE)

    @property
    def size(self) -> int:
        if self.page_end is None or self.page_start is None:
            return -1
        return self.page_end - self.page_start

    # @property
    # def realpath(self) -> str:
    #    # when in a `gef-remote` session, realpath returns the path to the binary on the local disk, not remote
    #    return (
    #        self.path
    #        if gef.session.remote is None
    #        else f"/tmp/gef/{gef.session.remote:d}/{self.path}"
    #    )

    def __str__(self) -> str:
        return (
            f"Section(page_start={self.page_start:#x}, page_end={self.page_end:#x}, "
            f"permissions={self.permission!s})"
        )


class SectionList:

    def __init__(self) -> None:
        self.sections: List[Section] = []

    # def __getitem__(self, index: int) -> Section:
    #    return self.sections[index]

    def __iter__(self) -> Iterator[Section]:
        return iter(self.sections)

    def __getittem__(self, index: int) -> Section:
        return self.sections[index]

    def __len__(self) -> int:
        return len(self.sections)

    @staticmethod
    def parse_string_range(s: str) -> Iterator[int]:
        """Parses an address range (e.g. 0x400000-0x401000)"""
        addrs = s.split("-")
        return map(lambda x: int(x, 16), addrs)

    @classmethod
    def parse_section(cls, line: str) -> Section:
        line = line.strip()
        addr, perm, off, _, rest = line.split(" ", 4)
        rest = rest.split(" ", 1)
        if len(rest) == 1:
            inode = rest[0]
            pathname = ""
        else:
            inode = rest[0]
            pathname = rest[1].lstrip()

        addr_start, addr_end = cls.parse_string_range(addr)
        off = int(off, 16)
        perm = Permission.from_process_maps(perm)
        inode = int(inode)
        # print(f"{addr_start=}, {addr_end=}, {off=}, {perm=}, {inode=}, {pathname=}")
        return Section(
            page_start=addr_start,
            page_end=addr_end,
            offset=off,
            permission=perm,
            inode=inode,
            path=pathname,
        )

    def update(self, exe_ctx: SBExecutionContext) -> None:
        debugger = lldb.debugger  # for plugin, only one debugger
        process = exe_ctx.process
        pid = process.GetProcessID()
        if pid == lldb.LLDB_INVALID_PROCESS_ID:
            print("vmmap: cannot get pid")
            return

        interpreter: lldb.SBCommandInterpreter = debugger.GetCommandInterpreter()
        rto = lldb.SBCommandReturnObject()
        cmd = f"platform shell cat /proc/{pid}/maps"
        interpreter.HandleCommand(cmd, rto)
        if not rto.Succeeded():
            print(f"vmmap: `{cmd}` failed")
            return

        output: str = rto.GetOutput()
        if not output:
            print("vmmap: No output")
            return

        self.sections = [
            self.parse_section(line) for line in output.strip().split("\n")
        ]

    def find_section(self, address):
        for section in self.sections:
            if section.page_start <= address < section.page_end:
                return section
        return None


# TODO: fix ptrsize
def align_address(address: int, ptrsize: int = 4) -> int:
    """Align the provided address to the process's native length."""
    if ptrsize == 4:
        return address & 0xFFFFFFFF

    return address & 0xFFFFFFFFFFFFFFFF


def format_address(addr: int, ptrsize: int = 4) -> str:
    """Format the address according to its size."""
    addr = align_address(addr, ptrsize)

    if ptrsize == 4:
        return f"0x{addr:08x}"

    return f"0x{addr:016x}"
