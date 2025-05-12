# fmt: off
from typing import (Any, ByteString, Callable, Dict, Generator, Iterable,
                    Iterator, List, NoReturn, Optional, Sequence, Set, Tuple, Type,
                    Union)
# fmt: on
import enum
from gef.memory import Permission


class Endianness(enum.Enum):
    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2

    def __str__(self) -> str:
        return "<" if self == Endianness.LITTLE_ENDIAN else ">"

    def __repr__(self) -> str:
        return self.name

    def __int__(self) -> int:
        return self.value


class Instruction:
    """GEF representation of a CPU instruction."""

    def __init__(
        self,
        address: int,
        location: str,
        mnemo: str,
        operands: list[str],
        opcodes: bytes,
    ) -> None:
        self.address, self.location, self.mnemonic, self.operands, self.opcodes = (
            address,
            location,
            mnemo,
            operands,
            opcodes,
        )
        return

    # Allow formatting an instruction with {:o} to show opcodes.
    # The number of bytes to display can be configured, e.g. {:4o} to only show 4 bytes of the opcodes
    def __format__(self, format_spec: str) -> str:
        if len(format_spec) == 0 or format_spec[-1] != "o":
            return str(self)

        if format_spec == "o":
            opcodes_len = len(self.opcodes)
        else:
            opcodes_len = int(format_spec[:-1])

        opcodes_text = "".join(f"{b:02x}" for b in self.opcodes[:opcodes_len])
        if opcodes_len < len(self.opcodes):
            opcodes_text += "..."
        return (
            f"{self.address:#10x} {opcodes_text:{opcodes_len * 2 + 3:d}s} {self.location:16} "
            f"{self.mnemonic:6} {', '.join(self.operands)}"
        )

    def __str__(self) -> str:
        return f"{self.address:#10x} {self.location:16} {self.mnemonic:6} {', '.join(self.operands)}"

    def is_valid(self) -> bool:
        return "(bad)" not in self.mnemonic

    def size(self) -> int:
        return len(self.opcodes)

    def next(self) -> "Instruction":
        address = self.address + self.size()
        return gef_get_instruction_at(address)


class ArchitectureBase:
    """Class decorator for declaring an architecture to GEF."""

    aliases: tuple[str | Elf.Abi, ...] = ()

    def __init_subclass__(cls: Type["ArchitectureBase"], **kwargs):
        global __registered_architectures__
        super().__init_subclass__(**kwargs)
        for key in getattr(cls, "aliases"):
            if issubclass(cls, Architecture):
                if isinstance(key, str):
                    __registered_architectures__[key.lower()] = cls
                else:
                    __registered_architectures__[key] = cls
        return


class Architecture(ArchitectureBase):
    """Generic metaclass for the architecture supported by GEF."""

    # Mandatory defined attributes by inheriting classes
    arch: str
    mode: str
    all_registers: Union[Tuple[()], Tuple[str, ...]]
    nop_insn: bytes
    return_register: str
    flag_register: Optional[str]
    instruction_length: Optional[int]
    flags_table: Dict[int, str]
    syscall_register: Optional[str]
    syscall_instructions: Union[Tuple[()], Tuple[str, ...]]
    function_parameters: Union[Tuple[()], Tuple[str, ...]]

    # Optionally defined attributes
    _ptrsize: Optional[int] = None
    _endianness: Optional[Endianness] = None
    special_registers: Union[Tuple[()], Tuple[str, ...]] = ()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        attributes = (
            "arch",
            "mode",
            "aliases",
            "all_registers",
            "nop_insn",
            "return_register",
            "flag_register",
            "instruction_length",
            "flags_table",
            "function_parameters",
        )
        if not all(map(lambda x: hasattr(cls, x), attributes)):
            raise NotImplementedError

    def __str__(self) -> str:
        return (
            f"Architecture({self.arch}, {self.mode or 'None'}, {repr(self.endianness)})"
        )

    @staticmethod
    def supports_gdb_arch(gdb_arch: str) -> Optional[bool]:
        """If implemented by a child `Architecture`, this function dictates if the current class
        supports the loaded ELF file (which can be accessed via `gef.binary`). This callback
        function will override any assumption made by GEF to determine the architecture.
        """
        return None

    def flag_register_to_human(self, val: Optional[int] = None) -> str:
        raise NotImplementedError

    def is_call(self, insn: Instruction) -> bool:
        raise NotImplementedError

    def is_ret(self, insn: Instruction) -> bool:
        raise NotImplementedError

    def is_conditional_branch(self, insn: Instruction) -> bool:
        raise NotImplementedError

    def is_branch_taken(self, insn: Instruction) -> Tuple[bool, str]:
        raise NotImplementedError

    def get_ra(self, insn: Instruction, frame: "gdb.Frame") -> Optional[int]:
        raise NotImplementedError

    def canary_address(self) -> int:
        raise NotImplementedError

    @classmethod
    def mprotect_asm(cls, addr: int, size: int, perm: Permission) -> str:
        raise NotImplementedError

    def reset_caches(self) -> None:
        self.__get_register_for_selected_frame.cache_clear()
        return

    def __get_register(self, regname: str) -> int:
        """Return a register's value."""
        curframe = gdb.selected_frame()
        key = curframe.pc() ^ int(
            curframe.read_register("sp")
        )  # todo: check when/if gdb.Frame implements `level()`
        return self.__get_register_for_selected_frame(regname, key)

    @lru_cache()
    def __get_register_for_selected_frame(self, regname: str, hash_key: int) -> int:
        # 1st chance
        try:
            return parse_address(regname)
        except gdb.error:
            pass

        # 2nd chance - if an exception, propagate it
        regname = regname.lstrip("$")
        value = gdb.selected_frame().read_register(regname)
        return int(value)

    def register(self, name: str) -> int:
        if not is_alive():
            raise gdb.error("No debugging session active")
        return self.__get_register(name)

    @property
    def registers(self) -> Generator[str, None, None]:
        yield from self.all_registers

    @property
    def pc(self) -> int:
        return self.register("$pc")

    @property
    def sp(self) -> int:
        return self.register("$sp")

    @property
    def fp(self) -> int:
        return self.register("$fp")

    @property
    def ptrsize(self) -> int:
        if not self._ptrsize:
            res = cached_lookup_type("size_t")
            if res is not None:
                self._ptrsize = res.sizeof
            else:
                self._ptrsize = gdb.parse_and_eval("$pc").type.sizeof
        return self._ptrsize

    @property
    def endianness(self) -> Endianness:
        if not self._endianness:
            output = gdb.execute("show endian", to_string=True).strip().lower()
            if "little endian" in output:
                self._endianness = Endianness.LITTLE_ENDIAN
            elif "big endian" in output:
                self._endianness = Endianness.BIG_ENDIAN
            else:
                raise OSError(f"No valid endianess found in '{output}'")
        return self._endianness

    def get_ith_parameter(
        self, i: int, in_func: bool = True
    ) -> Tuple[str, Optional[int]]:
        """Retrieves the correct parameter used for the current function call."""
        reg = self.function_parameters[i]
        val = self.register(reg)
        key = reg
        return key, val


class GenericArchitecture(Architecture):
    arch = "Generic"
    mode = ""
    aliases = ("GenericArchitecture",)
    all_registers = ()
    instruction_length = 0
    return_register = ""
    function_parameters = ()
    syscall_register = ""
    syscall_instructions = ()
    nop_insn = b""
    flag_register = None
    flags_table = {}


class ARM(Architecture):
    aliases = ("ARM", Elf.Abi.ARM)
    arch = "ARM"
    all_registers = (
        "$r0",
        "$r1",
        "$r2",
        "$r3",
        "$r4",
        "$r5",
        "$r6",
        "$r7",
        "$r8",
        "$r9",
        "$r10",
        "$r11",
        "$r12",
        "$sp",
        "$lr",
        "$pc",
        "$cpsr",
    )

    # https://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0041c/Caccegih.html
    nop_insn = b"\x01\x10\xa0\xe1"  # mov r1, r1
    return_register = "$r0"
    flag_register: str = "$cpsr"
    flags_table = {
        31: "negative",
        30: "zero",
        29: "carry",
        28: "overflow",
        7: "interrupt",
        6: "fast",
        5: "thumb",
    }
    function_parameters = ("$r0", "$r1", "$r2", "$r3")
    syscall_register = "$r7"
    syscall_instructions = ("swi 0x0", "swi NR")
    _endianness = Endianness.LITTLE_ENDIAN

    def is_thumb(self) -> bool:
        """Determine if the machine is currently in THUMB mode."""
        return is_alive() and (self.cpsr & (1 << 5) == 1)

    @property
    def pc(self) -> Optional[int]:
        pc = gef.arch.register("$pc")
        if self.is_thumb():
            pc += 1
        return pc

    @property
    def cpsr(self) -> int:
        if not is_alive():
            raise RuntimeError("Cannot get CPSR, program not started?")
        return gef.arch.register(self.flag_register)

    @property
    def mode(self) -> str:
        return "THUMB" if self.is_thumb() else "ARM"

    @property
    def instruction_length(self) -> Optional[int]:
        # Thumb instructions have variable-length (2 or 4-byte)
        return None if self.is_thumb() else 4

    @property
    def ptrsize(self) -> int:
        return 4

    def is_call(self, insn: Instruction) -> bool:
        mnemo = insn.mnemonic
        call_mnemos = {"bl", "blx"}
        return mnemo in call_mnemos

    def is_ret(self, insn: Instruction) -> bool:
        pop_mnemos = {"pop"}
        branch_mnemos = {"bl", "bx"}
        write_mnemos = {"ldr", "add"}
        if insn.mnemonic in pop_mnemos:
            return insn.operands[-1] == " pc}"
        if insn.mnemonic in branch_mnemos:
            return insn.operands[-1] == "lr"
        if insn.mnemonic in write_mnemos:
            return insn.operands[0] == "pc"
        return False

    def flag_register_to_human(self, val: Optional[int] = None) -> str:
        # https://www.botskool.com/user-pages/tutorials/electronics/arm-7-tutorial-part-1
        if val is None:
            reg = self.flag_register
            val = gef.arch.register(reg)
        return flags_to_human(val, self.flags_table)

    def is_conditional_branch(self, insn: Instruction) -> bool:
        conditions = {
            "eq",
            "ne",
            "lt",
            "le",
            "gt",
            "ge",
            "vs",
            "vc",
            "mi",
            "pl",
            "hi",
            "ls",
            "cc",
            "cs",
        }
        return insn.mnemonic[-2:] in conditions

    def is_branch_taken(self, insn: Instruction) -> Tuple[bool, str]:
        mnemo = insn.mnemonic
        # ref: https://www.davespace.co.uk/arm/introduction-to-arm/conditional.html
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = gef.arch.register(self.flag_register)
        taken, reason = False, ""

        if mnemo.endswith("eq"):
            taken, reason = bool(val & (1 << flags["zero"])), "Z"
        elif mnemo.endswith("ne"):
            taken, reason = not bool(val & (1 << flags["zero"])), "!Z"
        elif mnemo.endswith("lt"):
            taken, reason = (
                bool(val & (1 << flags["negative"]))
                != bool(val & (1 << flags["overflow"])),
                "N!=V",
            )
        elif mnemo.endswith("le"):
            taken, reason = (
                bool(val & (1 << flags["zero"]))
                or bool(val & (1 << flags["negative"]))
                != bool(val & (1 << flags["overflow"])),
                "Z || N!=V",
            )
        elif mnemo.endswith("gt"):
            taken, reason = (
                bool(val & (1 << flags["zero"])) == 0
                and bool(val & (1 << flags["negative"]))
                == bool(val & (1 << flags["overflow"])),
                "!Z && N==V",
            )
        elif mnemo.endswith("ge"):
            taken, reason = (
                bool(val & (1 << flags["negative"]))
                == bool(val & (1 << flags["overflow"])),
                "N==V",
            )
        elif mnemo.endswith("vs"):
            taken, reason = bool(val & (1 << flags["overflow"])), "V"
        elif mnemo.endswith("vc"):
            taken, reason = not val & (1 << flags["overflow"]), "!V"
        elif mnemo.endswith("mi"):
            taken, reason = bool(val & (1 << flags["negative"])), "N"
        elif mnemo.endswith("pl"):
            taken, reason = not val & (1 << flags["negative"]), "N==0"
        elif mnemo.endswith("hi"):
            taken, reason = (
                bool(val & (1 << flags["carry"]))
                and not bool(val & (1 << flags["zero"])),
                "C && !Z",
            )
        elif mnemo.endswith("ls"):
            taken, reason = (
                not val & (1 << flags["carry"]) or bool(val & (1 << flags["zero"])),
                "!C || Z",
            )
        elif mnemo.endswith("cs"):
            taken, reason = bool(val & (1 << flags["carry"])), "C"
        elif mnemo.endswith("cc"):
            taken, reason = not val & (1 << flags["carry"]), "!C"
        return taken, reason

    def get_ra(self, insn: Instruction, frame: "gdb.Frame") -> int:
        ra = None
        if self.is_ret(insn):
            # If it's a pop, we have to peek into the stack, otherwise use lr
            if insn.mnemonic == "pop":
                ra_addr = gef.arch.sp + (len(insn.operands) - 1) * self.ptrsize
                ra = to_unsigned_long(dereference(ra_addr))
            elif insn.mnemonic == "ldr":
                return to_unsigned_long(dereference(gef.arch.sp))
            else:  # 'bx lr' or 'add pc, lr, #0'
                return gef.arch.register("$lr")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr: int, size: int, perm: Permission) -> str:
        _NR_mprotect = 125
        insns = [
            "push {r0-r2, r7}",
            f"mov r1, {addr & 0xffff:d}",
            f"mov r0, {(addr & 0xffff0000) >> 16:d}",
            "lsl r0, r0, 16",
            "add r0, r0, r1",
            f"mov r1, {size & 0xffff:d}",
            f"mov r2, {perm.value & 0xff:d}",
            f"mov r7, {_NR_mprotect:d}",
            "svc 0",
            "pop {r0-r2, r7}",
        ]
        return "; ".join(insns)
