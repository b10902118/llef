import os

from typing import Dict, Type, Optional, Union, Literal
from string import printable

import lldb
from lldb import (
    SBAddress,
    SBDebugger,
    SBError,
    SBExecutionContext,
    SBFrame,
    SBProcess,
    SBTarget,
    SBThread,
    SBValue,
)

from arch import get_arch, get_arch_from_str
from arch.base_arch import BaseArch, FlagRegister
from common.constants import GLYPHS, TERM_COLORS
from common.settings import LLEFSettings
from common.color_settings import LLEFColorSettings
from common.state import LLEFState
from common.util import (
    attempt_to_read_string_from_memory,
    clear_page,
    get_frame_arguments,
    get_registers,
    print_instruction,
    print_line,
    print_line_with_string,
    change_use_color,
    output_line,
    is_ascii_cstring,
)
from gef.memory import Section, SectionList, format_address
import settings
import time

from gef.color import Color
from setting_utils import get_address_color


class ContextHandler:
    """Context handler. One instance only. (Singleton)"""

    frame: SBFrame
    process: SBProcess
    target: SBTarget
    thread: SBThread
    arch: Type[BaseArch]
    debugger: SBDebugger
    exe_ctx: SBExecutionContext
    settings: LLEFSettings
    color_settings: LLEFColorSettings
    state: LLEFState
    section_list: SectionList

    def __init__(
        self,
        debugger: SBDebugger,
    ) -> None:
        """
        For up to date documentation on args provided to this function run: `help target stop-hook add`
        """
        print("ContextHandler init")
        self.debugger = debugger
        self.settings = LLEFSettings(debugger)
        self.color_settings = LLEFColorSettings()
        self.state = LLEFState()
        change_use_color(self.settings.color_output)
        self.section_list = SectionList()

    def generate_rebased_address_string(self, address: Union[SBAddress, int]) -> str:
        # TODO: remove leading space
        """
        `(libc.so.6 0xdeadbeef)`
        """
        if isinstance(address, int):
            address = SBAddress(address, self.target)
        module = address.GetModule()

        if module is not None and self.settings.rebase_addresses is True:
            file_name = os.path.basename(str(module.file))
            rebased_address = address.GetFileAddress()
            return (
                f" {TERM_COLORS[self.color_settings.rebased_address_color].value}"
                f"({file_name}+{rebased_address:#x})"
                f"{TERM_COLORS.ENDC.value}"
            )

        return ""

    def is_valid_address(self, addr: int) -> bool:
        # SBAddress.GetSection cannot detect section to stack (maybe dynamic sections)
        return self.section_list.find_section(addr) is not None

    def dereference_once(self, addr: int) -> dict:

        if not self.is_valid_address(addr):
            return {
                "address": addr,
                "type": "NaA",  # Not an Address
            }
        else:
            addr_obj = SBAddress(addr, self.target)
            if addr_obj.symbol.IsValid():
                offset = addr_obj.offset - addr_obj.symbol.GetStartAddress().offset
                return {
                    "address": addr,
                    "type": "symbol",  # addr is a pointer to symbol
                    "data": {"symbol": addr_obj.symbol.name, "offset": offset},
                }

            # TODO: check if addr is code
            referenced_string = attempt_to_read_string_from_memory(
                self.process, addr_obj.GetLoadAddress(self.target)
            )
            if referenced_string:
                return {
                    "address": addr,
                    "type": "string",  # addr is a pointer to string
                    "data": referenced_string,
                }

            else:
                err = SBError()
                new_addr = self.process.ReadPointerFromMemory(addr, err)
                if err.Fail():  # should not happen
                    return {
                        "address": addr,
                        "type": "error",
                    }
                else:
                    return {
                        "address": addr,
                        "type": "pointer",  # addr is a pointer to any other
                        "data": new_addr,
                    }

    def get_dereference_path(self, addr: int) -> list[dict]:
        path = []
        seen_addresses = []
        depth = 0

        while depth < settings.dereference_max_depth:
            result = self.dereference_once(addr)
            path.append(result)
            if result["type"] == "NaA":
                return path
            elif result["type"] in ["symbol", "string", "error"]:
                return path
            else:  # pointer to other (possibly pointer)
                seen_addresses.append(addr)
                addr = result["data"]
                if addr in seen_addresses:
                    return path
                depth += 1
        return path

    def get_dereference_str(self, addr: int, paddr: int = None) -> str:
        """
        Recursively dereference a pointer with a max depth.
        return a string with the dereference path starting from the address.
        addr -> *addr -> **addr -> ...
        value "ascii string"
        """

        line = ""

        path = self.get_dereference_path(addr)
        if (
            path[0]["type"] == "NaA"  # len(path) == 1
            and paddr is not None
            and is_ascii_cstring(
                path[0]["address"].to_bytes(self.arch().bytes, "little")
            )
        ):
            s = attempt_to_read_string_from_memory(self.process, paddr)
            line += f" {TERM_COLORS[self.color_settings.string_color].value}{repr(s)}{TERM_COLORS.ENDC.value}"
            return line

        for ptr in path:
            ptr_color = get_address_color(ptr["address"], self.section_list)
            line += Color.colorify(format_address(ptr["address"]), ptr_color)
            if ptr["type"] == "symbol":
                line += (
                    f" {GLYPHS.RIGHT_ARROW.value} {TERM_COLORS[self.color_settings.dereferenced_value_color].value}"
                    f"<{ptr['data']['symbol']}+{ptr['data']['offset']}>"
                    f"{self.generate_rebased_address_string(ptr['address'])}"
                    f"{TERM_COLORS.ENDC.value}"
                )
            elif ptr_color == "red":  # TODO: iscode, determined on dereference
                addr_obj = SBAddress(ptr["address"], self.target)
                if addr_obj.symbol.IsValid():
                    offset = addr_obj.offset - addr_obj.symbol.GetStartAddress().offset
                    line += (
                        f" {TERM_COLORS[self.color_settings.dereferenced_value_color].value}"
                        f"<{addr_obj.symbol.name}+{offset}>"
                        f"{TERM_COLORS.ENDC.value}"
                    )
                line += f"{self.generate_rebased_address_string(addr_obj)}"
                break
            elif ptr["type"] == "pointer":  # other pointers
                line += f" {GLYPHS.RIGHT_ARROW.value} "  # must not be last
            elif ptr["type"] == "string":  # after pointer to exclulde code
                line += (
                    f" {GLYPHS.RIGHT_ARROW.value} "
                    f"{TERM_COLORS[self.color_settings.string_color].value}"
                    f"{repr(ptr['data'])}"
                    f"{TERM_COLORS.ENDC.value}"
                )
            elif ptr["type"] == "error":
                line += " Error"
        # special case: addr value is part of an ascii string
        # not handling both pointer and ascii case

        return line

    def generate_printable_line_from_pointer(
        self, pointer: int, address_containing_pointer: Optional[int] = None
    ) -> str:
        """
        Generate a line from a memory address (@pointer) that contains relevant
        information about the address.
        This is intended to be used when printing stack and register values.
        """

        line = ""
        pointer_value = SBAddress(pointer, self.target)

        # TODO: show reference to valid section

        if pointer_value.symbol.IsValid():
            offset = (
                pointer_value.offset - pointer_value.symbol.GetStartAddress().offset
            )
            line += (
                f" {TERM_COLORS[self.color_settings.dereferenced_value_color].value}"
                f"<{pointer_value.symbol.name}+{offset}>"
                f"{TERM_COLORS.ENDC.value}"
                f"{self.generate_rebased_address_string(pointer_value)}"  # {GLYPHS.RIGHT_ARROW.value}"
            )

        referenced_string = attempt_to_read_string_from_memory(
            self.process, pointer_value.GetLoadAddress(self.target)
        )

        if len(referenced_string) > 0 and referenced_string.isprintable():
            # Only add this to the line if there are any printable characters in refd_string
            referenced_string = referenced_string.replace("\n", " ")
            line += (
                f' {GLYPHS.RIGHT_ARROW.value} ("'
                f"{TERM_COLORS[self.color_settings.string_color].value}"
                f"{referenced_string}"
                f'{TERM_COLORS.ENDC.value}"?)'
            )

        if address_containing_pointer is not None:
            registers_pointing_to_address = []
            for register in get_registers(self.frame, self.arch().gpr_key):
                if register.GetValueAsUnsigned() == address_containing_pointer:
                    registers_pointing_to_address.append(f"${register.GetName()}")
            if len(registers_pointing_to_address) > 0:
                reg_list = ", ".join(registers_pointing_to_address)
                line += (
                    f" {TERM_COLORS[self.color_settings.dereferenced_register_color].value}"
                    f"{GLYPHS.LEFT_ARROW.value}{reg_list}"
                    f"{TERM_COLORS.ENDC.value}"
                )

        return line

    def print_dereference_line(
        self, addr: int, offset: int, data: bytes = None
    ) -> None:
        """Produce a printable line containing information about a given stack @addr and print it"""
        # Add stack address to line
        n_digits = self.arch().bits // 4
        line = (
            f"{TERM_COLORS[self.color_settings.stack_address_color].value}0x{addr:0{n_digits}x}"
            f"{TERM_COLORS.ENDC.value}{GLYPHS.VERTICAL_LINE.value}"
            f"+{offset:04x}: "
        )

        if not data:
            err = SBError()
            data = self.process.ReadMemory(addr, self.arch().bytes, err)
            if err.Fail():
                line += str(err)
                output_line(line)
                return

        value = int.from_bytes(data, "little")
        line += self.get_dereference_str(value, addr)
        output_line(line)

    def print_dereference(self, start: int, count: int = None) -> None:
        err = SBError()
        count = count or settings.displayed_stack_depth
        mem = self.process.ReadMemory(start, count * self.arch().bytes, err)
        if err.Success():
            for i in range(count):
                offset = i * self.arch().bytes
                addr = start + offset
                self.print_dereference_line(
                    addr, offset, mem[offset : offset + self.arch().bytes]
                )
        else:
            print(str(err))

    def print_memory_address(self, addr: int, offset: int, size: int) -> None:
        """Print a line containing information about @size bytes at @addr displaying @offset"""
        # Add address to line
        line = (
            f"{TERM_COLORS[self.color_settings.read_memory_address_color].value}{hex(addr)}"
            + f"{TERM_COLORS.ENDC.value}{GLYPHS.VERTICAL_LINE.value}"
        )
        # Add offset to line
        line += f"+{offset:04x}: "

        # Add value to line
        err = SBError()
        memory_value = int.from_bytes(
            self.process.ReadMemory(addr, size, err), "little"
        )
        if err.Success():
            line += f"0x{memory_value:0{size * 2}x}"
        else:
            line += str(err)

        output_line(line)

    def print_bytes(self, addr: int, size: int) -> None:
        """Print a line containing information about @size individual bytes at @addr"""
        if size > 0:
            # Add address to line
            line = (
                f"{TERM_COLORS[self.color_settings.read_memory_address_color].value}{hex(addr)}"
                + f"{TERM_COLORS.ENDC.value}    "
            )

            # Add value to line
            err = SBError()
            memory_value: bytes = self.process.ReadMemory(addr, size, err)
            if err.Success():
                line += f"{memory_value.hex(' '):47}    "

                # Add characters to line
                characters = ""
                for byte in memory_value:
                    if chr(byte) in printable.strip():
                        characters += chr(byte)
                    else:
                        characters += "."

                line += characters
            else:
                line += str(err)

            output_line(line)

    def print_register(self, register: Union[SBValue, tuple]) -> None:
        """Print details of a @register"""
        if isinstance(register, SBValue):
            reg_name, reg_value = register.GetName(), register.GetValueAsUnsigned()
        else:
            reg_name, reg_value = register

        if self.state.prev_registers.get(reg_name) == reg_value:
            # Register value as not changed
            change_highlight = TERM_COLORS[self.color_settings.register_color]
        else:
            # Register value has changed so highlight
            change_highlight = TERM_COLORS[self.color_settings.modified_register_color]

        line = f"{change_highlight.value}{reg_name.ljust(7)}{TERM_COLORS.ENDC.value}: "

        # line += self.generate_printable_line_from_pointer(reg_value)
        line += self.get_dereference_str(reg_value)

        output_line(line)

    def print_flags_register(self, flag_register: Union[FlagRegister, tuple]) -> None:
        """Format and print the contents of the flag register."""
        if isinstance(flag_register, FlagRegister):
            flag_value = self.frame.register[flag_register.name].GetValueAsUnsigned()
            flag_name = flag_register.name
        else:
            flag_value, flag_name = flag_register

        if self.state.prev_registers.get(flag_name) == flag_value:
            # No change
            highlight = TERM_COLORS[self.color_settings.register_color]
        else:
            # Change and highlight
            highlight = TERM_COLORS[self.color_settings.modified_register_color]

        line = f"{highlight.value}{flag_name.ljust(7)}{TERM_COLORS.ENDC.value}: ["
        line += " ".join(
            [
                name.upper() if flag_value & bitmask else name
                for name, bitmask in flag_register.bit_masks.items()
            ]
        )
        line += "]"
        output_line(line)

    def update_registers(self, update_prev=False) -> None:
        """
        This updates current & previous registers, for change detection and current display.
        If there is no frame currently then the previous registers do not change
        """

        # LLDB api is slow, even after first call, so get the values once here and manipulate them.
        if update_prev:
            self.state.prev_registers = self.state.current_registers.copy()
        if self.frame is not None:
            # grp only by default for speed
            reg_sets = (
                [self.frame.registers[0]]
                if not self.settings.show_all_registers
                else self.frame.registers
            )
            for reg_set in reg_sets:
                for reg in reg_set:
                    self.state.current_registers[reg.GetName()] = (
                        reg.GetValueAsUnsigned()
                    )

    def print_legend(self) -> None:
        """Print a line containing the color legend"""

        output_line(
            f"[ Legend: "
            f"{TERM_COLORS[self.color_settings.modified_register_color].value}"
            f"Modified register{TERM_COLORS.ENDC.value} | "
            f"{TERM_COLORS[self.color_settings.code_color].value}Code{TERM_COLORS.ENDC.value} | "
            f"{TERM_COLORS[self.color_settings.heap_color].value}Heap{TERM_COLORS.ENDC.value} | "
            f"{TERM_COLORS[self.color_settings.stack_color].value}Stack{TERM_COLORS.ENDC.value} | "
            f"{TERM_COLORS[self.color_settings.string_color].value}String{TERM_COLORS.ENDC.value} ]"
        )

    def display_registers(self) -> None:
        """Print the registers display section"""

        print_line_with_string(
            "registers",
            line_color=TERM_COLORS[self.color_settings.line_color],
            string_color=TERM_COLORS[self.color_settings.section_header_color],
        )

        flag_ragisters = []
        # general purpose register
        for reg in self.state.current_registers.items():
            if reg[0] not in self.arch.flag_registers:
                self.print_register(reg)
            else:
                flag_ragisters.append(reg)

        # flag register
        for flag_reg in flag_ragisters:
            self.print_flags_register(flag_reg)

    def display_stack(self) -> None:
        """Print information about the contents of the top of the stack"""

        print_line_with_string(
            "stack",
            line_color=TERM_COLORS[self.color_settings.line_color],
            string_color=TERM_COLORS[self.color_settings.section_header_color],
        )
        sp = self.frame.GetSP()
        self.print_dereference(sp)

    def display_code(self) -> None:
        """
        Print the disassembly generated by LLDB.
        """
        print_line_with_string(
            "code",
            line_color=TERM_COLORS[self.color_settings.line_color],
            string_color=TERM_COLORS[self.color_settings.section_header_color],
        )

        if self.frame.disassembly:
            instructions = self.frame.disassembly.split("\n")

            current_pc = hex(self.frame.GetPC())
            for i, item in enumerate(instructions):
                if current_pc in item.split(":")[0]:
                    output_line(instructions[0])
                    if i > 3:
                        print_instruction(
                            instructions[i - 3],
                            TERM_COLORS[self.color_settings.instruction_color],
                        )
                        print_instruction(
                            instructions[i - 2],
                            TERM_COLORS[self.color_settings.instruction_color],
                        )
                        print_instruction(
                            instructions[i - 1],
                            TERM_COLORS[self.color_settings.instruction_color],
                        )
                        print_instruction(
                            item,
                            TERM_COLORS[
                                self.color_settings.highlighted_instruction_color
                            ],
                        )
                        # This slice notation (and the 4 below) are a buggy interaction of black and pycodestyle
                        # See: https://github.com/psf/black/issues/157
                        # fmt: off
                        for instruction in instructions[i + 1:i + 6]:  # noqa
                            # fmt: on
                            print_instruction(instruction)
                    if i == 3:
                        print_instruction(
                            instructions[i - 2],
                            TERM_COLORS[self.color_settings.instruction_color],
                        )
                        print_instruction(
                            instructions[i - 1],
                            TERM_COLORS[self.color_settings.instruction_color],
                        )
                        print_instruction(
                            item,
                            TERM_COLORS[
                                self.color_settings.highlighted_instruction_color
                            ],
                        )
                        # fmt: off
                        for instruction in instructions[i + 1:10]:  # noqa
                            # fmt: on
                            print_instruction(instruction)
                    if i == 2:
                        print_instruction(
                            instructions[i - 1],
                            TERM_COLORS[self.color_settings.instruction_color],
                        )
                        print_instruction(
                            item,
                            TERM_COLORS[
                                self.color_settings.highlighted_instruction_color
                            ],
                        )
                        # fmt: off
                        for instruction in instructions[i + 1:10]:  # noqa
                            # fmt: on
                            print_instruction(instruction)
                    if i == 1:
                        print_instruction(
                            item,
                            TERM_COLORS[
                                self.color_settings.highlighted_instruction_color
                            ],
                        )
                        # fmt: off
                        for instruction in instructions[i + 1:10]:  # noqa
                            # fmt: on
                            print_instruction(instruction)
        else:
            output_line("No disassembly to print")

    def display_threads(self) -> None:
        """Print LLDB formatted thread information"""
        print_line_with_string(
            "threads",
            line_color=TERM_COLORS[self.color_settings.line_color],
            string_color=TERM_COLORS[self.color_settings.section_header_color],
        )
        for thread in self.process:
            output_line(thread)

    def display_trace(self) -> None:
        """
        Prints the call stack including arguments if LLDB knows them.
        """
        print_line_with_string(
            "trace",
            line_color=TERM_COLORS[self.color_settings.line_color],
            string_color=TERM_COLORS[self.color_settings.section_header_color],
        )

        for i in range(self.thread.GetNumFrames()):
            if i == 0:
                number_color = TERM_COLORS[self.color_settings.highlighted_index_color]
            else:
                number_color = TERM_COLORS[self.color_settings.index_color]
            line = f"[{number_color.value}#{i}{TERM_COLORS.ENDC.value}] "

            current_frame = self.thread.GetFrameAtIndex(i)
            pc_address = current_frame.GetPCAddress()
            func = current_frame.GetFunction()
            trace_address = pc_address.GetLoadAddress(self.target)

            if func:
                line += (
                    f"{trace_address:#x}{self.generate_rebased_address_string(pc_address)}  {GLYPHS.RIGHT_ARROW.value} "
                    f"{TERM_COLORS[self.color_settings.function_name_color].value}"
                    f"{func.GetName()}{TERM_COLORS.ENDC.value}"
                )
            else:
                line += (
                    f"{trace_address:#x}{self.generate_rebased_address_string(pc_address)}  {GLYPHS.RIGHT_ARROW.value} "
                    f"{TERM_COLORS[self.color_settings.function_name_color].value}"
                    f"{current_frame.GetSymbol().GetName()}{TERM_COLORS.ENDC.value}"
                )

            line += get_frame_arguments(
                current_frame,
                frame_argument_name_color=TERM_COLORS[
                    self.color_settings.frame_argument_name_color
                ],
            )

            output_line(line)

    def display_all(self) -> None:
        # if self.settings.show_legend:
        #    self.print_legend()

        if self.settings.show_registers:
            self.display_registers()

        if self.settings.show_stack:
            self.display_stack()

        if self.settings.show_code:
            self.display_code()

        if self.settings.show_threads:
            self.display_threads()

        if self.settings.show_trace:
            self.display_trace()

    def refresh(self, exe_ctx: SBExecutionContext) -> None:
        """Refresh stored values"""
        self.frame = exe_ctx.GetFrame()
        self.process = exe_ctx.GetProcess()
        self.target = exe_ctx.GetTarget()
        self.thread = exe_ctx.GetThread()
        if self.settings.force_arch is not None:
            self.arch = get_arch_from_str(self.settings.force_arch)
        else:
            self.arch = get_arch(self.target)

        self.section_list.update(exe_ctx)

    def display_context(
        self,
        exe_ctx: SBExecutionContext,
        update_prev_also: bool = False,
        layout: list[str] = ["all"],
    ) -> None:
        """For up to date documentation on args provided to this function run: `help target stop-hook add`"""

        # Refresh frame, process, target, and thread objects at each stop.
        self.refresh(exe_ctx)

        # check if need update current
        if (
            "all" in layout
            or "registers" in layout
            or "stack" in layout
            or "code" in layout
        ):
            self.update_registers(update_prev=update_prev_also)

        # Hack to print cursor at the top of the screen
        clear_page()

        for entry in layout:
            if entry == "all":
                self.display_all()
            elif entry == "registers":
                self.display_registers()
            elif entry == "stack":
                self.display_stack()
            elif entry == "code":
                self.display_code()
            elif entry == "threads":
                self.display_threads()
            elif entry == "trace":
                self.display_trace()
            else:
                output_line(f"Error: Unknown entry: {entry}")

        print_line(color=TERM_COLORS[self.color_settings.line_color])

    @staticmethod
    def find_in_section(
        target: bytes,
        section: Section,
        exe_ctx: SBExecutionContext,
    ):
        err = SBError()
        mem: bytes = exe_ctx.process.ReadMemory(section.page_start, section.size, err)
        if err.Fail():
            print("find_in_section:", err.GetCString())
            return None
        offsets = []
        start = 0
        while start < len(mem):
            start = mem.find(target, start)
            if start == -1:
                break
            offsets.append(start)
            start += len(target)
        return offsets, mem


context_handler = ContextHandler(lldb.debugger)
