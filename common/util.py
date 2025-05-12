"""Utility functions."""

import os
from typing import List, Any, Union, Iterable
import re

from lldb import (
    SBError,
    SBFrame,
    SBMemoryRegionInfo,
    SBMemoryRegionInfoList,
    SBProcess,
    SBValue,
)

from common.constants import ALIGN, GLYPHS, MSG_TYPE, TERM_COLORS
from common.state import LLEFState
from gef.memory import SectionList, Section
from setting_utils import *


def change_use_color(new_value: bool) -> None:
    """
    Change the global use_color bool. use_color should not be written to directly
    """
    LLEFState.use_color = new_value


def output_line(line: Any) -> None:
    """
    Format a line of output for printing. Print should not be used elsewhere.
    Exception - clear_page would not function without terminal characters
    """
    line = str(line)
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    if LLEFState.use_color is False:
        line = ansi_escape.sub("", line)
    print(line)


def clear_page() -> None:
    """
    Used to clear the previously printed breakpoint information before
    printing the next information.
    """
    num_lines = os.get_terminal_size().lines
    for _ in range(num_lines):
        print()
    print("\033[0;0H")  # Ansi escape code: Set cursor to 0,0 position
    print("\033[J")  # Ansi escape code: Clear contents from cursor to end of screen


def print_line_with_string(
    string: str,
    char: GLYPHS = GLYPHS.HORIZONTAL_LINE,
    line_color: TERM_COLORS = TERM_COLORS.GREY,
    string_color: TERM_COLORS = TERM_COLORS.BLUE,
    align: ALIGN = ALIGN.RIGHT,
) -> None:
    """Print a line with the provided @string padded with @char"""
    width = os.get_terminal_size().columns
    if align == ALIGN.RIGHT:
        l_pad = (width - len(string) - 6) * char.value
        r_pad = 4 * char.value

    elif align == ALIGN.CENTRE:
        l_pad = (width - len(string)) * char.value
        r_pad = 4 * char.value

    elif align == ALIGN.LEFT:
        l_pad = 4 * char.value
        r_pad = (width - len(string) - 6) * char.value

    output_line(
        f"{line_color.value}{l_pad}{TERM_COLORS.ENDC.value} "
        + f"{string_color.value}{string}{TERM_COLORS.ENDC.value} {line_color.value}{r_pad}{TERM_COLORS.ENDC.value}"
    )


def print_line(
    char: GLYPHS = GLYPHS.HORIZONTAL_LINE, color: TERM_COLORS = TERM_COLORS.GREY
) -> None:
    """Print a line of @char"""
    output_line(
        f"{color.value}{os.get_terminal_size().columns*char.value}{TERM_COLORS.ENDC.value}"
    )


def print_message(msg_type: MSG_TYPE, message: str) -> None:
    """Format and print a @message"""
    info_color = TERM_COLORS.BLUE
    success_color = TERM_COLORS.GREEN
    error_color = TERM_COLORS.GREEN

    if msg_type == MSG_TYPE.INFO:
        output_line(f"{info_color.value}[+]{TERM_COLORS.ENDC.value} {message}")
    elif msg_type == MSG_TYPE.SUCCESS:
        output_line(f"{success_color.value}[+]{TERM_COLORS.ENDC.value} {message}")
    elif msg_type == MSG_TYPE.ERROR:
        output_line(f"{error_color.value}[+]{TERM_COLORS.ENDC.value} {message}")


def print_instruction(line: str, color: TERM_COLORS = TERM_COLORS.ENDC) -> None:
    """Format and print a line of disassembly returned from LLDB (SBFrame.disassembly)"""
    loc_0x = line.find("0x")
    start_idx = loc_0x if loc_0x >= 0 else 0
    output_line(f"{color.value}{line[start_idx:]}{TERM_COLORS.ENDC.value}")


def get_registers(frame: SBFrame, frame_type: str) -> List[SBValue]:
    """
    Returns the registers in @frame that are of the specified @type.
    A @type is a string defined in LLDB, e.g. "General Purpose"
    """
    registers = []
    for regs in frame.GetRegisters():
        if frame_type.lower() in regs.GetName().lower():
            registers = regs
    return registers


def get_frame_arguments(frame: SBFrame, frame_argument_name_color: TERM_COLORS) -> str:
    """
    Returns a string containing args of the supplied frame
    """
    # GetVariables(arguments, locals, statics, in_scope_only)
    variables = frame.GetVariables(True, False, False, True)
    args = []
    for var in variables:
        # get and format argument value
        value = "???"
        var_value = var.GetValue()
        if var_value is None:
            value = "null"
        elif var_value:
            try:
                value = f"{int(var.GetValue(), 0):#x}"
            except ValueError:
                pass
        args.append(
            f"{frame_argument_name_color.value}{var.GetName()}{TERM_COLORS.ENDC.value}={value}"
        )
    return f"({' '.join(args)})"


def attempt_to_read_string_from_memory(
    process: SBProcess, addr: int, buffer_size: int = 256
) -> str:
    """
    Returns a string from a memory address if one can be read, else an empty string
    """
    err = SBError()
    ret_string = ""
    try:
        string = process.ReadCStringFromMemory(addr, buffer_size, err)
        if err.Success():
            ret_string = string
    except SystemError:
        # This swallows an internal error that is sometimes generated by a bug in LLDB.
        # Ex: non-ascii bytes before string terminated
        pass
    return ret_string

    ## Read memory and self parse,
    # err = SBError()
    # print(f"{hex(addr)=}")
    # memory = process.ReadMemory(addr, buffer_size, err)
    # if err.Fail():  # should not happen
    #    return "! Error reading memory"
    #
    # if is_ascii_cstring(memory):
    #    return memory.split(b"\x00", 1)[0].decode("ascii")
    # return ""


# def get_segment_type(address: int, sections: SectionList) -> Union[str, None]:
#    section = sections.find_section(address)
#    if not section:
#        return None
#    elif section.is_executable():
#        return "code"
#    elif section.path == "[stack]":
#        return "stack"
#    elif section.path == "[heap]":
#        return "heap"
#    else:
#        return "other"


def parse_number(num_str: str) -> int:
    try:
        num = int(num_str)
    except ValueError:
        num = int(num_str, 16)
    return num


def is_code(address: int, sections: SectionList) -> bool:
    """Determines whether an @address points to code"""
    section = sections.find_section(address)
    return section.is_executable() if section else False


def is_stack(address: int, sections: SectionList) -> bool:
    """Determines whether an @address points to the stack"""
    section = sections.find_section(address)
    return section.path == "[stack]" if section else False


def is_heap(address: int, sections: SectionList) -> bool:
    """Determines whether an @address points to the heap"""
    section = sections.find_section(address)
    return section.path == "[heap]" if section else False


def extract_arch_from_triple(triple: str) -> str:
    """Extracts the architecture from triple string."""
    return triple.split("-")[0]


def is_ascii_cstring(s: Iterable, min_length=1) -> bool:

    for i, b in enumerate(s):
        if b >= 128 or (b == 0 and i < min_length):
            return False
        if i >= min_length:  # only passed 4 bytes address, probably not null terminated
            return True
