import argparse
import shlex
from typing import Any, Dict

import lldb
from lldb import SBCommandReturnObject, SBDebugger, SBExecutionContext
from lldb import SBDebugger, SBExecutionContext, SBError

from commands.base_command import BaseCommand
from common.context_handler import context_handler
from common.util import parse_number, get_setting_filters, match_section

from gef.color import Color, colorify
from gef.memory import *


class FindCommand(BaseCommand):
    program: str = "find"
    container = None
    description = "find a value in specific memory regions"

    def __init__(self, debugger: SBDebugger, __: Dict[Any, Any]) -> None:
        super().__init__()
        self.parser = self.get_command_parser()
        self.prev_results = []

    @classmethod
    def get_command_parser(cls) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description=cls.description)
        parser.add_argument("-v", "--value", type=str, help="numeric value to find")
        parser.add_argument("-s", "--string", type=str, help="string to find")
        parser.add_argument(
            "-l", "--length", type=int, help="length with leading 0 padding"
        )
        parser.add_argument(
            "-n", "--name", type=str, help="name of the section to search"
        )
        parser.add_argument(
            "-p",
            "--prev",
            type=int,
            nargs="?",
            const=0,
            default=None,
            help="find at n-th previous result addresses",
        )

        return parser

    @staticmethod
    def get_short_help() -> str:
        return FindCommand.description

    @staticmethod
    def get_long_help() -> str:
        return FindCommand.description

    def __call__(
        self,
        debugger: SBDebugger,
        command: str,
        exe_ctx: SBExecutionContext,
        result: SBCommandReturnObject,
    ) -> None:
        args = self.parser.parse_args(shlex.split(command))

        context_handler.section_list.update(exe_ctx)

        target: bytes
        if args.value:
            value = parse_number(args.value)
            length = args.length if args.length else (value.bit_length() + 7) // 8
            target = value.to_bytes(length, byteorder="little")
        elif args.string:
            target = args.string.encode() + b"\x00"

        section_name = args.name

        print(f"searching {target}")

        results = []
        if args.prev is not None:
            addrs = self.prev_results[args.prev]
            where = f"{len(addrs)} previous addresses"
            if not addrs:
                print(colorify("Warning: No previous found address", "yellow"))
            err = SBError()
            for addr in addrs:
                mem: bytes = exe_ctx.process.ReadMemory(addr, length, err)
                if mem == target:
                    print(f"{hex(addr)}:")
                    context_handler.print_dereference(addr - (addr % 4))
                    print()
                    results.append(addr)
        else:
            section_cnt = 0
            section_filter = (
                {"keyword": section_name, "perm_mask": None}
                if section_name
                else get_setting_filters()
            )
            for section in context_handler.section_list:
                if match_section(section, section_filter):
                    section_cnt += 1
                    # print(section.path, hex(section.page_start), hex(section.page_end))
                    offsets, mem = context_handler.find_in_section(
                        target, section, exe_ctx
                    )
                    for offset in offsets:
                        addr = section.page_start + offset
                        print(f"{hex(addr)} ({section.path}+{hex(offset)}):")
                        # context_handler.print_dereference(addr - (addr % 4))
                        # print()
                        results.append(addr)
            where = f"{section_cnt} sections"
        print(f"found {len(results)} results for {target} in", where)
        if results:
            print(
                f"Use `find -p {len(self.prev_results)}` to search in previous results"
            )
            self.prev_results.append(results)
