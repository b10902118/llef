import argparse
import shlex
from typing import Any, Dict

import lldb
from lldb import SBCommandReturnObject, SBDebugger, SBExecutionContext

from commands.base_command import BaseCommand
from common.context_handler import context_handler
from common.util import parse_number

from gef.color import Color
from gef.memory import *

from setting_utils import get_section_color, match_setting_section_filters


class VmmapCommand(BaseCommand):
    """Implements the vmmap"""

    program: str = "vmmap"
    container = None

    def __init__(self, debugger: SBDebugger, __: Dict[Any, Any]) -> None:
        super().__init__()
        self.parser = self.get_command_parser()

    @classmethod
    def get_command_parser(cls) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="vmmap command")
        parser.add_argument(
            "target",
            type=str,
            nargs="?",
            help="Name (path, anno) of the section or Address in hex or int",
        )
        return parser

    @staticmethod
    def get_short_help() -> str:
        return "Display memory mapping"

    @staticmethod
    def get_long_help() -> str:
        return """
        Display memory mapping
        """

    @staticmethod
    def print_section(section: Section) -> None:
        line_color = get_section_color(section)

        l = [
            Color.colorify(format_address(section.page_start), line_color),
            Color.colorify(format_address(section.page_end), line_color),
            Color.colorify(format_address(section.offset), line_color),
        ]
        if section.permission == Permission.ALL:
            l.append(Color.colorify(str(section.permission), "underline " + line_color))
        else:
            l.append(Color.colorify(str(section.permission), line_color))

        l.append(Color.colorify(section.path, line_color))
        line = " ".join(l)

        print(line)
        return

    def __call__(
        self,
        debugger: SBDebugger,
        command: str,
        exe_ctx: SBExecutionContext,
        result: SBCommandReturnObject,
    ) -> None:
        """Display memory mapping"""
        args = self.parser.parse_args(shlex.split(command))

        addr: int = None
        name: str = ""

        if args.target and args.target != "all":
            try:
                addr = parse_number(args.target)
            except ValueError:
                name = args.target

        context_handler.section_list.update(exe_ctx)

        for section in context_handler.section_list:
            if args.target == "all":
                self.print_section(section)
            elif addr:
                if section.page_start <= addr < section.page_end:
                    self.print_section(section)
            elif name:
                if name in section.path:
                    self.print_section(section)
            else:
                if match_setting_section_filters(section):
                    self.print_section(section)
