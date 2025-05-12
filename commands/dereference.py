import argparse
import shlex
from typing import Any, Dict

import lldb
from lldb import SBCommandReturnObject, SBDebugger, SBExecutionContext
from lldb import (
    SBDebugger,
    SBExecutionContext,
)

from commands.base_command import BaseCommand
from common.context_handler import context_handler
from common.util import output_line
from common.util import clear_page

from gef.color import Color
from gef.memory import *


class DereferenceCommand(BaseCommand):
    """Implements the dereference (telescope)"""

    program: str = "dereference"
    container = None

    def __init__(self, debugger: SBDebugger, __: Dict[Any, Any]) -> None:
        super().__init__()
        self.parser = self.get_command_parser()

    @classmethod
    def get_command_parser(cls) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="dereference recursively from an address"
        )
        parser.add_argument("target", type=str, help="address to dereference")
        parser.add_argument(
            "-c", "--count", type=int, help="number of addresses to dereference"
        )

        return parser

    @staticmethod
    def get_short_help() -> str:
        return "dereference recursively from an address"

    @staticmethod
    def get_long_help() -> str:
        return "dereference recursively from an address"

    def __call__(
        self,
        debugger: SBDebugger,
        command: str,
        exe_ctx: SBExecutionContext,
        result: SBCommandReturnObject,
    ) -> None:
        """Display memory mapping"""
        args = self.parser.parse_args(shlex.split(command))

        addr: int
        if args.target:
            try:
                addr = int(args.target, 16)
            except ValueError:  # assume it is base 10
                try:
                    addr = int(args.target)
                except ValueError:
                    output_line("Invalid address")
                    return
        context_handler.refresh(exe_ctx)
        context_handler.print_dereference(addr, args.count)
