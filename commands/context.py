"""Context command class."""

import argparse
import shlex
from typing import Any, Dict

from lldb import SBCommandReturnObject, SBDebugger, SBExecutionContext
from lldb import (
    SBDebugger,
    SBExecutionContext,
)

from commands.base_command import BaseCommand
from common.context_handler import context_handler
from common.util import output_line
import lldb
from common.util import clear_page
import settings
import time

possible_entries = ["all", "registers", "stack", "code", "threads", "trace"]


class ContextCommand(BaseCommand):
    """Implements the context"""

    program: str = "context"
    container = None

    def __init__(self, debugger: SBDebugger, __: Dict[Any, Any]) -> None:
        super().__init__()
        self.parser = self.get_command_parser()

    @classmethod
    def get_command_parser(cls) -> argparse.ArgumentParser:
        """Get the command parser."""
        parser = argparse.ArgumentParser(description="context command")
        parser.add_argument(
            "-t",
            "--thread",
            type=int,
            default=settings.displayed_thread_idx,
            help="Specify the thread to display (default is 1)",
        )
        parser.add_argument(
            "-u",
            "--update",
            action="store_true",
            default=False,
            help="Update the context registers",
        )
        parser.add_argument(
            "layout",
            nargs="*",
            default=settings.context_layout,
            help="Specify layout entries: registers, stack, code, threads, trace, all",
        )

        return parser

    @staticmethod
    def get_short_help() -> str:
        return "Usage: context [-t thread index] [--update] [entries...]"

    @staticmethod
    def get_long_help() -> str:
        return "Print the execution context"

    @staticmethod
    def _complete_entries(entries) -> list[str]:
        layout = []
        for entry in entries:
            for possible_entry in possible_entries:
                if possible_entry.startswith(entry):
                    layout.append(possible_entry)
                    break
        return layout

    def __call__(
        self,
        debugger: SBDebugger,
        command: str,
        exe_ctx: SBExecutionContext,
        result: SBCommandReturnObject,
    ) -> None:
        """Handles the invocation of 'context' command"""

        # bottleneck: refresh (read /proc/pid/maps & reg SBValues)
        # print(f"{exe_ctx.thread.idx=}") # always 1
        # TODO: accept thread idx as argument, default 1 (different from hook's target thread idx)
        if not exe_ctx.frame:
            output_line("Program not running")
            return

        args = self.parser.parse_args(shlex.split(command))

        # allow specifying prefix only
        layout = self._complete_entries(args.layout)

        context_handler.display_context(exe_ctx, args.update, layout)
