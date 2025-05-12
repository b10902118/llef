from typing import Any, Dict

from lldb import SBCommandReturnObject, SBDebugger, SBExecutionContext
from lldb import (
    SBDebugger,
    SBExecutionContext,
)

from commands.base_command import BaseCommand
from common.util import clear_page


class ClearCommand(BaseCommand):
    """Implements the vmmap"""

    program: str = "clear"
    container = None

    def __init__(self, debugger: SBDebugger, __: Dict[Any, Any]) -> None:
        super().__init__()

    @staticmethod
    def get_short_help() -> str:
        return "clear screen"

    @staticmethod
    def get_long_help() -> str:
        return "clear screen"

    def __call__(
        self,
        debugger: SBDebugger,
        command: str,
        exe_ctx: SBExecutionContext,
        result: SBCommandReturnObject,
    ) -> None:
        clear_page()
        return
