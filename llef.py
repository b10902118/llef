#!/usr/bin/env python3
"""LLEF main handler."""

# ---------------------------------------------------------------------
# To use this in the embedded python interpreter using "lldb" just
# import it with the full path using the "command script import"
# command``
#   (lldb) command script import /path/to/cmdtemplate.py
#
# The __lldb_init_module function automatically loads the stop-hook-handler
# ---------------------------------------------------------------------

from typing import Any, Dict, List, Type, Union

from lldb import SBDebugger

from commands.base_command import BaseCommand
from commands.base_container import BaseContainer
from commands.pattern import (
    PatternContainer,
    PatternCreateCommand,
    PatternSearchCommand,
)
from commands.context import ContextCommand
from commands.settings import SettingsCommand
from commands.color_settings import ColorSettingsCommand
from commands.hexdump import HexdumpCommand
from commands.vmmap import VmmapCommand
from commands.clear import ClearCommand
from commands.dereference import DereferenceCommand
from commands.find import FindCommand
from handlers.stop_hook import StopHookHandler


def __lldb_init_module(debugger: SBDebugger, _: Dict[Any, Any]) -> None:
    commands: List[Union[Type[BaseCommand], Type[BaseContainer]]] = [
        PatternContainer,
        PatternCreateCommand,
        PatternSearchCommand,
        ContextCommand,
        SettingsCommand,
        ColorSettingsCommand,
        HexdumpCommand,
        VmmapCommand,
        ClearCommand,
        DereferenceCommand,
        FindCommand,
    ]

    handlers = [StopHookHandler]

    for command in commands:
        command.lldb_self_register(debugger, "llef")

    for handler in handlers:
        handler.lldb_self_register(debugger, "llef")
