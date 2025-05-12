import lldb
from lldb import (
    SBDebugger,
    SBExecutionContext,
    SBStream,
    SBStructuredData,
    SBTarget,
    SBCommandReturnObject,
)
import settings


class StopHookHandler:

    @classmethod
    def lldb_self_register(cls, debugger: SBDebugger, module_name: str) -> None:
        """Register the Stop Hook Handler"""

        command = f"target stop-hook add -P {module_name}.{cls.__name__}"
        debugger.HandleCommand(command)

    def __init__(self, target, _, __):
        pass

    def handle_stop(self, exe_ctx: SBExecutionContext, stream: SBStream):
        tid = exe_ctx.thread.idx
        if tid == settings.displayed_thread_idx:
            lldb.debugger.HandleCommand(f"context -t {tid} --update")
