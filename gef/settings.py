# fmt: off
from typing import (Any, ByteString, Callable, Generator, Iterable, Iterator,
                    NoReturn, Sequence, Type, TypeVar, cast)
import pathlib
# fmt: on
class GefSetting:
    """Basic class for storing gef settings as objects"""

    def __init__(
        self,
        value: Any,
        cls: type | None = None,
        description: str | None = None,
        hooks: dict[str, list[Callable]] | None = None,
    ) -> None:
        self.value = value
        self.type = cls or type(value)
        self.description = description or ""
        self.hooks: dict[str, list[Callable]] = collections.defaultdict(list)
        if not hooks:
            hooks = {"on_read": [], "on_write": [], "on_changed": []}

        for access, funcs in hooks.items():
            self.add_hook(access, funcs)
        return

    def __str__(self) -> str:
        return (
            f"Setting(type={self.type.__name__}, value='{self.value}', desc='{self.description[:10]}...', "
            f"read_hooks={len(self.hooks['on_read'])}, write_hooks={len(self.hooks['on_write'])}, "
            f"changed_hooks={len(self.hooks['on_changed'])})"
        )

    def add_hook(self, access: str, funcs: list[Callable]):
        if access not in ("on_read", "on_write", "on_changed"):
            raise ValueError("invalid access type")
        for func in funcs:
            if not callable(func):
                raise ValueError("hook is not callable")
            self.hooks[access].append(func)
        return self

    @staticmethod
    def no_spaces(value: pathlib.Path):
        if " " in str(value):
            raise ValidationError("setting cannot contain spaces")

    @staticmethod
    def must_exist(value: pathlib.Path):
        if not value or not pathlib.Path(value).expanduser().absolute().exists():
            raise ValidationError("specified path must exist")

    @staticmethod
    def create_folder_tree(value: pathlib.Path):
        value.mkdir(0o755, exist_ok=True, parents=True)


class GefSettingsManager(dict):
    """
    GefSettings acts as a dict where the global settings are stored and can be read, written or deleted as any other dict.
    For instance, to read a specific command setting: `gef.config[mycommand.mysetting]`
    """

    def __getitem__(self, name: str) -> Any:
        setting: GefSetting = super().__getitem__(name)
        self.__invoke_read_hooks(setting)
        return setting.value

    def __setitem__(self, name: str, value: Any) -> None:
        # check if the key exists
        if super().__contains__(name):
            # if so, update its value directly
            setting = super().__getitem__(name)
            if not isinstance(setting, GefSetting):
                raise TypeError
            new_value = setting.type(value)
            dbg(
                f'in __invoke_changed_hooks("{name}"), setting.value={setting.value} -> new_value={new_value}, changing={bool(setting.value != new_value)}'
            )
            self.__invoke_changed_hooks(setting, new_value)
            self.__invoke_write_hooks(setting, new_value)
            setting.value = new_value
            return

        # if not, assert `value` is a GefSetting, then insert it
        if not isinstance(value, GefSetting):
            raise TypeError("Invalid argument")
        if not value.type:
            raise TypeError("Invalid type")
        if not value.description:
            raise AttributeError("Invalid description")
        setting = value
        value = setting.value
        self.__invoke_write_hooks(setting, value)
        super().__setitem__(name, setting)
        return

    def __delitem__(self, name: str) -> None:
        return super().__delitem__(name)

    def raw_entry(self, name: str) -> GefSetting:
        return super().__getitem__(name)

    def __invoke_read_hooks(self, setting: GefSetting) -> None:
        for callback in setting.hooks["on_read"]:
            callback()
        return

    def __invoke_changed_hooks(self, setting: GefSetting, new_value: Any) -> None:
        old_value = setting.value
        if old_value == new_value:
            return
        for callback in setting.hooks["on_changed"]:
            callback(old_value, new_value)

    def __invoke_write_hooks(self, setting: GefSetting, new_value: Any) -> None:
        for callback in setting.hooks["on_write"]:
            callback(new_value)
