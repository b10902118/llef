# from gef.arch import Architecture, GenericArchitecture
from gef.settings import GefSettingsManager


class Gef:
    """The GEF root class for global variables."""

    # arch: Architecture
    # config: GefSettingsManager

    def __init__(self) -> None:
        # self.arch: Architecture = (
        #    GenericArchitecture()
        # )  # see PR #516, will be reset by `new_objfile_handler`
        self.config = GefSettingsManager()


gef = Gef()
