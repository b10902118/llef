"""Base arch abstract class definition."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class FlagRegister:
    """FlagRegister dataclass to store register name / bitmask associations"""

    name: str
    bit_masks: Dict[str, int]


class BaseArch(ABC):
    """BaseArch abstract class definition."""

    bits: int

    # TODO: fix arch().bytes, caused by @property require instance
    @property
    def bytes(self) -> int:
        return self.bits // 8

    @property
    @abstractmethod
    def gpr_registers(self) -> List[str]:
        """GPR register property"""

    @property
    @abstractmethod
    def gpr_key(self) -> str:
        """GPR key property"""

    @property
    @abstractmethod
    def flag_registers(self) -> List[FlagRegister]:
        """List of flag registers with associated bit masks"""
