# Please import those functions from common.util
from typing import Union
import settings
from gef.memory import Section, Permission, SectionList


def match_section(section: Section, filters: Union[list[dict], dict]) -> bool:
    def match_section_one_filter(section: Section, filter: dict) -> bool:
        matched = True
        if filter["keyword"]:
            if not filter["keyword"] in section.path:
                return False
        if filter["perm_mask"]:
            perm = Permission.from_process_maps(filter["perm_mask"])
            matched = (section.permission & perm) == perm
        return matched

    if isinstance(filters, dict):
        filters = [filters]
    for filter in filters:
        if match_section_one_filter(section, filter):
            return True
    return False


def match_setting_section_filters(section: Section) -> bool:
    return match_section(section, settings.section_filters)


# TODO: a class to manage settings
def get_setting_filters() -> list[dict]:
    """
    Read only access to the section_filters setting.
    """
    return settings.section_filters.copy()


def get_section_color(section: Section) -> str:
    """Get the color of the section."""
    for color, filters in settings.section_highlight.items():
        for filter in filters:
            if match_section(section, filter):
                return color
    return ""


def get_address_color(addr: int, section_list: SectionList) -> str:
    section = section_list.find_section(addr)
    if section:  # all objects are true by default
        return get_section_color(section)
    return ""


# def save_config():
# def load_config():
# g = list(settings.__dict__.keys())
# for k in g:
#    if not k.startswith("_"):
#        print(k)
