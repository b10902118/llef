displayed_thread_idx: int = 1
displayed_stack_depth: int = 5
# settings.show_stack
context_layout: list[str] = ["reg", "stack", "code", "trace"]

section_highlight: dict[str, list[dict[str, str]]] = {
    "pink": [{"keyword": "stack", "perm_mask": None}],
    "green": [
        {"keyword": "heap", "perm_mask": "rw-"},
        {"keyword": "alloc", "perm_mask": "rw-"},
    ],
    "red": [{"keyword": None, "perm_mask": "r-x"}],
}

section_filters: list[dict[str, str]] = [
    {"keyword": "libg.so", "perm_mask": None},
    {"keyword": "libc_malloc", "perm_mask": None},
]

dereference_max_depth = 5

# TODO use globals excluding __ as a serializable dictionary
