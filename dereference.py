from gef.memory import *


def dereference_from(address: int) -> List[str]:
    if not is_alive():
        return [
            format_address(address),
        ]

    code_color = gef.config["theme.dereference_code"]
    string_color = gef.config["theme.dereference_string"]
    max_recursion = gef.config["dereference.max_recursion"] or 10
    addr = lookup_address(align_address(address))
    msg = [
        format_address(addr.value),
    ]
    seen_addrs = set()

    while addr.section and max_recursion:
        if addr.value in seen_addrs:
            msg.append("[loop detected]")
            break
        seen_addrs.add(addr.value)

        max_recursion -= 1

        # Is this value a pointer or a value?
        # -- If it's a pointer, dereference
        deref = addr.dereference()
        if deref is None:
            # if here, dereferencing addr has triggered a MemoryError, no need to go further
            msg.append(str(addr))
            break

        new_addr = lookup_address(deref)
        if new_addr.valid:
            addr = new_addr
            msg.append(str(addr))
            continue

        # -- Otherwise try to parse the value
        if addr.section:
            if (
                addr.section.is_executable()
                and addr.is_in_text_segment()
                and not is_ascii_string(addr.value)
            ):
                insn = gef_current_instruction(addr.value)
                insn_str = f"{insn.location} {insn.mnemonic} {', '.join(insn.operands)}"
                msg.append(Color.colorify(insn_str, code_color))
                break

            elif addr.section.permission & Permission.READ:
                if is_ascii_string(addr.value):
                    s = gef.memory.read_cstring(addr.value)
                    if len(s) < gef.arch.ptrsize:
                        txt = f'{format_address(deref)} ("{Color.colorify(s, string_color)}"?)'
                    elif len(s) > 50:
                        txt = Color.colorify(f'"{s[:50]}[...]"', string_color)
                    else:
                        txt = Color.colorify(f'"{s}"', string_color)

                    msg.append(txt)
                    break

        # if not able to parse cleanly, simply display and break
        val = "{:#0{ma}x}".format(
            int(deref & 0xFFFFFFFFFFFFFFFF), ma=(gef.arch.ptrsize * 2 + 2)
        )
        msg.append(val)
        break

    return msg


class DereferenceCommand(GenericCommand):
    """Dereference recursively from an address and display information. This acts like WinDBG `dps`
    command."""

    _cmdline_ = "dereference"
    _syntax_ = f"{_cmdline_} [-h] [--length LENGTH] [--reference REFERENCE] [address]"
    _aliases_ = [
        "telescope",
    ]
    _example_ = f"{_cmdline_} --length 20 --reference $sp+0x10 $sp"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        self["max_recursion"] = (7, "Maximum level of pointer recursion")
        return

    @staticmethod
    def pprint_dereferenced(addr: int, idx: int, base_offset: int = 0) -> str:
        base_address_color = gef.config["theme.dereference_base_address"]
        registers_color = gef.config["theme.dereference_register_value"]

        sep = f" {RIGHT_ARROW} "
        memalign = gef.arch.ptrsize

        offset = idx * memalign
        current_address = align_address(addr + offset)
        addrs = dereference_from(current_address)
        l = ""
        addr_l = format_address(int(addrs[0], 16))
        l += "{}{}{:+#07x}: {:{ma}s}".format(
            Color.colorify(addr_l, base_address_color),
            VERTICAL_LINE,
            base_offset + offset,
            sep.join(addrs[1:]),
            ma=(memalign * 2 + 2),
        )

        register_hints = []

        for regname in gef.arch.all_registers:
            regvalue = gef.arch.register(regname)
            if current_address == regvalue:
                register_hints.append(regname)

        if register_hints:
            m = f"\t{LEFT_ARROW}{', '.join(list(register_hints))}"
            l += Color.colorify(m, registers_color)

        offset += memalign
        return l

    @only_if_gdb_running
    @parse_arguments(
        {"address": "$sp"}, {("-r", "--reference"): "", ("-l", "--length"): 10}
    )
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args: argparse.Namespace = kwargs["arguments"]
        nb = args.length

        target = args.address
        target_addr = parse_address(target)

        reference = args.reference or target
        ref_addr = parse_address(reference)

        if process_lookup_address(target_addr) is None:
            err(f"Unmapped address: '{target}'")
            return

        if process_lookup_address(ref_addr) is None:
            err(f"Unmapped address: '{reference}'")
            return

        if gef.config["context.grow_stack_down"] is True:
            insnum_step = -1
            if nb > 0:
                from_insnum = nb * (self.repeat_count + 1) - 1
                to_insnum = self.repeat_count * nb - 1
            else:
                from_insnum = self.repeat_count * nb
                to_insnum = nb * (self.repeat_count + 1)
        else:
            insnum_step = 1
            if nb > 0:
                from_insnum = self.repeat_count * nb
                to_insnum = nb * (self.repeat_count + 1)
            else:
                from_insnum = nb * (self.repeat_count + 1) + 1
                to_insnum = (self.repeat_count * nb) + 1

        start_address = align_address(target_addr)
        base_offset = start_address - align_address(ref_addr)

        for i in range(from_insnum, to_insnum, insnum_step):
            gef_print(
                DereferenceCommand.pprint_dereferenced(start_address, i, base_offset)
            )

        return
