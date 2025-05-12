class Color:
    """Used to colorify terminal output."""

    colors = {
        "normal": "\033[0m",
        "gray": "\033[1;38;5;240m",
        "light_gray": "\033[0;37m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "pink": "\033[35m",
        "cyan": "\033[36m",
        "bold": "\033[1m",
        "underline": "\033[4m",
        "underline_off": "\033[24m",
        "highlight": "\033[3m",
        "highlight_off": "\033[23m",
        "blink": "\033[5m",
        "blink_off": "\033[25m",
    }

    @staticmethod
    def colorify(text: str, attrs: str) -> str:
        """Color text according to the given attributes."""
        # if gef.config["gef.disable_color"] is True:
        #    return text

        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(str(text))
        if colors["highlight"] in msg:
            msg.append(colors["highlight_off"])
        if colors["underline"] in msg:
            msg.append(colors["underline_off"])
        if colors["blink"] in msg:
            msg.append(colors["blink_off"])
        msg.append(colors["normal"])
        return "".join(msg)


def colorify(text: str, attrs: str) -> str:
    """Color text according to the given attributes."""
    # if gef.config["gef.disable_color"] is True:
    #    return text

    colors = Color.colors
    msg = [colors[attr] for attr in attrs.split() if attr in colors]
    msg.append(str(text))
    if colors["highlight"] in msg:
        msg.append(colors["highlight_off"])
    if colors["underline"] in msg:
        msg.append(colors["underline_off"])
    if colors["blink"] in msg:
        msg.append(colors["blink_off"])
    msg.append(colors["normal"])
    return "".join(msg)
