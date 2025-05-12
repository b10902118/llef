import sys
import pathlib

tty = "/dev/pts/6"
clean_sequence = "\x1b[H\x1b[J"
if tty:
    pathlib.Path(tty).write_text(clean_sequence)
else:
    sys.stdout.write(clean_sequence)
