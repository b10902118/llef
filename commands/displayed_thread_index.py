import settings


# TODO: Make command
def default_displayed_thread(
    debugger,
    command: str,
    exe_ctx,
    result,
    internal_dict,
):
    args = command.strip().split()
    if len(args) == 0:
        print(f"Default displayed thread: {settings.displayed_thread_idx}")
    elif len(args) != 1 or not args[0].isdigit():
        result.SetError("Invalid argument. Expected a single numeric argument.")
        return
    else:
        settings.displayed_thread_idx = int(args[0])
