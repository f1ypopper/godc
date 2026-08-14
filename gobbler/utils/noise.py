RUNTIME_NOISE_PREFIXES = (
    "runtime.gcwritebarrier",
    "runtime.writebarrier",
    "runtime.morestack",
    "runtime.duff",
    "runtime.memclr",
    "runtime.panic",
    "runtime.gopanic",
    "runtime.typeassert",
    "runtime.print",
    "runtime.deferreturn",
    "runtime.wbmove",
)


def is_runtime_noise_call(target: str) -> bool:
    lowered = target.lower()
    return lowered.startswith(RUNTIME_NOISE_PREFIXES)
