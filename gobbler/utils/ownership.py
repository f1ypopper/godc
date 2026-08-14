APP_PREFIXES = ("main.", "ConvertyFile/")

LIBRARY_PREFIXES = (
    "github.com/StackExchange/wmi",
    "github.com/armon/go-socks5",
    "github.com/bodgit/sevenzip",
    "github.com/ecies/go",
    "github.com/go-ole/",
    "github.com/kbinani/screenshot",
    "github.com/lxn/",
    "github.com/op/",
    "github.com/pkg/errors",
    "github.com/spf13/",
    "github.com/therecipe/qt",
    "github.com/tidwall/gjson",
    "github.com/wailsapp/",
    "github.com/whiterabb17/medusa/antivm",
    "github.com/whiterabb17/medusa/utils",
    "golang.org/x/",
    "gopkg.in/",
    "internal/",
    "slices.",
    "syscall.",
    "runtime.",
    "reflect.",
    "sync.",
    "os.",
    "io.",
    "fmt.",
    "log.",
    "net/",
    "net.",
    "encoding/",
    "compress/",
    "crypto/",
    "path/",
    "strings.",
    "strconv.",
)


def is_library_function(function: str) -> bool:
    return function.startswith(LIBRARY_PREFIXES)


def is_app_function(function: str) -> bool:
    if function.startswith(APP_PREFIXES):
        return True
    return bool(function) and not is_library_function(function)
