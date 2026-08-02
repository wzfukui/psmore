#!/bin/sh

set -eu

usage() {
    cat <<'EOF'
Usage: uninstall.sh [--prefix DIR] [--dry-run]

Remove only files installed by the psmore binary package. User preferences,
diagnostic reports, and unrelated files under the prefix are preserved.
EOF
}

fail() {
    printf 'psmore uninstall: %s\n' "$*" >&2
    exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
case "$script_dir" in
    */share/psmore) prefix=$(CDPATH= cd -- "$script_dir/../.." && pwd -P) ;;
    *)
        if [ -n "${PSMORE_PREFIX:-}" ]; then
            prefix=$PSMORE_PREFIX
        elif [ -n "${HOME:-}" ]; then
            prefix="$HOME/.local"
        else
            fail 'cannot infer prefix; pass --prefix with an absolute path'
        fi
        ;;
esac
dry_run=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)
            [ "$#" -ge 2 ] || fail '--prefix requires a value'
            prefix=$2
            shift 2
            ;;
        --dry-run)
            dry_run=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

case "$prefix" in
    /*) ;;
    *) fail "prefix must be an absolute path: $prefix" ;;
esac
case "/$prefix/" in
    */../*|*/./*) fail "prefix must not contain . or .. path components: $prefix" ;;
esac
while [ "$prefix" != / ] && [ "${prefix%/}" != "$prefix" ]; do
    prefix=${prefix%/}
done

remove_file() {
    target=$1
    if [ "$dry_run" = true ]; then
        printf 'remove %s\n' "$target"
    elif [ -e "$target" ] || [ -L "$target" ]; then
        rm -f -- "$target"
        printf 'removed %s\n' "$target"
    fi
}

remove_file "$prefix/bin/psmore"
remove_file "$prefix/share/man/man1/psmore.1"
remove_file "$prefix/share/bash-completion/completions/psmore"
remove_file "$prefix/share/zsh/site-functions/_psmore"
remove_file "$prefix/share/fish/vendor_completions.d/psmore.fish"
remove_file "$prefix/share/psmore/VERSION"
remove_file "$prefix/share/psmore/BUILD-INFO"
remove_file "$prefix/share/psmore/uninstall.sh"

if [ "$dry_run" = false ]; then
    for directory in \
        "$prefix/share/psmore" \
        "$prefix/share/bash-completion/completions" \
        "$prefix/share/zsh/site-functions" \
        "$prefix/share/fish/vendor_completions.d" \
        "$prefix/share/man/man1" \
        "$prefix/bin"
    do
        rmdir "$directory" 2>/dev/null || true
    done
    printf 'psmore package files removed; user configuration was preserved.\n'
else
    printf 'Dry run only; no files changed.\n'
fi
