#!/bin/sh

set -eu

usage() {
    cat <<'EOF'
Usage: ./install.sh [OPTIONS]

Install this psmore binary package without modifying shell startup files.

Options:
  --prefix DIR          Install prefix (default: $PSMORE_PREFIX or ~/.local)
  --no-completions      Do not install bash, zsh, or fish completion files
  --dry-run             Print planned changes without writing files
  --uninstall           Remove psmore files from the selected prefix
  -h, --help            Show this help

The installer never removes psmore UI state or diagnostic reports.
EOF
}

fail() {
    printf 'psmore install: %s\n' "$*" >&2
    exit 1
}

home_dir=${HOME:-}
if [ -n "${PSMORE_PREFIX:-}" ]; then
    prefix=$PSMORE_PREFIX
elif [ -n "$home_dir" ]; then
    prefix="$home_dir/.local"
else
    fail 'HOME is unset; pass --prefix with an absolute path'
fi

install_completions=true
dry_run=false
uninstall=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)
            [ "$#" -ge 2 ] || fail '--prefix requires a value'
            prefix=$2
            shift 2
            ;;
        --no-completions)
            install_completions=false
            shift
            ;;
        --dry-run)
            dry_run=true
            shift
            ;;
        --uninstall)
            uninstall=true
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

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
package_dir=$script_dir

if [ "$uninstall" = true ]; then
    helper="$prefix/share/psmore/uninstall.sh"
    [ -x "$helper" ] || fail "installed uninstaller not found: $helper"
    if [ "$dry_run" = true ]; then
        exec "$helper" --prefix "$prefix" --dry-run
    fi
    exec "$helper" --prefix "$prefix"
fi

for required in \
    "$package_dir/bin/psmore" \
    "$package_dir/share/man/man1/psmore.1" \
    "$package_dir/VERSION" \
    "$package_dir/BUILD-INFO" \
    "$package_dir/uninstall.sh"
do
    [ -f "$required" ] || fail "incomplete package; missing $required"
done

if [ "$install_completions" = true ]; then
    for required in \
        "$package_dir/share/bash-completion/completions/psmore" \
        "$package_dir/share/zsh/site-functions/_psmore" \
        "$package_dir/share/fish/vendor_completions.d/psmore.fish"
    do
        [ -f "$required" ] || fail "incomplete package; missing $required"
    done
fi

current_tmp=''
cleanup() {
    if [ -n "$current_tmp" ]; then
        rm -f -- "$current_tmp"
    fi
}
trap cleanup 0 1 2 15

ensure_dir() {
    directory=$1
    if [ "$dry_run" = true ]; then
        printf 'mkdir  %s\n' "$directory"
    else
        install -d -m 0755 "$directory"
    fi
}

install_file() {
    source_file=$1
    destination=$2
    mode=$3
    ensure_dir "$(dirname -- "$destination")"
    printf 'install %s\n' "$destination"
    if [ "$dry_run" = false ]; then
        current_tmp="$destination.psmore-install.$$"
        rm -f -- "$current_tmp"
        install -m "$mode" "$source_file" "$current_tmp"
        mv -f -- "$current_tmp" "$destination"
        current_tmp=''
    fi
}

install_file "$package_dir/bin/psmore" "$prefix/bin/psmore" 0755
install_file "$package_dir/share/man/man1/psmore.1" "$prefix/share/man/man1/psmore.1" 0644
install_file "$package_dir/uninstall.sh" "$prefix/share/psmore/uninstall.sh" 0755
install_file "$package_dir/VERSION" "$prefix/share/psmore/VERSION" 0644
install_file "$package_dir/BUILD-INFO" "$prefix/share/psmore/BUILD-INFO" 0644

if [ "$install_completions" = true ]; then
    install_file "$package_dir/share/bash-completion/completions/psmore" \
        "$prefix/share/bash-completion/completions/psmore" 0644
    install_file "$package_dir/share/zsh/site-functions/_psmore" \
        "$prefix/share/zsh/site-functions/_psmore" 0644
    install_file "$package_dir/share/fish/vendor_completions.d/psmore.fish" \
        "$prefix/share/fish/vendor_completions.d/psmore.fish" 0644
fi

if [ "$dry_run" = true ]; then
    printf 'Dry run only; no files changed.\n'
    exit 0
fi

expected_version=$(sed -n '1p' "$package_dir/VERSION")
actual_version=$($prefix/bin/psmore --version) || fail 'installed binary did not start'
[ "$actual_version" = "psmore $expected_version" ] || fail "installed version mismatch: $actual_version"

printf 'Installed psmore %s in %s\n' "$expected_version" "$prefix"
case ":${PATH:-}:" in
    *:"$prefix/bin":*) ;;
    *) printf 'Add %s/bin to PATH to run psmore by name.\n' "$prefix" ;;
esac
printf 'Uninstall with %s/share/psmore/uninstall.sh\n' "$prefix"
