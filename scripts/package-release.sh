#!/bin/sh

set -eu
umask 022

usage() {
    cat <<'EOF'
Usage: scripts/package-release.sh [OPTIONS]

Build a native psmore release archive with documentation and completions.

Options:
  --target TARGET       Rust target triple (default: rustc host target)
  --output-dir DIR      Archive destination (default: ./dist)
  --no-build            Package an existing release binary
  -h, --help            Show this help

The target must match the build host, except linux-musl targets whose
architecture matches the host: the static musl binary runs natively on the
glibc host, so it can still generate completions and be smoke-tested.
Release automation uses native runners for the same reason.
EOF
}

fail() {
    printf 'psmore package: %s\n' "$*" >&2
    exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
target=''
output_dir="$repo_root/dist"
should_build=true

while [ "$#" -gt 0 ]; do
    case "$1" in
        --target)
            [ "$#" -ge 2 ] || fail '--target requires a value'
            target=$2
            shift 2
            ;;
        --output-dir)
            [ "$#" -ge 2 ] || fail '--output-dir requires a value'
            output_dir=$2
            shift 2
            ;;
        --no-build)
            should_build=false
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

command -v cargo >/dev/null 2>&1 || fail 'cargo is required'
command -v rustc >/dev/null 2>&1 || fail 'rustc is required'
command -v tar >/dev/null 2>&1 || fail 'tar is required'
command -v gzip >/dev/null 2>&1 || fail 'gzip is required'
command -v install >/dev/null 2>&1 || fail 'install is required'

host_target=$(rustc -vV | sed -n 's/^host: //p')
[ -n "$host_target" ] || fail 'could not determine the rustc host target'
[ -n "$target" ] || target=$host_target
if [ "$target" != "$host_target" ]; then
    host_arch=${host_target%%-*}
    case "$host_target:$target" in
        "$host_arch"-unknown-linux-gnu:"$host_arch"-unknown-linux-musl)
            # A static musl binary runs natively on this glibc Linux host.
            ;;
        *)
            fail "target $target is not native to this $host_target host"
            ;;
    esac
fi

version=$(sed -n '/^\[package\]/,/^\[/{s/^version = "\([^"]*\)"/\1/p;}' "$repo_root/Cargo.toml" | head -n 1)
[ -n "$version" ] || fail 'could not read package version from Cargo.toml'

case "$version" in
    *[!0-9A-Za-z.+-]*) fail "unsafe package version: $version" ;;
esac
case "$target" in
    *[!0-9A-Za-z_.-]*) fail "unsafe target triple: $target" ;;
esac

if [ "$should_build" = true ]; then
    (
        cd "$repo_root"
        cargo build --release --locked --target "$target"
    )
fi

binary="$repo_root/target/$target/release/psmore"
[ -x "$binary" ] || fail "release binary not found: $binary"
actual_version=$($binary --version)
[ "$actual_version" = "psmore $version" ] || fail "binary version mismatch: $actual_version"

mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd -P)

archive_root="psmore-v$version-$target"
archive_name="$archive_root.tar.gz"
archive_path="$output_dir/$archive_name"
archive_tmp="$output_dir/.$archive_name.tmp.$$"
checksum_path="$archive_path.sha256"
checksum_tmp="$output_dir/.$archive_name.sha256.tmp.$$"
stage_dir=$(mktemp -d "${TMPDIR:-/tmp}/psmore-package.XXXXXX")

cleanup() {
    rm -f -- "$archive_tmp" "$checksum_tmp"
    if [ -d "$stage_dir" ]; then
        find "$stage_dir" -depth -delete
    fi
}
trap cleanup 0 1 2 15

package_dir="$stage_dir/$archive_root"
install -d -m 0755 \
    "$package_dir/bin" \
    "$package_dir/share/man/man1" \
    "$package_dir/share/bash-completion/completions" \
    "$package_dir/share/zsh/site-functions" \
    "$package_dir/share/fish/vendor_completions.d"
install -m 0755 "$binary" "$package_dir/bin/psmore"
install -m 0755 "$repo_root/scripts/install.sh" "$package_dir/install.sh"
install -m 0755 "$repo_root/scripts/uninstall.sh" "$package_dir/uninstall.sh"
install -m 0644 "$repo_root/docs/psmore.1" "$package_dir/share/man/man1/psmore.1"
install -m 0644 "$repo_root/README.md" "$package_dir/README.md"
install -m 0644 "$repo_root/CHANGELOG.md" "$package_dir/CHANGELOG.md"
install -m 0644 "$repo_root/LICENSE" "$package_dir/LICENSE"
printf '%s\n' "$version" > "$package_dir/VERSION"

"$binary" completion bash > "$package_dir/share/bash-completion/completions/psmore"
"$binary" completion zsh > "$package_dir/share/zsh/site-functions/_psmore"
"$binary" completion fish > "$package_dir/share/fish/vendor_completions.d/psmore.fish"
chmod 0644 \
    "$package_dir/VERSION" \
    "$package_dir/share/bash-completion/completions/psmore" \
    "$package_dir/share/zsh/site-functions/_psmore" \
    "$package_dir/share/fish/vendor_completions.d/psmore.fish"

source_commit=unknown
source_dirty=unknown
source_date_epoch=${SOURCE_DATE_EPOCH:-}
if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    source_commit=$(git -C "$repo_root" rev-parse HEAD)
    if git -C "$repo_root" diff --quiet --ignore-submodules HEAD -- &&
       [ -z "$(git -C "$repo_root" ls-files --others --exclude-standard)" ]; then
        source_dirty=false
    else
        source_dirty=true
    fi
    if [ -z "$source_date_epoch" ]; then
        source_date_epoch=$(git -C "$repo_root" log -1 --format=%ct)
    fi
fi
[ -n "$source_date_epoch" ] || source_date_epoch=946684800
case "$source_date_epoch" in
    *[!0-9]*) fail "SOURCE_DATE_EPOCH must be a non-negative integer: $source_date_epoch" ;;
esac

rust_version=$(rustc --version)
cat > "$package_dir/BUILD-INFO" <<EOF
name=psmore
version=$version
target=$target
source_commit=$source_commit
source_dirty=$source_dirty
source_date_epoch=$source_date_epoch
rust=$rust_version
EOF
chmod 0644 "$package_dir/BUILD-INFO"

if touch_stamp=$(date -u -r "$source_date_epoch" +%Y%m%d%H%M.%S 2>/dev/null); then
    :
elif touch_stamp=$(date -u -d "@$source_date_epoch" +%Y%m%d%H%M.%S 2>/dev/null); then
    :
else
    fail "could not convert SOURCE_DATE_EPOCH: $source_date_epoch"
fi
find "$package_dir" -exec touch -h -t "$touch_stamp" {} +

file_list="$stage_dir/archive-files.txt"
(
    cd "$stage_dir"
    find "$archive_root" -print | LC_ALL=C sort > "$file_list"
)

if tar --version 2>&1 | grep -q 'GNU tar'; then
    (
        cd "$stage_dir"
        tar --format=ustar --mtime="@$source_date_epoch" --owner=0 --group=0 \
            --numeric-owner --no-recursion -cf - -T "$file_list"
    ) | gzip -n > "$archive_tmp"
else
    (
        cd "$stage_dir"
        tar --format ustar --uid 0 --gid 0 --uname root --gname root \
            --no-recursion -cf - -T "$file_list"
    ) | gzip -n > "$archive_tmp"
fi
mv -f -- "$archive_tmp" "$archive_path"

if command -v sha256sum >/dev/null 2>&1; then
    digest=$(sha256sum "$archive_path" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    digest=$(shasum -a 256 "$archive_path" | awk '{print $1}')
else
    fail 'sha256sum or shasum is required'
fi
printf '%s  %s\n' "$digest" "$archive_name" > "$checksum_tmp"
mv -f -- "$checksum_tmp" "$checksum_path"

printf 'Created %s\n' "$archive_path"
printf 'Created %s\n' "$checksum_path"
