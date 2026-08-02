#!/bin/sh

set -eu

fail() {
    printf 'psmore package verification: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 1 ] || fail 'usage: scripts/verify-release-package.sh ARCHIVE.tar.gz'
archive=$1
[ -f "$archive" ] || fail "archive not found: $archive"
case "$archive" in
    *.tar.gz) ;;
    *) fail 'archive must end in .tar.gz' ;;
esac

checksum_file="$archive.sha256"
[ -f "$checksum_file" ] || fail "checksum not found: $checksum_file"
expected_digest=$(awk 'NR == 1 {print $1}' "$checksum_file")
[ "${#expected_digest}" -eq 64 ] || fail "invalid checksum length in $checksum_file"
case "$expected_digest" in
    *[!0-9a-fA-F]*) fail "invalid checksum in $checksum_file" ;;
    '') fail "invalid checksum in $checksum_file" ;;
    *) ;;
esac
if command -v sha256sum >/dev/null 2>&1; then
    actual_digest=$(sha256sum "$archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    actual_digest=$(shasum -a 256 "$archive" | awk '{print $1}')
else
    fail 'sha256sum or shasum is required'
fi
[ "$actual_digest" = "$expected_digest" ] || fail 'SHA-256 checksum mismatch'

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/psmore-verify.XXXXXX")
cleanup() {
    if [ -d "$temp_dir" ]; then
        find "$temp_dir" -depth -delete
    fi
}
trap cleanup 0 1 2 15

listing="$temp_dir/archive-files.txt"
verbose_listing="$temp_dir/archive-files.verbose.txt"
tar -tzf "$archive" > "$listing"
tar -tvzf "$archive" > "$verbose_listing"
[ -s "$listing" ] || fail 'archive is empty'
[ -z "$(LC_ALL=C sort "$listing" | uniq -d)" ] || fail 'archive contains duplicate entries'
if awk 'substr($0, 1, 1) != "-" && substr($0, 1, 1) != "d" { exit 1 }' "$verbose_listing"; then
    :
else
    fail 'archive contains links, devices, or another unsupported entry type'
fi
archive_root=$(sed -n '1{s|/.*||;p;}' "$listing")
case "$archive_root" in
    psmore-v*-*) ;;
    *) fail "unexpected archive root: $archive_root" ;;
esac

while IFS= read -r entry; do
    case "$entry" in
        /*) fail "archive contains an absolute path: $entry" ;;
    esac
    case "/$entry/" in
        */../*|*/./*) fail "archive contains an unsafe path: $entry" ;;
    esac
    case "$entry" in
        "$archive_root"|"$archive_root/"*) ;;
        *) fail "archive contains a second root: $entry" ;;
    esac
done < "$listing"

tar -xzf "$archive" -C "$temp_dir"
package_dir="$temp_dir/$archive_root"
[ -x "$package_dir/install.sh" ] || fail 'install.sh is missing or not executable'
[ -x "$package_dir/uninstall.sh" ] || fail 'uninstall.sh is missing or not executable'
[ -x "$package_dir/bin/psmore" ] || fail 'psmore binary is missing or not executable'

version=$(sed -n '1p' "$package_dir/VERSION")
[ -n "$version" ] || fail 'VERSION is empty'
prefix="$temp_dir/prefix"

"$package_dir/install.sh" --prefix "$prefix" --dry-run >/dev/null
"$package_dir/install.sh" --prefix "$prefix" >/dev/null

[ -x "$prefix/bin/psmore" ] || fail 'installed binary is missing'
[ -f "$prefix/share/man/man1/psmore.1" ] || fail 'installed man page is missing'
[ -f "$prefix/share/bash-completion/completions/psmore" ] || fail 'bash completion is missing'
[ -f "$prefix/share/zsh/site-functions/_psmore" ] || fail 'zsh completion is missing'
[ -f "$prefix/share/fish/vendor_completions.d/psmore.fish" ] || fail 'fish completion is missing'
[ "$($prefix/bin/psmore --version)" = "psmore $version" ] || fail 'installed binary version mismatch'
grep -q 'file' "$prefix/share/bash-completion/completions/psmore" || fail 'bash completion is missing the file command'
grep -q 'file' "$prefix/share/zsh/site-functions/_psmore" || fail 'zsh completion is missing the file command'
grep -q 'file' "$prefix/share/fish/vendor_completions.d/psmore.fish" || fail 'fish completion is missing the file command'
grep -q 'run' "$prefix/share/bash-completion/completions/psmore" || fail 'bash completion is missing the run command'
grep -q 'run' "$prefix/share/zsh/site-functions/_psmore" || fail 'zsh completion is missing the run command'
grep -q 'run' "$prefix/share/fish/vendor_completions.d/psmore.fish" || fail 'fish completion is missing the run command'
file_report="$temp_dir/file-report.json"
"$prefix/bin/psmore" file "$prefix/bin/psmore" --json --limit 1 > "$file_report"
grep -q '"schema": "psmore.file-usage"' "$file_report" || fail 'installed file command returned an unexpected schema'

run_report="$temp_dir/run-report.json"
set +e
"$prefix/bin/psmore" run --output "$run_report" -- /bin/sh -c 'exit 7'
run_status=$?
set -e
[ "$run_status" -eq 7 ] || fail 'installed run command did not mirror the child exit status'
grep -q '"schema": "psmore.command-profile"' "$run_report" || fail 'installed run command returned an unexpected schema'

touch "$prefix/unrelated-file"
config_dir="$temp_dir/user-config"
mkdir -p "$config_dir"
touch "$config_dir/ui-state.json"

"$prefix/share/psmore/uninstall.sh" --prefix "$prefix" --dry-run >/dev/null
"$prefix/share/psmore/uninstall.sh" --prefix "$prefix" >/dev/null

[ ! -e "$prefix/bin/psmore" ] || fail 'uninstall left the binary behind'
[ ! -e "$prefix/share/psmore/uninstall.sh" ] || fail 'uninstall left its helper behind'
[ -f "$prefix/unrelated-file" ] || fail 'uninstall removed an unrelated prefix file'
[ -f "$config_dir/ui-state.json" ] || fail 'uninstall removed user configuration'

minimal_prefix="$temp_dir/minimal-prefix"
"$package_dir/install.sh" --prefix "$minimal_prefix" --no-completions >/dev/null
[ -x "$minimal_prefix/bin/psmore" ] || fail 'minimal install is missing the binary'
[ ! -e "$minimal_prefix/share/bash-completion/completions/psmore" ] || fail 'minimal install added bash completion'
[ ! -e "$minimal_prefix/share/zsh/site-functions/_psmore" ] || fail 'minimal install added zsh completion'
[ ! -e "$minimal_prefix/share/fish/vendor_completions.d/psmore.fish" ] || fail 'minimal install added fish completion'
"$package_dir/install.sh" --prefix "$minimal_prefix" --uninstall >/dev/null
[ ! -e "$minimal_prefix/bin/psmore" ] || fail 'delegated uninstall left the binary behind'

printf 'Verified %s (%s)\n' "$(basename -- "$archive")" "$actual_digest"
