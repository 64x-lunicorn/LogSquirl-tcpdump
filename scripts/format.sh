#!/usr/bin/env bash
# Format the C++ files with the clang-format the CI's Format job pins in
# .github/requirements/clang-format.txt, run through uvx, so that nothing
# needs installing.
#
#   scripts/format.sh                  format every file the CI checks
#   scripts/format.sh <base>           only those changed since <base> (a commit or branch)
#   scripts/format.sh --check [<base>] change nothing; exit 1 and name each file that is off
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

check=0
if [ "${1:-}" = "--check" ]; then
    check=1
    shift
fi
base="${1:-}"

version=$(sed -n 's/^clang-format==\([0-9][0-9.]*\).*/\1/p' .github/requirements/clang-format.txt)
if [ -z "$version" ]; then
    echo "format.sh: no clang-format==<version> in .github/requirements/clang-format.txt" >&2
    exit 2
fi

# The CI's Format job checks the same files, the vendored plugin API header aside.
patterns=('*.c' '*.cc' '*.cpp' '*.cxx' '*.h' '*.hh' '*.hpp' ':(exclude)include/logsquirl_plugin_api.h')
if [ -n "$base" ]; then
    files=$(git diff --name-only --diff-filter=d "$(git merge-base "$base" HEAD)" -- "${patterns[@]}")
    files+=$'\n'$(git ls-files --others --exclude-standard -- "${patterns[@]}")
else
    files=$(git ls-files -- "${patterns[@]}")
fi
files=$(printf '%s\n' "$files" | sed '/^$/d' | sort -u)
if [ -z "$files" ]; then
    echo "format.sh: no C++ files to format"
    exit 0
fi

clang_format=(uvx --quiet --from "clang-format==$version" clang-format)
if [ "$check" -eq 1 ]; then
    printf '%s\n' "$files" | xargs "${clang_format[@]}" --dry-run --Werror
    echo "format.sh: clean (clang-format $version)"
else
    printf '%s\n' "$files" | xargs "${clang_format[@]}" -i
    echo "format.sh: formatted $(printf '%s\n' "$files" | wc -l | tr -d ' ') files (clang-format $version)"
fi
