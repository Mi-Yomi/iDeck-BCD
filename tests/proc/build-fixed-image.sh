#!/bin/bash
# iDeck-BCD, 2026-10-22: compile device regression PEs in GitHub Actions.
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
MINGW="${MINGW:-$REPO_ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin}"
OUT="${1:-$DIR/out-fixed-image}"
mkdir -p "$OUT"
for role in 1 2; do
    name=fixed-parent
    if [ "$role" = 2 ]; then name=fixed-child; fi
    "$MINGW/x86_64-w64-mingw32-clang" -O2 -g -Wall -Wextra -Werror -mconsole \
        -DFIXED_TEST_ROLE="$role" \
        -Wl,--image-base,0x140000000,--disable-dynamicbase,--disable-reloc-section \
        "$DIR/fixed_image.c" -o "$OUT/$name.exe"
done
python3 "$REPO_ROOT/tests/host/check-fixed-image-isolation.py" --pe-dir "$OUT" --static-only
printf 'Built fixed-parent.exe and fixed-child.exe in %s\n' "$OUT"
