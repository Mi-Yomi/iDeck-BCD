#!/bin/bash
set -e

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$BUILD_DIR/../.." && pwd)"
WINE_SRC="$REPO_ROOT/wine"
WINE_BUILD="$WINE_SRC/build-macos"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
OBJ_DIR="$BUILD_DIR/obj"
APP_LIB="$REPO_ROOT/app/Madeira/libntdll_unix.a"

mkdir -p "$OBJ_DIR"

# The forced I/O shim reaches upstream file/socket and Unix DLL objects too.
# Upgrade old archives with a full build before using this incremental recipe.
IO_STAMP="$OBJ_DIR/fixed-image-io.stamp"
if [ ! -f "$IO_STAMP" ] || [ "$BUILD_DIR/shims/ios_fixed_image_io.h" -nt "$IO_STAMP" ] || \
   [ "$BUILD_DIR/build.sh" -nt "$IO_STAMP" ]; then
    echo "=== Rebuilding all Unix objects for the fixed-image I/O shim ==="
    exec "$BUILD_DIR/build.sh"
fi

compile_one() {
    local src=$1
    local out=$2
    local io_flags=()
    if [ "$out" = "ios_fixed_image_io.o" ]; then io_flags=(-DIOS_FIXED_IMAGE_IO_IMPL=1); fi
    echo -n "  $out... "
    if xcrun -sdk iphoneos clang \
        -arch arm64 -isysroot "$SDK" -miphoneos-version-min=17.0 \
        -O2 -fPIC -fvisibility=hidden -fno-stack-protector -fno-strict-aliasing \
        -Wno-implicit-function-declaration -Wno-int-conversion \
        -include "$WINE_BUILD/include/config.h" \
        -include "$BUILD_DIR/shims/wine_ios_exit.h" \
        -include "$BUILD_DIR/shims/ios_fixed_image_io.h" "${io_flags[@]}" \
        -I"$BUILD_DIR/shims" \
        -I"$WINE_BUILD/dlls/ntdll" -I"$WINE_SRC/dlls/ntdll" -I"$WINE_SRC/dlls/ntdll/unix" \
        -I"$WINE_BUILD/include" -I"$WINE_SRC/include" \
        -D__WINESRC__ -DLTC_NO_PROTOTYPES -DLTC_SOURCE -D_NTSYSTEM_ \
        -D_ACRTIMP= -DWINBASEAPI= \
        -DBINDIR=\"/usr/local/bin\" -DLIBDIR=\"/usr/local/lib\" \
        -DDATADIR=\"/usr/local/share\" -DSYSTEMDLLPATH=\"\" \
        -DWINE_UNIX_LIB -DWINE_IOS=1 \
        -Dget_thread_context=ntdll_get_thread_context \
        -Dset_thread_context=ntdll_set_thread_context \
        -c "$src" -o "$OBJ_DIR/$out" 2>"$OBJ_DIR/${out%.o}.err"; then
        echo "OK"
    else
        echo "FAILED"
        cat "$OBJ_DIR/${out%.o}.err"
        return 1
    fi
}

echo "=== Compiling patched files ==="
compile_one "$BUILD_DIR/loader_ios.c" "loader.o"
compile_one "$BUILD_DIR/ios_fixed_image_io.c" "ios_fixed_image_io.o"
compile_one "$BUILD_DIR/process_ios.c" "process.o"
compile_one "$BUILD_DIR/server_ios.c" "server.o"
compile_one "$BUILD_DIR/virtual_ios.c" "virtual.o"
compile_one "$BUILD_DIR/signal_arm64_ios.c" "signal_arm64.o"

echo ""
echo "=== Rebuilding libntdll_unix.a ==="
# Update existing archive with recompiled objects
if [ -f "$OBJ_DIR/libntdll_unix.a" ]; then
    for obj in loader.o process.o server.o virtual.o signal_arm64.o ios_fixed_image_io.o; do
        ar d "$OBJ_DIR/libntdll_unix.a" "$obj" 2>/dev/null || true
        ar r "$OBJ_DIR/libntdll_unix.a" "$OBJ_DIR/$obj"
    done
else
    echo "ERROR: No base libntdll_unix.a — run build.sh first"
    exit 1
fi

echo "Copying to app..."
cp "$OBJ_DIR/libntdll_unix.a" "$APP_LIB"
echo "libntdll_unix.a: $(wc -c < "$APP_LIB" | tr -d ' ') bytes"
echo "Done!"
