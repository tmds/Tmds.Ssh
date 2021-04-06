#!/bin/sh

MINGW_BIN_DIR="/usr/x86_64-w64-mingw32/sys-root/mingw/bin"

DLLS_DIR="$HOME/dlls"
LIBSSH_SRC_RPM="$HOME/libssh-*.src.rpm"
DLLS_INFO="$DLLS_DIR/info.txt"

rm -rf "$DLLS_INFO"

write_info()
{
    echo "$1" | tee -a "$DLLS_INFO"
}

MINGW_DLLS=("libgcc_s_seh-1.dll" \
      "libcrypto-1_1-x64.dll" \
      "zlib1.dll" \
      "libssp-0.dll")

LIBSSH_DLL="libssh.dll"

PACKAGE_INFO="package: %{name}\nversion: %{version}\nrelease: %{release}\nlicense: %{license}\n"

mkdir "$DLLS_DIR"

# MINGW_DLLS
for MINGW_DLL in ${MINGW_DLLS[@]};
do
  MINGW_DLL_PATH="$MINGW_BIN_DIR/$MINGW_DLL"
  cp "$MINGW_DLL_PATH" "$DLLS_DIR"
  write_info "dll: $MINGW_DLL"
  write_info "$(rpm -qf "$MINGW_DLL_PATH" --qf "$PACKAGE_INFO")"
  write_info ""
done
# LIBSSH_DLL
write_info "dll: $LIBSSH_DLL"
cp "$MINGW_BIN_DIR/$LIBSSH_DLL" "$DLLS_DIR"
write_info "$(rpm -q "$LIBSSH_SRC_RPM" --qf "$PACKAGE_INFO")"
write_info ""
