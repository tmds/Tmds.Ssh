FROM fedora

# Install dependencies
RUN dnf install -y mingw64-openssl 'dnf-command(download)' cpio xz cmake \
                   mingw64-gcc-c++ binutils

WORKDIR /root

# Download libssh rpm sources.
RUN dnf download libssh --source && \
    rpm2cpio libssh-*.src.rpm  | cpio -idmv && \
    tar -xf libssh-*.tar.xz && \
    ls && \
    mv $(find . -maxdepth 1 -name 'libssh-*' -type d) libssh

# Build and install libssh.
RUN mkdir libssh/build && \
    cd libssh/build && \
    mingw64-cmake .. && \
    make -j$(nproc) && \
    make install

# Collect dlls.
COPY collect-dlls.sh .
RUN ./collect-dlls.sh
