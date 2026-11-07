#!/usr/bin/env bash
# Собирает liboqs из submodule vendor/liboqs в vendor/oqs-install
# (там её ищет qcc/oqs.py). Нужны cmake и компилятор C.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/vendor/liboqs"
BUILD="$SRC/build"

if [ ! -f "$SRC/CMakeLists.txt" ]; then
    git -C "$ROOT" submodule update --init vendor/liboqs
fi

# Только нужные алгоритмы; OQS_DIST_BUILD — переносимая сборка,
# AVX2 выбирается во время работы
cmake -S "$SRC" -B "$BUILD" \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=ON \
    -DOQS_USE_OPENSSL=OFF \
    -DOQS_MINIMAL_BUILD="SIG_falcon_512;SIG_falcon_1024;SIG_ml_dsa_44;SIG_ml_dsa_65" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$ROOT/vendor/oqs-install"
cmake --build "$BUILD" -j"$(nproc)"
cmake --install "$BUILD"
