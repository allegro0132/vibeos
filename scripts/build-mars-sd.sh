#!/bin/sh
# Produces a test SD image file; never writes a physical disk or board SPI.
set -eu
profile=serial
if [ "$#" -eq 1 ] && [ "$1" = --ethernet ]; then
    profile=ethernet
elif [ "$#" -ne 0 ]; then
    echo 'usage: build-mars-sd.sh [--ethernet]' >&2
    exit 2
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
sdk_commit=1fd6bac9f2efde47fbb8afd28d2903c49f893e3f
work="$root/target/mars-boot"
sdk="$work/sdk"
payload=bringup
if [ "$profile" = ethernet ]; then
    work="$root/target/mars-boot-ethernet"
    payload=ethernet
fi
image="mars-$profile-sd.img"
if [ -e "$work/out/$image" ]; then
    echo "Move the previous $work/out/$image before rebuilding." >&2
    exit 1
fi
mkdir -p "$work/input"
if [ ! -d "$sdk/.git" ]; then
    mkdir -p "$(dirname "$sdk")"
    git clone --filter=blob:none --no-checkout --depth 1 \
        https://github.com/milkv-mars/mars-buildroot-sdk.git "$sdk"
fi
test -z "$(git -C "$sdk" status --porcelain)"
git -C "$sdk" fetch --depth 1 origin "$sdk_commit"
git -C "$sdk" sparse-checkout set u-boot opensbi soft_3rdpart/spl_tool conf \
    linux/arch/riscv/boot/dts/starfive linux/include/dt-bindings
git -C "$sdk" checkout --detach "$sdk_commit"
sh scripts/build-milkv-mars.sh "$@"
cp firmware/milkv-mars/bootchain/build.sh firmware/milkv-mars/bootchain/package.sh \
    firmware/milkv-mars/bootchain/firmware.its firmware/milkv-mars/bootchain/vibeos.its \
    scripts/mars-sd-image.py scripts/mars-check-bootchain.py "target/milkv-mars/$payload/vibeos.bin" "$work/input/"
docker build --tag vibeos-mars-boot-tools:stage25 firmware/milkv-mars/bootchain
docker run --rm --mount "type=bind,source=$work,target=/work" \
    --mount "type=bind,source=$sdk,target=/work/sdk,readonly" \
    vibeos-mars-boot-tools:stage25 sh /work/input/build.sh
docker run --rm --mount "type=bind,source=$work,target=/work" \
    --mount "type=bind,source=$sdk,target=/work/sdk,readonly" \
    vibeos-mars-boot-tools:stage25 sh /work/input/package.sh "$@"
python3 scripts/mars-sd-manifest.py "$@"
echo "Test image: $work/out/$image (physical qualification pending)"
