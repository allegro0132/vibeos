#!/bin/sh
# Produces a test SD image file; never writes a physical disk or board SPI.
set -eu
profile=serial
trng=0
work_override=
usage() { echo 'usage: build-mars-sd.sh [--ethernet] [--trng-probe] [--work-dir DIRECTORY]' >&2; exit 2; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --ethernet) [ "$profile" = serial ] || usage; profile=ethernet ;;
        --trng-probe) [ "$trng" -eq 0 ] || usage; trng=1 ;;
        --work-dir)
            [ -z "$work_override" ] && [ "$#" -ge 2 ] && [ -n "$2" ] || usage
            case "$2" in --*) usage ;; esac
            work_override=$2
            shift ;;
        *) usage ;;
    esac
    shift
done
# Forward only profile flags to payload and in-container packaging commands.
set --
[ "$profile" != ethernet ] || set -- "$@" --ethernet
[ "$trng" -eq 0 ] || set -- "$@" --trng-probe
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
if [ "$trng" -eq 1 ]; then
    work="$work-trng-probe"
    payload="$payload-trng-probe"
    profile="$profile-trng-probe"
fi
# Relative custom work paths are relative to the repository, as are defaults.
# Keep SDK inputs shared and pinned even when archiving a new output generation.
if [ -n "$work_override" ]; then
    case "$work_override" in
        /*) work=$work_override ;;
        *) work="$root/$work_override" ;;
    esac
fi
image="mars-$profile-sd.img"
# Artifacts and manifest are shared within a work directory. Even a different
# profile image must prevent reuse, or its existing evidence would be replaced.
for previous in "$work"/out/mars-*-sd.img; do
    if [ -e "$previous" ] || [ -L "$previous" ]; then
        echo "Move the previous $previous or select a new --work-dir before rebuilding." >&2
        exit 1
    fi
done
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
python3 scripts/mars-sd-manifest.py "$@" --work-dir "$work"
echo "Test image: $work/out/$image (physical qualification pending)"
