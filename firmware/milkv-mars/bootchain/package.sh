#!/bin/sh
set -eu
profile=serial
trng=0
for arg in "$@"; do
    case "$arg" in
        --ethernet) [ "$profile" = serial ] || exit 2; profile=ethernet ;;
        --trng-probe) [ "$trng" -eq 0 ] || exit 2; trng=1 ;;
        *) echo 'usage: package.sh [--ethernet] [--trng-probe]' >&2; exit 2 ;;
    esac
done
if [ "$trng" -eq 1 ]; then profile="$profile-trng-probe"; fi
image="mars-$profile-sd.img"
export SOURCE_DATE_EPOCH=1711929600
sdk=/work/sdk
out=/work/out/artifacts
test ! -e "/work/out/$image"
cd "$out"
cp /work/input/vibeos.bin .
cp /work/input/firmware.its /work/input/vibeos.its .
gcc -E -nostdinc -undef -D__DTS__ -x assembler-with-cpp \
    -I "$sdk/linux/include" -I "$sdk/linux/arch/riscv/boot/dts/starfive" \
    "$sdk/linux/arch/riscv/boot/dts/starfive/jh7110-milkv-mars.dts" -o mars.pp.dts
dtc -I dts -O dtb -o mars.dtb mars.pp.dts
mkimage -f firmware.its firmware.itb
mkimage -f vibeos.its vibeos.itb
python3 /work/input/mars-check-bootchain.py /work/out
# Regular staging FAT file only. The assembler refuses to overwrite its output.
truncate -s 0 boot.fat
truncate -s 120M boot.fat
mkfs.vfat --invariant -F 32 -n VIBEOSBOOT boot.fat
mcopy -o -i boot.fat vibeos.itb ::vibeos.itb
mdir -i boot.fat ::
fsck.vfat -n boot.fat
python3 /work/input/mars-sd-image.py assemble "/work/out/$image" \
    --artifacts "$out" --report /work/out/sd-check.json
sgdisk --verify "/work/out/$image"
mkimage -l firmware.itb
mkimage -l vibeos.itb
