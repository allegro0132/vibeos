#!/bin/sh
set -eu
image=mars-serial-sd.img
if [ "$#" -eq 1 ] && [ "$1" = --ethernet ]; then
    image=mars-ethernet-sd.img
elif [ "$#" -ne 0 ]; then
    echo 'usage: package.sh [--ethernet]' >&2
    exit 2
fi
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
