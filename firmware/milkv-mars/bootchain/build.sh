#!/bin/sh
# Run in the pinned tools container with only target/mars-boot mounted at /work.
set -eu
export SOURCE_DATE_EPOCH=1711929600
export KBUILD_BUILD_USER=vibeos KBUILD_BUILD_HOST=mars-builder
sdk=/work/sdk
out=/work/out
mkdir -p "$out/uboot" "$out/opensbi" "$out/artifacts"
test "$(git -C "$sdk" rev-parse HEAD)" = 1fd6bac9f2efde47fbb8afd28d2903c49f893e3f
test -z "$(git -C "$sdk" status --porcelain)"
make -C "$sdk/u-boot" O="$out/uboot" starfive_visionfive2_defconfig
python3 - "$out/uboot/.config" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
changes = {
    'CONFIG_ENV_IS_IN_SPI_FLASH': 'n', 'CONFIG_ENV_IS_NOWHERE': 'y',
    'CONFIG_SMP': 'n', 'CONFIG_SBI_V01': 'n',
    'CONFIG_BOOTCOMMAND': '"mmc dev 1; if load mmc 1:3 0x46000000 vibeos.itb; then bootm 0x46000000; fi"',
    'CONFIG_BOOTARGS': '""',
}
lines = p.read_text().splitlines()
lines = [s for s in lines if not any(s.startswith(k + '=') or s == '# ' + k + ' is not set' for k in changes)]
lines += [('# ' + k + ' is not set') if v == 'n' else k + '=' + v for k, v in changes.items()]
p.write_text('\n'.join(lines) + '\n')
PY
make -C "$sdk/u-boot" O="$out/uboot" CROSS_COMPILE=riscv64-linux-gnu- olddefconfig
# Building explicit binaries avoids the SDK's unused/missing SPL_FIT_SOURCE.
make -C "$sdk/u-boot" O="$out/uboot" CROSS_COMPILE=riscv64-linux-gnu- -j"${JOBS:-4}" u-boot.bin spl/u-boot-spl.bin
make -C "$sdk/opensbi" O="$out/opensbi" CROSS_COMPILE=riscv64-linux-gnu- \
    PLATFORM=generic FW_TEXT_START=0x40000000 FW_PAYLOAD_OFFSET=0x200000 \
    FW_PAYLOAD_PATH="$out/uboot/u-boot.bin" \
    FW_FDT_PATH="$out/uboot/arch/riscv/dts/starfive_visionfive2.dtb" -j"${JOBS:-4}"
mkdir -p "$out/spl_tool"
cp -R "$sdk/soft_3rdpart/spl_tool/." "$out/spl_tool/"
make -C "$out/spl_tool"
"$out/spl_tool/spl_tool" -c -f "$out/uboot/spl/u-boot-spl.bin"
cp "$out/uboot/spl/u-boot-spl.bin.normal.out" "$out/artifacts/"
cp "$out/opensbi/platform/generic/firmware/fw_payload.bin" "$out/artifacts/"
cp "$out/uboot/.config" "$out/artifacts/uboot.config"
cp "$out/opensbi/platform/generic/kconfig/.config" "$out/artifacts/opensbi.config"
{
    riscv64-linux-gnu-gcc --version
    riscv64-linux-gnu-as --version
    dtc --version
    mkimage -V
    dpkg-query -W
} > "$out/artifacts/tool-versions.txt"
