# Before you flash

Selected bundles have repeated normal/cold boot and user-reported offline memory-test observations on one MR9A PRO V1.2; comprehensive hardware validation remains incomplete. See [hardware test records](hardware-tests.md) for the exact selections and limits. A bad image leaves a board that won't POST. Only flash if you can recover with an external programmer.

## 1. Read and keep the original

Use an external SPI programmer (for example a CH341A with a SOIC-8 clip) and `flashrom`. Power the board off and unplug it first.

```sh
flashrom -p ch341a_spi -r dump1.bin
flashrom -p ch341a_spi -r dump2.bin
cmp dump1.bin dump2.bin && sha256sum dump1.bin
```

Two identical reads mean the clip is seated. Keep that file somewhere safe; it's your only way back. It contains the board's own data too: the Intel ME region, the GbE MAC address if present, the serial numbers and the NVRAM settings.

## 2. Build from that dump

```sh
./x99fix scan dump1.bin
./x99fix patch dump1.bin --select B02-B03 B01-B06 -o patched.bin
```

`x99fix` changes only the firmware volumes that contain patched modules. It checks that every other byte is identical before it writes the output. Look at `patched.bin.manifest.json` to see what changed.

## 3. Write only the BIOS region

The dump starts with an Intel flash descriptor. Write only the BIOS region, so the ME and GbE regions on the chip stay untouched:

```sh
flashrom -p ch341a_spi --ifd -i bios -w patched.bin
```

`flashrom` verifies after writing. If the board doesn't POST, write `dump1.bin` back the same way.

## About AFU and other in-OS flashers

AMI's flashing tools may reject a modified image or refuse to write some regions. A programmer avoids both problems and gives you a recovery path. This repository doesn't document in-OS flashing.

## Test one change at a time

Flash one patch set, then boot several times, cold and warm. Note the POST sequence ([post-codes.md](post-codes.md)). Then move on to the next set. If something regresses, you'll know which change caused it.
