#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Copy one GPT partition of a disk image file to a file, without root, loop devices or sfdisk.

    gpt_part.py <image> <type-guid> <out>      the first partition of that type (UEFI spec 5.3, 512-byte sectors)

Prints "<first-lba> <last-lba> <bytes> <name>". Exit 1 when the image has no such partition.
"""
import struct
import sys
import uuid


def main():
    img, want, out = sys.argv[1], uuid.UUID(sys.argv[2]), sys.argv[3]
    with open(img, "rb") as f:
        f.seek(512)
        hdr = f.read(92)
        if hdr[:8] != b"EFI PART":
            sys.exit("gpt_part: no GPT header at LBA 1")
        entries_lba, count, size = struct.unpack_from("<QII", hdr, 72)
        f.seek(entries_lba * 512)
        table = f.read(count * size)
        for i in range(count):
            e = table[i * size:(i + 1) * size]
            if uuid.UUID(bytes_le=e[:16]) != want:
                continue
            first, last = struct.unpack_from("<QQ", e, 32)
            name = e[56:128].decode("utf-16-le").rstrip("\0")
            n = (last - first + 1) * 512
            f.seek(first * 512)
            with open(out, "wb") as o:
                left = n
                while left:
                    b = f.read(min(left, 1 << 20))
                    if not b:
                        sys.exit("gpt_part: image shorter than the partition table says")
                    o.write(b)
                    left -= len(b)
            print(first, last, n, name)
            return
    sys.exit(1)


if __name__ == "__main__":
    main()
