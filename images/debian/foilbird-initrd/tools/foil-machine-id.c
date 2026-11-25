// SPDX-License-Identifier: Apache-2.0
// machine-id = SMBIOS system UUID (lower-case hex, no dashes), written into the new root before systemd there initializes
// the id. /etc is a tmpfs, so without this the id is new on every boot (systemd uses the DMI UUID only under KVM); same
// rule on VMs and hardware. If the firmware has no UUID, or it is all zeros / all F, /sysroot/etc/machine-id is left
// alone: systemd generates a random one for this boot (warned on the console). Runs in the initrd, which has no
// shell, hence a small program. Exit 0 in every case: a missing id must not fail the boot.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DMI_UUID "/sys/class/dmi/id/product_uuid"
#define TARGET_DIR "/sysroot/etc"
#define TARGET TARGET_DIR "/machine-id"

int main(void) {
    char raw[128] = "", id[33];
    size_t n = 0;
    FILE *f = fopen(DMI_UUID, "re");
    if (f) {
        size_t r = fread(raw, 1, sizeof raw - 1, f);
        raw[r] = 0;
        fclose(f);
    }
    // drop newlines and dashes, lower-case; anything else is kept so a malformed value is reported as such
    char clean[128];
    for (size_t i = 0; raw[i]; i++) {
        char c = raw[i];
        if (c == '\n' || c == '-') continue;
        if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
        clean[n++] = c;
        if (n == sizeof clean - 1) break;
    }
    clean[n] = 0;
    if (n == 0 || !strcmp(clean, "00000000000000000000000000000000") || !strcmp(clean, "ffffffffffffffffffffffffffffffff")) {
        printf("foil-machine-id: no usable SMBIOS UUID ('%s'), machine-id will be random for this boot\n", clean);
        return 0;
    }
    if (n != 32 || strspn(clean, "0123456789abcdef") != 32) {
        printf("foil-machine-id: malformed SMBIOS UUID '%s', ignored\n", clean);
        return 0;
    }
    memcpy(id, clean, 32);
    id[32] = 0;
    if (mkdir(TARGET_DIR, 0755) < 0 && errno != EEXIST) {
        printf("foil-machine-id: mkdir %s: %s, machine-id will be random for this boot\n", TARGET_DIR, strerror(errno));
        return 0;
    }
    int fd = open(TARGET, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0444);
    char line[34];
    memcpy(line, id, 32);
    line[32] = '\n';
    if (fd < 0 || write(fd, line, 33) != 33 || close(fd) < 0) {
        printf("foil-machine-id: writing %s: %s, machine-id will be random for this boot\n", TARGET, strerror(errno));
        return 0;
    }
    printf("foil-machine-id: %s (from SMBIOS)\n", id);
    return 0;
}
