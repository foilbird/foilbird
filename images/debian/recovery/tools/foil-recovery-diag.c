// SPDX-License-Identifier: Apache-2.0
// Read-only diagnosis of both A/B slots from the recovery UKI (decision 0003). No shell on the node, so this is a
// small program. For every slot usr_<v> it finds usr-verity_<v> and usr-verity-sig_<v> by partition name, takes the
// root hash from the signature partition (JSON "rootHash"; the signature itself is not checked here) and runs
// `veritysetup verify` (user space, nothing is opened or written). It lists the boot entries on the ESP, which the
// recovery mounts read-only at /boot. Report: console and /run/foilbird-recovery/report. Exit 0 = report written.
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAXP 64
#define VERITYSETUP "/usr/sbin/veritysetup"
#define ESP_LINUX "/boot/EFI/Linux"
#define IMAGE_PREFIX "foilbird-deb_"

struct part { char dev[300]; char name[128]; };
static struct part parts[MAXP];
static int nparts;
static FILE *rep;

static void out(const char *fmt, ...) {
    va_list a, b;
    va_start(a, fmt); va_copy(b, a);
    fputs("foilbird-recovery: ", stdout); vprintf(fmt, a); fputc('\n', stdout);
    if (rep) { vfprintf(rep, fmt, b); fputc('\n', rep); }
    va_end(a); va_end(b);
    fflush(stdout);
}

static int read_file(const char *path, char *buf, size_t n) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, n - 1);
    close(fd);
    if (r < 0) return -1;
    buf[r] = 0;
    return (int)r;
}

static void scan_parts(void) {
    DIR *d = opendir("/sys/class/block");
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) && nparts < MAXP) {
        if (e->d_name[0] == '.') continue;
        char p[512], buf[4096];
        snprintf(p, sizeof p, "/sys/class/block/%s/partition", e->d_name);
        if (access(p, F_OK) != 0) continue;
        snprintf(p, sizeof p, "/sys/class/block/%s/uevent", e->d_name);
        if (read_file(p, buf, sizeof buf) < 0) continue;
        char *n = strstr(buf, "PARTNAME=");
        if (!n) continue;
        n += 9;
        size_t l = strcspn(n, "\n");
        if (l == 0 || l >= sizeof parts[0].name) continue;
        snprintf(parts[nparts].dev, sizeof parts[0].dev, "/dev/%s", e->d_name);
        memcpy(parts[nparts].name, n, l); parts[nparts].name[l] = 0;
        nparts++;
    }
    closedir(d);
}

static const char *dev_of(const char *name) {
    for (int i = 0; i < nparts; i++) if (strcmp(parts[i].name, name) == 0) return parts[i].dev;
    return NULL;
}

// rootHash from the JSON in the signature partition (zero padded); 0 on success
static int root_hash(const char *dev, char *hash, size_t n) {
    static char buf[65536];
    if (read_file(dev, buf, sizeof buf) < 0) return -1;
    char *k = strstr(buf, "\"rootHash\"");
    if (!k) return -1;
    k = strchr(k + 10, '"');
    if (!k) return -1;
    k++;
    size_t l = strspn(k, "0123456789abcdef");
    if (l < 64 || l >= n || k[l] != '"') return -1;
    memcpy(hash, k, l); hash[l] = 0;
    return 0;
}

static int verify(const char *data, const char *hashdev, const char *hash) {
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        int nul = open("/dev/null", O_WRONLY);
        if (nul >= 0) { dup2(nul, 1); }
        execl(VERITYSETUP, "veritysetup", "verify", data, hashdev, hash, (char *)NULL);
        _exit(127);
    }
    int st;
    if (waitpid(p, &st, 0) < 0) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

// boot entry of version v on the ESP: file name or NULL
static char entry[256];
static const char *esp_entry(const char *v) {
    DIR *d = opendir(ESP_LINUX);
    if (!d) return NULL;
    struct dirent *e;
    const char *res = NULL;
    size_t pl = strlen(IMAGE_PREFIX), vl = strlen(v);
    while ((e = readdir(d))) {
        const char *n = e->d_name;
        if (strncmp(n, IMAGE_PREFIX, pl) != 0 || strncmp(n + pl, v, vl) != 0) continue;
        const char *r = n + pl + vl;
        if (strcmp(r, ".efi") == 0 || r[0] == '+') {
            snprintf(entry, sizeof entry, "%s", n);
            res = entry;
            break;
        }
    }
    closedir(d);
    return res;
}

int main(void) {
    mkdir("/run/foilbird-recovery", 0755);
    rep = fopen("/run/foilbird-recovery/report.tmp", "we");
    scan_parts();
    out("BEGIN read-only diagnosis, %d partitions", nparts);
    int slots = 0, good = 0;
    for (int i = 0; i < nparts; i++) {
        if (strncmp(parts[i].name, "usr_", 4) != 0) continue;
        const char *v = parts[i].name + 4;
        char nv[160], ns[160], hash[160];
        snprintf(nv, sizeof nv, "usr-verity_%s", v);
        snprintf(ns, sizeof ns, "usr-verity-sig_%s", v);
        const char *dv = dev_of(nv), *ds = dev_of(ns), *en = esp_entry(v);
        slots++;
        if (!dv || !ds) {
            out("slot %s: usr=%s verity=%s sig=%s result=INCOMPLETE entry=%s", v, parts[i].dev, dv ? dv : "-",
                ds ? ds : "-", en ? en : "-");
            continue;
        }
        if (root_hash(ds, hash, sizeof hash) != 0) {
            out("slot %s: usr=%s verity=%s sig=%s result=NO_ROOT_HASH entry=%s", v, parts[i].dev, dv, ds, en ? en : "-");
            continue;
        }
        int rc = verify(parts[i].dev, dv, hash);
        if (rc == 0) good++;
        out("slot %s: usr=%s verity=%s roothash=%.16s result=%s(rc=%d) entry=%s", v, parts[i].dev, dv, hash,
            rc == 0 ? "OK" : "CORRUPT", rc, en ? en : "-");
    }
    DIR *d = opendir(ESP_LINUX);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) if (e->d_name[0] != '.') out("esp: %s", e->d_name);
        closedir(d);
    } else {
        out("esp: %s not readable (%s)", ESP_LINUX, strerror(errno));
    }
    out("END slots=%d verified=%d", slots, good);
    if (rep) {
        fclose(rep);
        rename("/run/foilbird-recovery/report.tmp", "/run/foilbird-recovery/report");
    }
    return 0;
}
