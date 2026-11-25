/* SPDX-License-Identifier: Apache-2.0
 * foil-var-epoch: key slots of the TPM-bound /var per PCR-signing epoch (docs/disk-encryption.md).
 * Run by foil-var-epoch@<op>-<version>.service, which the node agent starts over D-Bus; the agent passes only the
 * release version. Nothing it wrote is trusted: the staged release is copied into a private directory, its SHA256SUMS
 * is checked with the release key from /usr (verity) and the UKI against it; key and epoch come from that copy.
 *
 *   enroll-<v>  staged release <v> (/var/lib/foil-agent/staging/current): add a TPM2 slot for its PCR key, if its epoch
 *               is newer than the booted one. Idempotent.
 *   raise-<v>   booted release <v>, committed (/var/lib/foilbird/committed/<v>): wipe the TPM2 slots of the PCR keys of
 *               older epochs and of keys of unknown epoch (enroll records every key before its slot, so an unknown key
 *               was not enrolled by us), then write /var/lib/foilbird/min_version = FOILBIRD_MIN_VERSION of the booted
 *               release. Slots of newer epochs (enrolled for a staged release) stay. Idempotent.
 *   sync-booted at every boot after /var is open: remove orphaned tokens, finish an interrupted enroll, write
 *               var-epochs. Wipes no slot of a finished enroll; unknown TPM2 slots are reported, not wiped.
 * Every run rewrites /run/foilbird/var-epoch/slots (read by the agent): what is outside the wanted set and what this run
 * removed. Slots without a token (a password, a recovery key) are only reported, until ADR 0010 marks the recovery slot.
 * Intent journal: systemd-cryptenroll adds the keyslot first and the token second; enroll first writes
 * /var/lib/foilbird/enrolling (epoch, key slots before). A run that finds it wipes every tokenless slot not listed there
 * (the keyslot of the interrupted enroll), then removes the journal.
 *   stage-<v>   for foil-install@<v>: copy the staged release out of the agent's reach into
 *               /var/lib/foilbird/staged/<v>, check the copy (signature, every file listed with its hash, UKI version) and
 *               the floor (<v> >= max(/var/lib/foilbird/min_version, booted FOILBIRD_MIN_VERSION)); the installer installs the copy.
 * Declarative: the wanted set is {TPM2 slots of epochs >= the booted one} plus every slot that is not a TPM2 slot
 * (recovery). enroll, raise and sync first bring the header to it as far as it is safe: systemd-tpm2 tokens without a
 * live key slot (a power loss inside a wipe) are removed; the slot /var was opened with is never wiped (only the
 * booted key can open it: the booted UKI signs PCR 11 with its own key only). They finish by writing
 * /var/lib/foilbird/var-epochs (epochs with a working slot) and /run/foilbird/var-epoch/<op>-<v>.result.
 * A /var that is not LUKS2 is not an error: nothing to do, exit 0.
 * No shell: helpers (cryptsetup, systemd-cryptenroll, gpg, sha256sum) are run with fork/exec. */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEV "/dev/disk/by-partlabel/var"
#define ST "/var/lib/foilbird"
#define KEYS ST "/epoch-keys"
#define STAGING "/var/lib/foil-agent/staging/current"
#define STAGED ST "/staged"
#define KEYRING "/usr/lib/systemd/import-pubring.gpg"
#define OWNKEY "/usr/lib/foilbird/pcr-key.pem"
#define OSREL "/usr/lib/os-release"
#define RESDIR "/run/foilbird/var-epoch"
#define MAXTOK 32
#define ESP_LINUX "/boot/EFI/Linux"   /* installed UKIs (automount) */
#define UKI_PREFIX "foilbird-deb_"      /* ImageId_ (mkosi.conf, 70-uki-name.conf) */
/* Policy of our TPM2 slots: what enroll passes to systemd-cryptenroll and what raise requires of the token
   it keeps, in one place. foil-repart.service (first boot) enrolls with the same values; keep them equal. The PCR bank is
   neither passed nor compared: systemd picks it per TPM (sha256 where active), and a fixed bank would turn every node with
   another active bank into a CRITICAL report. */
#define ENROLL_PCRS "7"
#define ENROLL_PUBKEY_PCRS "11"

static char op[16], ver[64], resfile[PATH_MAX], tmpdir[PATH_MAX];
static void write_report(void);
static int g_report;   /* tokens loaded: result() also writes RESDIR/slots */
static int g_probe;    /* a child checking the staged release for raise; result() only exits, non-zero */
static char g_own[2048]; static long g_booted;   /* the booted PCR key (body) and epoch, once read */
static char g_staged_key[2048], g_staged_ver[64]; static long g_staged_ep = -1;   /* the verified staged release */
static int g_staged_ok;   /* staging/current verified (any epoch); its key is kept only above the booted epoch */

static void say(const char *fmt, ...) {
  va_list a; va_start(a, fmt); fputs("foil-var-epoch: ", stdout); vprintf(fmt, a); putchar('\n'); va_end(a); fflush(stdout);
}
static void result(const char *res, const char *fmt, ...) { /* one line for the agent, then exit */
  char d[1024]; va_list a; va_start(a, fmt); vsnprintf(d, sizeof d, fmt, a); va_end(a);
  if (g_probe) { say("staged release check: %s: %s", res, d); _exit(strcmp(res, "ok") ? 1 : 0); }
  say("%s: %s", res, d);
  mkdir("/run/foilbird", 0755); mkdir(RESDIR, 0755);
  FILE *f = fopen(resfile, "w");
  if (f) { fprintf(f, "result=%s\ndetail=%s\n", res, d); fclose(f); }
  if (g_report) write_report();
  if (tmpdir[0]) { char *argv[] = {"/usr/bin/rm", "-rf", "--", tmpdir, NULL}; pid_t p = fork();
    if (p == 0) { execv(argv[0], argv); _exit(127); } if (p > 0) waitpid(p, NULL, 0); }
  exit(strcmp(res, "error") && strcmp(res, "refused") ? 0 : 1);
}

/* run argv; stdout captured into *out (NUL-terminated, malloc'd) unless out is NULL; stderr goes to the journal */
static int run(char *const argv[], char **out) {
  int fd[2]; if (out && pipe(fd)) return -1;
  pid_t p = fork(); if (p < 0) return -1;
  if (p == 0) {
    if (out) { dup2(fd[1], 1); close(fd[0]); close(fd[1]); }
    execv(argv[0], argv); _exit(127);
  }
  if (out) {
    close(fd[1]); size_t n = 0, cap = 8192; char *b = malloc(cap); ssize_t r;
    while ((r = read(fd[0], b + n, cap - n - 1)) > 0) { n += r; if (cap - n < 4096) b = realloc(b, cap *= 2); }
    close(fd[0]); b[n] = 0; *out = b;
  }
  int st; if (waitpid(p, &st, 0) < 0) return -1;
  return WIFEXITED(st) ? WEXITSTATUS(st) : 128;
}

static char *read_file(const char *path, size_t *len) {
  int fd = open(path, O_RDONLY | O_CLOEXEC); if (fd < 0) return NULL;
  struct stat s; if (fstat(fd, &s) || !S_ISREG(s.st_mode)) { close(fd); return NULL; }
  char *b = malloc(s.st_size + 1); size_t n = 0; ssize_t r;
  while (n < (size_t)s.st_size && (r = read(fd, b + n, s.st_size - n)) > 0) n += r;
  close(fd); if (n != (size_t)s.st_size) { free(b); return NULL; }
  b[n] = 0; if (len) *len = n; return b;
}
static int write_atomic(const char *path, const void *data, size_t len) { /* temp + fsync + rename + fsync dir */
  char t[PATH_MAX]; snprintf(t, sizeof t, "%s.tmp", path);
  int fd = open(t, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644); if (fd < 0) return -1;
  if (write(fd, data, len) != (ssize_t)len || fsync(fd)) { close(fd); unlink(t); return -1; }
  close(fd); if (rename(t, path)) { unlink(t); return -1; }
  char d[PATH_MAX]; snprintf(d, sizeof d, "%s", path); char *s = strrchr(d, '/'); if (s) *s = 0;
  int dfd = open(d, O_RDONLY | O_DIRECTORY | O_CLOEXEC); if (dfd >= 0) { fsync(dfd); close(dfd); }
  return 0;
}
static int copy_file(const char *from, const char *to) { size_t n; char *b = read_file(from, &n); if (!b) return -1;
  int r = write_atomic(to, b, n); free(b); return r; }

/* KEY=value from an os-release text (quotes stripped) */
static int osrel_get(const char *txt, const char *key, char *out, size_t sz) {
  size_t kl = strlen(key);
  for (const char *l = txt; l && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL) {
    if (!strncmp(l, key, kl) && l[kl] == '=') {
      const char *v = l + kl + 1, *e = strchr(v, '\n'); size_t n = e ? (size_t)(e - v) : strlen(v);
      if (n && (*v == '"' || *v == '\'')) { v++; n -= (n >= 2 && (v[n - 2] == '"' || v[n - 2] == '\'')) ? 2 : 1; }
      if (n >= sz) return -1;
      memcpy(out, v, n); out[n] = 0; return 0;
    }
  }
  return -1;
}
static int is_number(const char *s) { if (!*s || strlen(s) > 9) return 0; for (; *s; s++) if (!isdigit((unsigned char)*s)) return 0; return 1; }

/* PE/COFF section by name (UKI: .osrel, .pcrpkey) */
static char *pe_section(const unsigned char *b, size_t len, const char *name, size_t *out) {
  if (len < 0x40 || b[0] != 'M' || b[1] != 'Z') return NULL;
  uint32_t pe = b[0x3c] | b[0x3d] << 8 | b[0x3e] << 16 | (uint32_t)b[0x3f] << 24;
  if (pe > len - 24 || memcmp(b + pe, "PE\0\0", 4)) return NULL;
  unsigned ns = b[pe + 6] | b[pe + 7] << 8, opt = b[pe + 20] | b[pe + 21] << 8;
  size_t t = pe + 24 + opt;
  for (unsigned i = 0; i < ns; i++, t += 40) {
    if (t + 40 > len) return NULL;
    char n[9] = {0}; memcpy(n, b + t, 8);
    if (strcmp(n, name)) continue;
    uint32_t vs = *(uint32_t *)(b + t + 8), rs = *(uint32_t *)(b + t + 16), ro = *(uint32_t *)(b + t + 20);
    size_t s = vs && vs < rs ? vs : rs; if (ro > len || s > len - ro) return NULL;
    char *r = malloc(s + 1); memcpy(r, b + ro, s); r[s] = 0;
    while (s && r[s - 1] == 0) r[--s] = 0;
    *out = s; return r;
  }
  return NULL;
}

/* a PEM public key reduced to its base64 body (whitespace removed), for comparisons */
static void pem_body(const char *pem, char *out, size_t sz) {
  size_t n = 0; const char *p = strstr(pem, "-----BEGIN"); if (p) p = strchr(p, '\n'); if (!p) { *out = 0; return; }
  for (p++; *p && strncmp(p, "-----END", 8); p++) if (!isspace((unsigned char)*p) && n + 1 < sz) out[n++] = *p;
  out[n] = 0;
}
static int b64val(int c) { return c >= 'A' && c <= 'Z' ? c - 'A' : c >= 'a' && c <= 'z' ? c - 'a' + 26 : c >= '0' && c <= '9' ? c - '0' + 52 : c == '+' ? 62 : c == '/' ? 63 : -1; }
static size_t b64dec(const char *in, char *out, size_t sz) {
  size_t n = 0; unsigned acc = 0; int bits = 0;
  for (; *in && *in != '='; in++) { int v = b64val((unsigned char)*in); if (v < 0) continue;
    acc = acc << 6 | v; bits += 6; if (bits >= 8) { bits -= 8; if (n + 1 < sz) out[n++] = acc >> bits & 0xff; } }
  out[n] = 0; return n;
}

/* --- LUKS2 tokens */
struct tok { int id, nks, ks[8], ours; char key[2048]; };   /* ours: JSON policy = our enroll (tok_params_ours) */
static struct tok toks[MAXTOK]; static int ntok;
static int slots[64], nslots, refd[64], nrefd;   /* key slots; key slots named by any token (of any type) */
/* tokens of any other type: root can add one ("cryptsetup token import") to hide a slot from tokenless_slots */
static int ftok[MAXTOK], nftok, fref[64], nfref, fks[MAXTOK][8], nfks[MAXTOK];   /* fks: key slots per foreign token */
static char slot_salt[64][64];   /* first line of each key slot's Salt (luksDump), by slot number: identity for WIPING */

/* raw text of the value of a TOP-LEVEL "key" of a JSON object, spaces outside strings dropped; "" if absent. Top level only:
   root writes the token JSON and could put a nested {"tpm2-pcrs":[7]} before the real key; systemd reads the top level.
   cryptsetup re-serializes token JSON through json-c, so a key occurs once per object. */
static void json_raw(const char *j, const char *key, char *out, size_t sz) {
  out[0] = 0; int d = 0; size_t kl = strlen(key);
  for (const char *p = j; *p; p++) {
    if (*p == '"') {   /* a string: at depth 1 followed by ':' it is a top-level key */
      const char *st = ++p; while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
      if (!*p) return;
      const char *q = p + 1; while (isspace((unsigned char)*q)) q++;
      if (d == 1 && *q == ':' && (size_t)(p - st) == kl && !strncmp(st, key, kl)) {
        size_t o = 0; int dd = 0, in = 0;
        for (q++; *q && o + 1 < sz; q++) {
          if (in) { out[o++] = *q; if (*q == '\\' && q[1] && o + 1 < sz) out[o++] = *++q; else if (*q == '"') in = 0; continue; }
          if (*q == '"') in = 1;
          else if (*q == '[' || *q == '{') dd++;
          else if (*q == ']' || *q == '}') { if (!dd) break; dd--; }
          else if (*q == ',' && !dd) break;
          if (!isspace((unsigned char)*q)) out[o++] = *q;
        }
        out[o] = 0; return;
      }
      continue;
    }
    if (*p == '{' || *p == '[') d++;
    else if (*p == '}' || *p == ']') d--;
  }
}
/* The JSON policy is what our enroll writes. The TPM test (tok_opens) proves the blob matches its JSON (the plugin
   builds the policy session from the JSON); this proves the JSON is ours: PCR 7 bound, pubkey on PCR 11, no PIN/pcrlock (bank: see ENROLL_PCRS). */
static int tok_params_ours(const char *j) {
  char v[64];
  json_raw(j, "tpm2-pcrs", v, sizeof v); if (strcmp(v, "[" ENROLL_PCRS "]")) return 0;
  json_raw(j, "tpm2_pubkey_pcrs", v, sizeof v); if (strcmp(v, "[" ENROLL_PUBKEY_PCRS "]")) return 0;
  json_raw(j, "tpm2-pin", v, sizeof v); if (*v && strcmp(v, "false")) return 0;
  json_raw(j, "tpm2_pcrlock", v, sizeof v); if (*v && strcmp(v, "false")) return 0;
  return 1;
}

static int load_tokens(void) {
  char *d = NULL; char *a1[] = {"/usr/sbin/cryptsetup", "luksDump", DEV, NULL};
  if (run(a1, &d)) { free(d); return -1; }
  ntok = nslots = nrefd = nftok = nfref = 0; int sec = 0, cur_foreign = 0, cur_slot = -1;
  memset(slot_salt, 0, sizeof slot_salt);
  for (char *l = strtok(d, "\n"); l; l = strtok(NULL, "\n")) {
    if (!strncmp(l, "Keyslots:", 9)) { sec = 1; continue; }
    if (!strncmp(l, "Tokens:", 7)) { sec = 2; continue; }
    if (!isspace((unsigned char)*l)) { sec = 0; continue; }
    int id; char type[64];
    if (sec == 2 && sscanf(l, " Keyslot: %d", &id) == 1) {
      if (nrefd < 64) refd[nrefd++] = id;
      if (cur_foreign && nfref < 64) fref[nfref++] = id;
      if (cur_foreign && nftok && nfks[nftok - 1] < 8) fks[nftok - 1][nfks[nftok - 1]++] = id;
      continue; }
    if (sec == 1 && cur_slot >= 0 && cur_slot < 64 && !slot_salt[cur_slot][0] && !strncmp(l, "\tSalt:", 6)) {
      size_t o = 0; for (const char *q = l + 6; *q && o + 1 < sizeof slot_salt[0]; q++) if (isxdigit((unsigned char)*q)) slot_salt[cur_slot][o++] = *q;
      continue; }
    if (l[0] != ' ' || l[1] != ' ' || !isdigit((unsigned char)l[2]) || sscanf(l, " %d: %63s", &id, type) != 2) continue;
    if (sec == 1 && nslots < 64) { slots[nslots++] = id; cur_slot = id; }   /* "  <n>: luks2"; detail lines start with a tab */
    if (sec == 2) { cur_foreign = strcmp(type, "systemd-tpm2") != 0;
      if (!cur_foreign && ntok < MAXTOK) toks[ntok++].id = id;
      if (cur_foreign && nftok < MAXTOK) { nfks[nftok] = 0; ftok[nftok++] = id; } }
  }
  free(d);
  for (int i = 0; i < ntok; i++) {
    char ids[16], *j = NULL; snprintf(ids, sizeof ids, "%d", toks[i].id);
    char *a2[] = {"/usr/sbin/cryptsetup", "token", "export", "--token-id", ids, DEV, NULL};
    if (run(a2, &j)) { free(j); return -1; }
    toks[i].nks = 0; toks[i].key[0] = 0; toks[i].ours = tok_params_ours(j);
    char v[4096];   /* top-level keys only (json_raw): what systemd reads */
    json_raw(j, "keyslots", v, sizeof v);
    for (char *p = v; *p && toks[i].nks < 8; p++)
      if (isdigit((unsigned char)*p)) { toks[i].ks[toks[i].nks++] = (int)strtol(p, &p, 10); p--; }
    json_raw(j, "tpm2_pubkey", v, sizeof v);
    if (v[0] == '"') { char *e = strchr(v + 1, '"'); if (e) { *e = 0; char pem[4096]; b64dec(v + 1, pem, sizeof pem); pem_body(pem, toks[i].key, sizeof toks[i].key); } }
    free(j);
  }
  return 0;
}
static int in_list(const int *l, int n, int v) { for (int i = 0; i < n; i++) if (l[i] == v) return 1; return 0; }
static int slot_tokenless(int s) { return !in_list(refd, nrefd, s); }
static int rep_orph[MAXTOK], nrep_orph, rep_intr[64], nrep_intr, rep_wiped[64], nrep_wiped;   /* removed by this run */
static int rep_xwiped[64], nrep_xwiped, rep_rmtok[MAXTOK], nrep_rmtok;   /* raise: extra slots wiped, tokens removed */
static int slot_exists(int s) { for (int i = 0; i < nslots; i++) if (slots[i] == s) return 1; return 0; }
static int token_live(const struct tok *t) { for (int i = 0; i < t->nks; i++) if (slot_exists(t->ks[i])) return 1; return 0; }
static const struct tok *token_for_key(const char *body) {
  for (int i = 0; i < ntok; i++) if (*body && !strcmp(toks[i].key, body) && token_live(&toks[i])) return &toks[i];
  return NULL;
}

/* a token without a live key slot can never open /var; removing it changes no slot */
static int remove_orphans(void) {
  int n = 0;
  for (int i = 0; i < ntok; i++) if (!token_live(&toks[i])) {
    char ids[16]; snprintf(ids, sizeof ids, "%d", toks[i].id);
    char *a[] = {"/usr/sbin/cryptsetup", "token", "remove", "--token-id", ids, DEV, NULL};
    int rc = run(a, NULL);
    say("token %d is a systemd-tpm2 token without a key slot (left by an interrupted wipe): remove rc=%d", toks[i].id, rc);
    if (!rc && nrep_orph < MAXTOK) rep_orph[nrep_orph++] = toks[i].id;
    n++;
  }
  if (load_tokens()) result("error", "cannot read the LUKS2 header of " DEV);
  return n;
}

/* does the TPM open /var through token <id> (and, if slot >= 0, through that key slot)? Read-only test, no activation */
static int tok_opens(int id, int slot) {
  char ids[16], ks[16]; snprintf(ids, sizeof ids, "%d", id); snprintf(ks, sizeof ks, "%d", slot);
  char *a[] = {"/usr/sbin/cryptsetup", "open", "--test-passphrase", "--token-only", "--token-id", ids,
               slot >= 0 ? "--key-slot" : DEV, slot >= 0 ? ks : NULL, slot >= 0 ? DEV : NULL, NULL};
  return run(a, NULL) == 0;
}
static int token_unassign(int id, int slot) {
  char ids[16], ks[16]; snprintf(ids, sizeof ids, "%d", id); snprintf(ks, sizeof ks, "%d", slot);
  char *a[] = {"/usr/sbin/cryptsetup", "token", "unassign", "--token-id", ids, "--key-slot", ks, DEV, NULL};
  return run(a, NULL);
}
static int wipe_slots(const int *l, int n) {   /* systemd-cryptenroll --wipe-slot=a,b; then the header is re-read */
  if (!n) return 0;
  char w[300] = "--wipe-slot="; size_t o = strlen(w);
  for (int i = 0; i < n; i++) o += snprintf(w + o, sizeof w - o, "%s%d", i ? "," : "", l[i]);
  char *wa[] = {"/usr/bin/systemd-cryptenroll", w, DEV, NULL};
  int rc = run(wa, NULL); if (load_tokens()) result("error", "cannot read the LUKS2 header of " DEV);
  return rc;
}

/* --- intent journal of enroll: "epoch=<E>\nslots=<a,b,...>\n" */
#define ENROLLING ST "/enrolling"
static void fsync_dir(const char *d) { int fd = open(d, O_RDONLY | O_DIRECTORY | O_CLOEXEC); if (fd >= 0) { fsync(fd); close(fd); } }
static void journal_write(long epoch) {
  char b[512]; size_t o = snprintf(b, sizeof b, "epoch=%ld\nslots=", epoch);
  for (int i = 0; i < nslots; i++) o += snprintf(b + o, sizeof b - o, "%s%d", i ? "," : "", slots[i]);
  snprintf(b + o, sizeof b - o, "\n");
  if (write_atomic(ENROLLING, b, strlen(b))) result("error", "cannot write " ENROLLING ": %m");
}
static void journal_drop(void) { if (unlink(ENROLLING) == 0) fsync_dir(ST); }
/* an enroll cut between its keyslot and its token left a tokenless keyslot that was not there before: wipe it */
static void recover_enrolling(void) {
  char *j = read_file(ENROLLING, NULL); if (!j) return;
  int before[64], nb = 0; char *l = strstr(j, "slots=");
  if (!l) { free(j); say(ENROLLING " unreadable, dropped"); journal_drop(); return; }
  for (char *q = l + 6; *q && *q != '\n'; q++) if (isdigit((unsigned char)*q) && nb < 64) { before[nb++] = (int)strtol(q, &q, 10); q--; }
  free(j);
  int w[64], nw = 0;
  for (int k = 0; k < nslots; k++) if (slot_tokenless(slots[k]) && !in_list(before, nb, slots[k])) w[nw++] = slots[k];
  if (nw) {
    int rc = wipe_slots(w, nw);
    for (int k = 0; k < nw; k++) if (slot_exists(w[k])) result("error", "interrupted enroll: wipe of key slot %d failed rc=%d, " ENROLLING " kept", w[k], rc);
    for (int k = 0; k < nw && nrep_intr < 64; k++) rep_intr[nrep_intr++] = w[k];
    say("interrupted enroll: wiped tokenless key slot(s) it had added (%d), rc=%d", nw, rc);
  } else say("interrupted enroll: no tokenless key slot added by it");
  journal_drop();
}

/* intent journal of raise's wipes: "slot=<n> salt=<hex>" per key slot it is about to wipe, written before the first
   token unassign. systemd-cryptenroll --wipe-slot drops every token naming a wiped slot, and with it that token's other
   slots (cryptenroll-wipe.c find_slot_tokens: keep_slots is empty in a wipe-only run), so before the wipe every token is
   made to name either only slots being wiped or none of them (prepare_wipe). The order cannot be wipe-then-unassign:
   libcryptsetup does not write a header whose token names a missing key slot (LUKS2_token_validate ->
   validate_keyslots_array), and cryptsetup luksKillSlot, which unassigns and wipes in one header write, wants another
   slot's passphrase when stdin is not a tty (cryptsetup.c action_luksKillSlot). A cut after an unassign can leave a slot
   being wiped tokenless (reported, never wiped otherwise); the next run wipes the listed slots that still exist, are
   tokenless and have the same salt (a slot number freed by the wipe and reused before that run is not touched). Slots
   that a cut leaves under a token (a fake token keeps its others) are not covered: the next raise wipes them again. */
#define WIPING ST "/wiping"
static void wiping_write(const int *l, int n) {
  char b[64 * 90]; size_t o = 0;
  for (int i = 0; i < n && o < sizeof b; i++) o += snprintf(b + o, sizeof b - o, "slot=%d salt=%s\n", l[i], l[i] >= 0 && l[i] < 64 ? slot_salt[l[i]] : "");
  if (write_atomic(WIPING, b, strlen(b))) result("error", "cannot write " WIPING ": %m");
}
static void wiping_drop(void) { if (unlink(WIPING) == 0) fsync_dir(ST); }
static void recover_wiping(void) {
  char *j = read_file(WIPING, NULL); if (!j) return;
  int w[64], nw = 0, n; char salt[64];
  for (char *l = strtok(j, "\n"); l; l = strtok(NULL, "\n")) {
    salt[0] = 0;
    if (sscanf(l, "slot=%d salt=%63[0-9a-f]", &n, salt) < 1 || n < 0 || n >= 64) continue;
    if (!slot_exists(n)) continue;
    if (!slot_tokenless(n)) { say("interrupted raise: journaled key slot %d is still named by a token, kept (the next raise wipes it again)", n); continue; }
    if (!salt[0] || strcmp(salt, slot_salt[n])) { say("interrupted raise: key slot %d is tokenless but not the one journaled (salt differs): kept", n); continue; }
    if (nw < 64) w[nw++] = n; }
  free(j);
  if (nw) {
    int rc = wipe_slots(w, nw);
    for (int k = 0; k < nw; k++) { if (slot_exists(w[k])) result("error", "interrupted raise: wipe of key slot %d failed rc=%d, " WIPING " kept", w[k], rc);
      if (nrep_xwiped < 64) rep_xwiped[nrep_xwiped++] = w[k]; }
    say("interrupted raise: wiped %d journaled key slot(s) left tokenless", nw);
  }
  wiping_drop();
}
#ifdef FOILBIRD_VAR_EPOCH_LAB
/* Lab builds only: "raise-after-unassign" in /run/foilbird-lab/crash resets the machine right after prepare_wipe, between
   raise's unassigns and its wipe, in whichever stage wipes first (older epochs or the booted epoch's reconciliation):
   an unassigned slot can then be tokenless, and only the WIPING journal gets it wiped by the next run. */
static void lab_crash_after_unassign(void) {
  char *c = read_file("/run/foilbird-lab/crash", NULL);
  if (!c || strncmp(c, "raise-after-unassign", 20)) { free(c); return; }
  free(c); say("LAB: hard reset between unassign and wipe (journal " WIPING " stays)");
  sync(); int fd = open("/proc/sysrq-trigger", O_WRONLY); if (fd >= 0) { if (write(fd, "b", 1) < 0) {} close(fd); }
  pause();
}
#endif
/* is key slot sl named by a kept systemd-tpm2 token of the BOOTED key (outside t, the tokens being removed)? Such a slot is
   not wiped with t (root adding our slot to an old token). A token of another type proves nothing (root writes
   any JSON: "cryptsetup token import"), so it does not protect; prepare_wipe unassigns the slot from it, then it is wiped.
   Nor does a token of another kept key (the verified staged release's): its pubkey is public, root can write a token
   with it that names an old epoch's slot, and the TPM cannot test it before that release boots. A slot that root also put
   under an old token is then wiped with it; that only costs the staged release its slot (enroll makes it again). */
static int named_by_kept(int sl, const int *t, int nt) {
  for (int j = 0; j < ntok; j++)
    if (!in_list(t, nt, toks[j].id) && !strcmp(toks[j].key, g_own) && in_list(toks[j].ks, toks[j].nks, sl)) return 1;
  return 0;
}
/* before wipe_slots(w): a token in t (being removed) keeps only slots in w, every other token (any type) none of them, so
   that systemd-cryptenroll's token cascade removes exactly the tokens in t and wipes exactly w. Journal first. */
static void prepare_wipe(const int *w, int nw, const int *t, int nt) {
  for (int i = 0; i < ntok; i++) { int drop = in_list(t, nt, toks[i].id);
    for (int k = 0; k < toks[i].nks; k++) { int sl = toks[i].ks[k];
      if (!slot_exists(sl) || in_list(w, nw, sl) == drop) continue;
      say("token %d: unassign key slot %d (%s)", toks[i].id, sl, drop ? "not wiped: kept for the token that owns it" : "wiped: the token stays");
      if (token_unassign(toks[i].id, sl)) result("error", "cannot unassign key slot %d from token %d", sl, toks[i].id); } }
  for (int i = 0; i < nftok; i++) for (int k = 0; k < nfks[i]; k++) { int sl = fks[i][k];
    if (!slot_exists(sl) || !in_list(w, nw, sl)) continue;
    say("token %d (another type): unassign key slot %d (wiped: the token stays)", ftok[i], sl);
    if (token_unassign(ftok[i], sl)) result("error", "cannot unassign key slot %d from token %d", sl, ftok[i]); }
  if (load_tokens()) result("error", "cannot read the LUKS2 header of " DEV);
#ifdef FOILBIRD_VAR_EPOCH_LAB
  if (nw) lab_crash_after_unassign();
#endif
}

/* epoch of a key body: own key -> booted epoch, else /var/lib/foilbird/epoch-keys/<E>.pem; -1 unknown */
static long epoch_of(const char *body, const char *own, long booted) {
  if (!strcmp(body, own)) return booted;
  DIR *d = opendir(KEYS); if (!d) return -1; struct dirent *e; long r = -1;
  while ((e = readdir(d))) {
    char n[256], p[PATH_MAX]; snprintf(n, sizeof n, "%s", e->d_name); char *dot = strstr(n, ".pem");
    if (!dot || dot[4]) continue;
    *dot = 0;
    if (!is_number(n)) continue;
    snprintf(p, sizeof p, KEYS "/%s.pem", n); char *t = read_file(p, NULL); if (!t) continue;
    char b[2048]; pem_body(t, b, sizeof b); free(t); if (!strcmp(b, body)) { r = atol(n); break; }
  }
  closedir(d); return r;
}
static int cmpint(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }
static size_t emit(char *b, size_t o, size_t sz, const char *key, int *l, int n) {   /* key=a,b,c ascending */
  qsort(l, n, sizeof *l, cmpint); o += snprintf(b + o, sz - o, "%s=", key);
  for (int i = 0; i < n; i++) o += snprintf(b + o, sz - o, "%s%d", i ? "," : "", l[i]);
  return o + snprintf(b + o, sz - o, "\n");
}
/* epoch-keys/ is a cache under /var that root can edit; it decides nothing, but what does not fit is reported: a key
   body under two epochs, or an epoch above both the booted one and the staged release's (verified in this run by raise or
   enroll; otherwise read from the staged UKI without a signature check: the report only). */
static long staged_epoch_hint(void) {
  if (g_staged_ep >= 0) return g_staged_ep;
  char src[PATH_MAX], u[PATH_MAX + 320]; if (!realpath(STAGING, src)) return -1;
  const char *b = strrchr(src, '/'); int r = snprintf(u, sizeof u, "%s/" UKI_PREFIX "%s.efi", src, b ? b + 1 : src);
  if (r < 0 || (size_t)r >= sizeof u) return -1;
  size_t n, sl; unsigned char *img = (unsigned char *)read_file(u, &n); if (!img) return -1;
  char *o = pe_section(img, n, ".osrel", &sl), se[16]; free(img); long e = -1;
  if (o && !osrel_get(o, "FOILBIRD_PCR_EPOCH", se, sizeof se) && is_number(se)) e = atol(se);
  free(o); return e;
}
static int epoch_keys_suspect(int *out, int max) {
  long ep[64]; char body[64][2048]; int n = 0, no = 0;
  DIR *d = opendir(KEYS); if (!d) return 0; struct dirent *e;
  while ((e = readdir(d)) && n < 64) {
    char nm[256], p[PATH_MAX]; snprintf(nm, sizeof nm, "%s", e->d_name); char *dot = strstr(nm, ".pem");
    if (!dot || dot[4]) continue;
    *dot = 0; if (!is_number(nm)) continue;
    snprintf(p, sizeof p, KEYS "/%s.pem", nm); char *t = read_file(p, NULL); if (!t) continue;
    pem_body(t, body[n], sizeof body[n]); free(t); ep[n++] = atol(nm); }
  closedir(d);
  long hint = staged_epoch_hint(), top = hint > g_booted ? hint : g_booted;
  for (int i = 0; i < n; i++) {
    int bad = ep[i] > top;
    for (int j = 0; j < n && !bad; j++) bad = j != i && !strcmp(body[i], body[j]);
    if (bad && no < max) out[no++] = (int)ep[i]; }
  return no;
}
/* RESDIR/slots, rewritten by every run, read by the agent (the agent's report format): schema first, key=value lines,
   lists ascending, empty = none; the agent ignores unknown keys, so keys can be added without a new schema */
static void write_report(void) {
  char b[2048]; size_t o = 0; int u[64], nu = 0, t[64], nt = 0;
  for (int i = 0; i < ntok; i++) if (strcmp(toks[i].key, g_own) && epoch_of(toks[i].key, g_own, g_booted) < 0)
    for (int k = 0; k < toks[i].nks; k++) if (slot_exists(toks[i].ks[k]) && nu < 64) u[nu++] = toks[i].ks[k];
  for (int k = 0; k < nslots; k++) if (slot_tokenless(slots[k]) && nt < 64) t[nt++] = slots[k];
  o += snprintf(b + o, sizeof b - o, "schema=1\nop=%s-%s\ntime_unix=%lld\n", op, ver, (long long)time(NULL));
  o = emit(b, o, sizeof b, "unknown_tpm2_slots", u, nu);
  o = emit(b, o, sizeof b, "wiped_unknown_slots", rep_wiped, nrep_wiped);
  o = emit(b, o, sizeof b, "tokenless_slots", t, nt);
  o = emit(b, o, sizeof b, "interrupted_enroll_removed", rep_intr, nrep_intr);
  o = emit(b, o, sizeof b, "orphan_tokens_removed", rep_orph, nrep_orph);
  /* appended (schema 1: readers ignore unknown keys). Expected: per known epoch exactly one systemd-tpm2 token with
     exactly one key slot; everything else is reported */
  int ft[MAXTOK], nf = 0, fs[64], nfs = 0, bt[MAXTOK], nbt = 0, dt[MAXTOK], ndt = 0;
  for (int i = 0; i < nftok; i++) ft[nf++] = ftok[i];
  for (int i = 0; i < nfref; i++) if (slot_exists(fref[i]) && !in_list(fs, nfs, fref[i])) fs[nfs++] = fref[i];
  for (int i = 0; i < ntok; i++) {
    if (toks[i].nks != 1 || !toks[i].ours) bt[nbt++] = toks[i].id;   /* or a policy other than our enroll's */
    long e = strcmp(toks[i].key, g_own) ? epoch_of(toks[i].key, g_own, g_booted) : g_booted;
    if (e < 0) continue;
    for (int j = 0; j < i; j++) { long f = strcmp(toks[j].key, g_own) ? epoch_of(toks[j].key, g_own, g_booted) : g_booted;
      if (f == e) { dt[ndt++] = toks[i].id; break; } }
  }
  o = emit(b, o, sizeof b, "foreign_tokens", ft, nf);
  o = emit(b, o, sizeof b, "foreign_token_slots", fs, nfs);
  o = emit(b, o, sizeof b, "tpm2_bad_tokens", bt, nbt);
  o = emit(b, o, sizeof b, "duplicate_epoch_tokens", dt, ndt);
  o = emit(b, o, sizeof b, "wiped_extra_slots", rep_xwiped, nrep_xwiped);
  o = emit(b, o, sizeof b, "removed_tokens", rep_rmtok, nrep_rmtok);
  int sk[64], nsk = epoch_keys_suspect(sk, 64);
  o = emit(b, o, sizeof b, "epoch_keys_suspect", sk, nsk);
  for (int k = 0; k < nf; k++) say("token %d (not systemd-tpm2): reported, kept", ft[k]);   /* not "token: <word>": the agent journal masks it */
  for (int k = 0; k < nfs; k++) say("key slot %d belongs to a token of another type: reported, kept", fs[k]);
  for (int k = 0; k < nbt; k++) say("token %d: systemd-tpm2 token without exactly one key slot or with another policy than ours: reported", bt[k]);
  for (int k = 0; k < ndt; k++) say("token %d: a second systemd-tpm2 token for the same epoch: reported", dt[k]);
  for (int k = 0; k < nsk; k++) say(KEYS "/%d.pem: same key as another epoch, or above the booted and staged epochs (unsigned cache): reported", sk[k]);
  mkdir("/run/foilbird", 0755); mkdir(RESDIR, 0755);
  if (write_atomic(RESDIR "/slots", b, o)) say("cannot write " RESDIR "/slots: %m");
  for (int k = 0; k < nt; k++) say("key slot %d has no token (password or recovery, not ours): reported, kept", t[k]);
  for (int k = 0; k < nu; k++) say("key slot %d: TPM2 slot of a key of unknown epoch: reported%s", u[k], strcmp(op, "raise") ? ", kept (only raise wipes)" : "");
}

static void write_epochs(const char *own, long booted) {
  long ep[MAXTOK]; int n = 0;
  for (int i = 0; i < ntok; i++) {
    if (!token_live(&toks[i])) continue;
    long e = epoch_of(toks[i].key, own, booted);
    if (e < 0) { say("token %d: slot of an unknown PCR key (not listed in var-epochs)", toks[i].id); continue; }
    int dup = 0; for (int k = 0; k < n; k++) dup |= ep[k] == e; if (!dup) ep[n++] = e;
  }
  for (int a = 0; a < n; a++) for (int b = a + 1; b < n; b++) if (ep[b] < ep[a]) { long t = ep[a]; ep[a] = ep[b]; ep[b] = t; }
  char line[512] = ""; size_t l = 0;
  for (int k = 0; k < n; k++) l += snprintf(line + l, sizeof line - l, "%s%ld", k ? " " : "", ep[k]);
  snprintf(line + l, sizeof line - l, "\n");
  if (write_atomic(ST "/var-epochs", line, strlen(line))) say("cannot write " ST "/var-epochs: %m");
  else say("var-epochs: %.*s", (int)strlen(line) - 1, line);
}

/* --- signed release manifest. The agent leaves the channel's SHA256SUMS(.gpg) unchanged (signed, so it cannot be
   trimmed); the channel may hold several releases. Only the line of a given file name counts, exactly one of it. */
static void make_tmpdir(void) {
  if (tmpdir[0]) return;
  snprintf(tmpdir, sizeof tmpdir, "/run/foil-var-epoch.XXXXXX"); if (!mkdtemp(tmpdir)) result("error", "mkdtemp: %m");
}
static void sums_verify(const char *sums, const char *sig) { /* signature by the release key from /usr */
  make_tmpdir();
  /* a private copy of the keyring, as systemd-sysupdate does; no --import (it would start gpg-agent, not in the image) */
  char home[PATH_MAX + 16], ring[PATH_MAX + 32]; snprintf(home, sizeof home, "%s/gnupg", tmpdir); mkdir(home, 0700);
  snprintf(ring, sizeof ring, "%s/pubring.gpg", home);
  if (copy_file(KEYRING, ring)) result("error", "cannot read the release keyring " KEYRING);
  char kopt[PATH_MAX + 48]; snprintf(kopt, sizeof kopt, "--keyring=%s", ring);
  char *st = NULL; char *gv[] = {"/usr/bin/gpg", "--no-options", "--no-default-keyring", "--no-auto-key-locate",
    "--no-auto-check-trustdb", "--batch", "--trust-model=always", "--homedir", home, kopt, "--status-fd", "1",
    "--verify", (char *)sig, (char *)sums, NULL};
  int rc = run(gv, &st); int ok = rc == 0 && st && strstr(st, "[GNUPG:] VALIDSIG "); free(st);
  if (!ok) result("refused", "SHA256SUMS signature does not verify with the release key (gpg rc=%d)", rc);
}
static int sums_lookup(const char *sums_txt, const char *name, char hash[65]) { /* 1 found once, 0 absent, -1 twice */
  int n = 0; size_t nl = strlen(name);
  for (const char *l = sums_txt; l && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL) {
    const char *sp = strchr(l, ' '); const char *e = strchr(l, '\n'); if (!e) e = l + strlen(l);
    if (!sp || sp - l != 64 || sp > e) continue;
    const char *f = sp; while (f < e && *f == ' ') f++; if (f < e && *f == '*') f++;
    if ((size_t)(e - f) == nl && !strncmp(f, name, nl)) { if (n++) return -1; memcpy(hash, l, 64); hash[64] = 0; }
  }
  return n;
}
static int file_sha256(const char *path, char out[65]) {
  char *h = NULL; char *sh[] = {"/usr/bin/sha256sum", (char *)path, NULL};
  int ok = run(sh, &h) == 0 && h && strlen(h) >= 64; if (ok) { memcpy(out, h, 64); out[64] = 0; } free(h); return ok ? 0 : -1;
}
static void check_listed(const char *sums_txt, const char *name, const char *path) {
  char want[65], got[65]; int r = sums_lookup(sums_txt, name, want);
  if (r == 0) result("refused", "%s is not listed in SHA256SUMS", name);
  if (r < 0) result("refused", "SHA256SUMS lists %s more than once", name);
  if (file_sha256(path, got) || strcmp(want, got)) result("refused", "%s does not match SHA256SUMS", name);
}

/* --- enroll: private copy of manifest + UKI of release <ver>, verified; key and .osrel from the copy */
static void verify_staged(const char *v, char *osrel_out, size_t osz, char *keyfile, size_t ksz) {
  char src[PATH_MAX]; if (!realpath(STAGING, src)) result("refused", "no staged release at " STAGING);
  make_tmpdir();
  char a[PATH_MAX + 64], b[PATH_MAX + 64], g[PATH_MAX + 64], u[PATH_MAX + 16], uki[300];
  snprintf(a, sizeof a, "%s/SHA256SUMS", src); snprintf(b, sizeof b, "%s/SHA256SUMS", tmpdir);
  if (copy_file(a, b)) result("refused", "staged release has no SHA256SUMS");
  snprintf(a, sizeof a, "%s/SHA256SUMS.gpg", src); snprintf(g, sizeof g, "%s/SHA256SUMS.gpg", tmpdir);
  if (copy_file(a, g)) result("refused", "staged release has no SHA256SUMS.gpg");
  sums_verify(b, g);
  snprintf(uki, sizeof uki, "foilbird-deb_%s.efi", v);
  snprintf(a, sizeof a, "%s/%s", src, uki); snprintf(u, sizeof u, "%s/uki.efi", tmpdir);
  if (copy_file(a, u)) result("refused", "staged release has no %s", uki);
  char *sums = read_file(b, NULL); check_listed(sums, uki, u); free(sums);   /* hash the copy, read only the copy */
  size_t n, sl; unsigned char *img = (unsigned char *)read_file(u, &n); if (!img) result("error", "cannot read the UKI copy");
  char *osrel = pe_section(img, n, ".osrel", &sl); char *pk = pe_section(img, n, ".pcrpkey", &sl); free(img);
  if (!osrel || !pk) result("refused", "%s has no .osrel or .pcrpkey section", uki);
  snprintf(osrel_out, osz, "%s", osrel); snprintf(keyfile, ksz, "%s/pcr-key.pem", tmpdir);
  if (write_atomic(keyfile, pk, strlen(pk))) result("error", "cannot write %s", keyfile);
  free(osrel); free(pk);
  say("staged %s verified: listed in SHA256SUMS signed by the release key", uki);
}

/* --- stage: copy (not move: the agent could keep a file open and write after the check), then check the copy */
static int copy_stream(const char *from, const char *to) {
  int in = open(from, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); if (in < 0) return -1;
  int out = open(to, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644); if (out < 0) { close(in); return -1; }
  static char buf[1 << 20]; ssize_t r; int rc = 0;
  while ((r = read(in, buf, sizeof buf)) > 0) { char *p = buf; while (r > 0) { ssize_t w = write(out, p, r); if (w <= 0) { rc = -1; break; } p += w; r -= w; } if (rc) break; }
  if (r < 0 || fsync(out)) rc = -1;
  close(in); close(out); return rc;
}
static void rm_rf(const char *path) { char *a[] = {"/usr/bin/rm", "-rf", "--", (char *)path, NULL}; run(a, NULL); }
static void stage(const char *osr) {
  char src[PATH_MAX], dst[PATH_MAX + 64], cur[PATH_MAX + 64], f[PATH_MAX + 320], t[PATH_MAX + 320];
  if (!realpath(STAGING, src) || strncmp(src, "/var/lib/foil-agent/staging/", 27)) result("refused", "no staged release at " STAGING);
  mkdir(ST, 0755); mkdir(STAGED, 0755);
  snprintf(dst, sizeof dst, STAGED "/%s", ver); snprintf(cur, sizeof cur, STAGED "/current");
  unlink(cur); rm_rf(dst); if (mkdir(dst, 0755)) result("error", "mkdir %s: %m", dst);
  DIR *d = opendir(src); if (!d) result("refused", "cannot open %s", src);
  struct dirent *e; int nf = 0;
  while ((e = readdir(d))) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
    struct stat st; snprintf(f, sizeof f, "%s/%s", src, e->d_name);
    if (lstat(f, &st) || !S_ISREG(st.st_mode)) { closedir(d); result("refused", "staged %s is not a regular file", e->d_name); }
    snprintf(t, sizeof t, "%s/%s", dst, e->d_name);
    if (copy_stream(f, t)) { closedir(d); result("error", "copy of %s: %m", e->d_name); }
    nf++;
  }
  closedir(d);
  snprintf(f, sizeof f, "%s/SHA256SUMS", dst); snprintf(t, sizeof t, "%s/SHA256SUMS.gpg", dst);
  if (access(f, F_OK) || access(t, F_OK)) result("refused", "staged release lacks SHA256SUMS or SHA256SUMS.gpg");
  sums_verify(f, t);
  char *sums = read_file(f, NULL);
  d = opendir(dst); int nc = 0;
  while ((e = readdir(d))) {   /* every file of the copy must be listed, with its hash; other lines are other releases */
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..") || !strcmp(e->d_name, "SHA256SUMS") || !strcmp(e->d_name, "SHA256SUMS.gpg")) continue;
    snprintf(t, sizeof t, "%s/%s", dst, e->d_name); check_listed(sums, e->d_name, t); nc++;
  }
  closedir(d); free(sums);
  char uki[300]; snprintf(uki, sizeof uki, "foilbird-deb_%s.efi", ver); snprintf(t, sizeof t, "%s/%s", dst, uki);
  size_t n, sl; unsigned char *img = (unsigned char *)read_file(t, &n);
  if (!img) result("refused", "staged release has no %s", uki);
  char *osrel = pe_section(img, n, ".osrel", &sl); free(img); char sv[64];
  if (!osrel || osrel_get(osrel, "IMAGE_VERSION", sv, sizeof sv) || strcmp(sv, ver)) result("refused", "%s: .osrel IMAGE_VERSION is not %s", uki, ver);
  free(osrel);
  /* the floor: the node's (raised by foil-var-epoch raise) and the booted image's */
  char bmin[64] = "0", fl[64] = "0"; osrel_get(osr, "FOILBIRD_MIN_VERSION", bmin, sizeof bmin);
  char *c = read_file(ST "/min_version", NULL); if (c) { snprintf(fl, sizeof fl, "%s", c); fl[strcspn(fl, "\n")] = 0; free(c); }
  const char *flo = strverscmp(fl, bmin) > 0 ? fl : bmin;
  if (strverscmp(ver, flo) < 0) result("refused", "release %s is below the floor %s (min_version %s, image %s)", ver, flo, fl, bmin);
  char tl[PATH_MAX + 80]; snprintf(tl, sizeof tl, "%s.tmp", cur); unlink(tl);
  if (symlink(ver, tl) || rename(tl, cur)) result("error", "cannot point %s at %s: %m", cur, ver);
  result("ok", "release %s staged in %s: %d files copied, %d checked against SHA256SUMS, floor %s", ver, dst, nf, nc, flo);
}

/* The only key of another epoch raise keeps is the staged release's (/var/lib/foil-agent/staging/current), verified as
   enroll verifies it (SHA256SUMS signed by the release key in /usr, the UKI copy hashed, .pcrpkey and .osrel from the copy),
   with FOILBIRD_PCR_EPOCH above the booted one. Epochs in epoch-keys/ are written under /var and decide nothing (root can rename
   0.pem to 99.pem). Checked in a child: verify_staged() ends a refusal through result(), which only exits there. */
static int staged_trusted(long booted) {
  char lnk[PATH_MAX]; ssize_t n = readlink(STAGING, lnk, sizeof lnk - 1);
  if (n <= 0) { say("no staged release (" STAGING "): no key of another epoch is kept"); return 0; }
  lnk[n] = 0; const char *b = strrchr(lnk, '/'); b = b ? b + 1 : lnk;
  int okname = *b && strlen(b) < sizeof g_staged_ver;
  for (const char *p = b; okname && *p; p++) okname = isalnum((unsigned char)*p) || strchr(".~^_+-", *p);
  if (!okname) { say("staged release name not valid: no key of another epoch is kept"); return 0; }
  make_tmpdir(); fflush(stdout);
  pid_t pid = fork(); if (pid < 0) { say("fork: %m: no key of another epoch is kept"); return 0; }
  if (pid == 0) {
    g_probe = 1; char osr[4096], kf[PATH_MAX], sv[64], p[PATH_MAX + 16];
    verify_staged(b, osr, sizeof osr, kf, sizeof kf);
    if (osrel_get(osr, "IMAGE_VERSION", sv, sizeof sv) || strcmp(sv, b)) result("refused", "UKI .osrel IMAGE_VERSION is not %s", b);
    snprintf(p, sizeof p, "%s/staged.osrel", tmpdir);
    _exit(write_atomic(p, osr, strlen(osr)) ? 1 : 0);
  }
  int st; if (waitpid(pid, &st, 0) < 0 || !WIFEXITED(st) || WEXITSTATUS(st)) { say("staged release %s does not verify: its key is not kept", b); return 0; }
  char p[PATH_MAX + 16], se[16]; snprintf(p, sizeof p, "%s/staged.osrel", tmpdir); char *o = read_file(p, NULL);
  snprintf(p, sizeof p, "%s/pcr-key.pem", tmpdir); char *k = read_file(p, NULL);
  int ok = o && k && !osrel_get(o, "FOILBIRD_PCR_EPOCH", se, sizeof se) && is_number(se);
  if (ok) { g_staged_ep = atol(se); pem_body(k, g_staged_key, sizeof g_staged_key); snprintf(g_staged_ver, sizeof g_staged_ver, "%s", b); g_staged_ok = 1; }
  free(o); free(k);
  if (!ok) { say("staged release %s: no FOILBIRD_PCR_EPOCH or .pcrpkey: its key is not kept", b); return 0; }
  if (g_staged_ep <= booted) { say("staged release %s verified, epoch %ld (not above the booted %ld): no key of its own to keep", b, g_staged_ep, booted); g_staged_key[0] = 0; return 0; }
  say("staged release %s verified, epoch %ld: its key is kept", b, g_staged_ep);
  return 1;
}

/* An installed release newer than the booted one (A/B written, not booted yet) must be the verified staged release, or
   raise would wipe the key slot it boots with. Verified with an epoch not below the booted one is enough: a release of
   the booted epoch boots with the booted key, which raise never wipes. One below (a release pipeline error: enroll refuses
   it) would boot with an older key that raise wipes: refused. Entries with no tries left (+0, +0-N: failed or abandoned by a rollback) do
   not count. The ESP is read through its automount; unreadable -> refused (cannot tell). */
static void esp_guard(const char *bv) {
  DIR *d = opendir(ESP_LINUX);
  if (!d) result("refused", "cannot read " ESP_LINUX " (%m): a newer installed release could lose its key slot");
  struct dirent *e; size_t pl = strlen(UKI_PREFIX);
  while ((e = readdir(d))) {
    const char *n = e->d_name; size_t l = strlen(n);
    if (strncmp(n, UKI_PREFIX, pl) || l <= pl + 4 || strcmp(n + l - 4, ".efi")) continue;
    char v[64]; size_t k = 0; const char *q = n + pl;
    while (q < n + l - 4 && *q != '+' && k + 1 < sizeof v) v[k++] = *q++;
    v[k] = 0;
    if (*q == '+' && q[1] == '0' && (q[2] == '.' || q[2] == '-')) continue;
    if (!*v || strverscmp(v, bv) <= 0) continue;
    if (g_staged_ok && !strcmp(v, g_staged_ver)) {
      if (g_staged_ep >= g_booted) continue;
      char nn[256]; snprintf(nn, sizeof nn, "%s", n); closedir(d);
      result("refused", "release %s is installed on the ESP (%s) with PCR epoch %ld, below the booted %ld: it would boot with an older key that raise wipes; roll it back first",
             v, nn, g_staged_ep, g_booted); }
    char nn[256]; snprintf(nn, sizeof nn, "%s", n); closedir(d);
    result("refused", "release %s is installed on the ESP (%s) but is not the verified staged release (%s): raise would wipe the key slot it boots with; boot it, stage it again or roll it back first",
           v, nn, g_staged_ok ? g_staged_ver : "none");
  }
  closedir(d);
}

/* raise: the booted epoch gets exactly one systemd-tpm2 token with exactly one key slot. Token JSON can be edited by
   root, so the TPM decides: a token of the booted key that does not open /var is not ours; of the tokens that do, the
   first whose JSON policy is our enroll's (PCR 7 + pubkey on PCR 11, sha256, no PIN/pcrlock; the TPM test proves the
   blob matches its JSON) is kept; of its key slots, those it does not open are not ours. An opening token with another
   policy (root: systemd-cryptenroll --tpm2-public-key=<ours> --tpm2-pcrs=, Secure Boot state unbound) is wiped like a
   fake one. Slots the kept token opens are never wiped, and are unassigned from any other token before that token's slots
   are wiped (a slot shared with a fake token). If the test cannot tell the kept token's slots apart (all open), nothing is
   wiped there and the report keeps saying so. A slot named only by tokens of another type is only reported (ADR 0010); one
   that a removed token names too is wiped (named_by_kept). */
static void reconcile_booted_epoch(const char *own) {
  int keep = -1, ok[MAXTOK], weak = 0;
  for (int i = 0; i < ntok; i++) { ok[i] = 0;
    if (strcmp(toks[i].key, own) || !token_live(&toks[i])) continue;
    ok[i] = tok_opens(toks[i].id, -1);
    say("token %d (booted key): the TPM %s /var, policy %s", toks[i].id, ok[i] ? "opens" : "does NOT open",
        toks[i].ours ? "ours" : "NOT ours (tpm2-pcrs/tpm2_pubkey_pcrs/PIN/pcrlock differ)");
    if (ok[i] && !toks[i].ours) weak++;
    if (ok[i] && toks[i].ours && keep < 0) keep = i; }
  if (keep < 0) result("error", "no token of the booted key with our policy opens /var with the TPM%s, nothing wiped",
                       weak ? " (only tokens with another policy do)" : "");
  int ks[8], nk = 0, bad[8], nb = 0;   /* slots of the kept token it opens / does not open */
  for (int k = 0; k < toks[keep].nks; k++) { int sl = toks[keep].ks[k]; if (!slot_exists(sl)) continue;
    if (toks[keep].nks == 1 || tok_opens(toks[keep].id, sl)) ks[nk++] = sl; else bad[nb++] = sl; }
  if (!nk) result("error", "token %d opens /var but none of its key slots by itself, nothing wiped", toks[keep].id);
  int keep_id = toks[keep].id;
  int w[64], nw = 0, rt[MAXTOK], nr = 0;
  /* what is wiped is decided before the header is touched, and journaled (WIPING) before the first unassign */
  for (int k = 0; k < nb; k++) { say("token %d: key slot %d is not opened by it: wiped", keep_id, bad[k]); w[nw++] = bad[k]; }
  for (int i = 0; i < ntok; i++) { if (i == keep || strcmp(toks[i].key, own) || !token_live(&toks[i])) continue;
    say("token %d: %s token of the booted key: its other key slots are wiped", toks[i].id,
        !ok[i] ? "a fake" : toks[i].ours ? "a second" : "a weaker (another policy)");
    rt[nr++] = toks[i].id; }
  for (int i = 0; i < ntok; i++) { if (!in_list(rt, nr, toks[i].id)) continue;   /* ks and slots of other kept tokens stay */
    for (int k = 0; k < toks[i].nks; k++) { int sl = toks[i].ks[k];
      if (slot_exists(sl) && !in_list(w, nw, sl) && !named_by_kept(sl, rt, nr) && nw < 64) w[nw++] = sl; } }
  if (nw) wiping_write(w, nw);
  prepare_wipe(w, nw, rt, nr);   /* the removed tokens keep only slots being wiped (a removed token naming only kept slots
                                    is left with none and removed as an orphan below) */
  int rc = nw ? wipe_slots(w, nw) : 0;
  remove_orphans();
  for (int k = 0; k < nw; k++) { if (slot_exists(w[k])) result("error", "wipe of extra key slot %d failed rc=%d, " WIPING " kept", w[k], rc);
    if (nrep_xwiped < 64) rep_xwiped[nrep_xwiped++] = w[k]; }
  if (nw) wiping_drop();
  for (int k = 0; k < nr; k++) { int live = 0; for (int i = 0; i < ntok; i++) live |= toks[i].id == rt[k];
    if (!live && nrep_rmtok < MAXTOK) rep_rmtok[nrep_rmtok++] = rt[k]; }
  if (!token_for_key(own)) result("error", "after the reconciliation the booted key has no working slot");
  say("booted epoch: kept token %d (key slot(s) %d%s), %d extra key slot(s) wiped", keep_id, ks[0], nk > 1 ? " and more: the TPM test cannot tell them apart" : "", nw);
}

#ifdef FOILBIRD_VAR_EPOCH_LAB
/* Lab builds only (mkosi.build: FOILBIRD_VAR_EPOCH_CFLAGS=-DFOILBIRD_VAR_EPOCH_LAB): "enroll-after-keyslot" in
   /run/foilbird-lab/crash leaves exactly what a power loss between systemd-cryptenroll's keyslot and its token leaves (a
   keyslot without a token), then resets the machine. */
static void lab_crash_after_keyslot(void) {
  char *c = read_file("/run/foilbird-lab/crash", NULL);
  if (!c || strncmp(c, "enroll-after-keyslot", 20)) { free(c); return; }
  free(c); setenv("NEWPASSWORD", "lab-keyslot-without-token", 1);
  char *a[] = {"/usr/bin/systemd-cryptenroll", "--unlock-tpm2-device=auto", "--password", DEV, NULL};
  say("LAB: keyslot without token added rc=%d, hard reset now (journal " ENROLLING " stays)", run(a, NULL));
  sync(); int fd = open("/proc/sysrq-trigger", O_WRONLY); if (fd >= 0) { if (write(fd, "b", 1) < 0) {} close(fd); }
  pause();
}
#endif

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (argc != 2) { fprintf(stderr, "usage: foil-var-epoch enroll-<version>|raise-<version>|stage-<version>|sync-booted\n"); return 2; }
  /* the unit passes %I (unescaped instance): "raise-1" arrives as "raise/1"; a "-" inside the version as "/" too */
  const char *dash = strpbrk(argv[1], "-/"); size_t ol = dash ? (size_t)(dash - argv[1]) : 0;
  if (!dash || ol >= sizeof op || strlen(dash + 1) >= sizeof ver || !dash[1]) { fprintf(stderr, "bad instance %s\n", argv[1]); return 2; }
  memcpy(op, argv[1], ol); op[ol] = 0; snprintf(ver, sizeof ver, "%s", dash + 1);
  for (char *q = ver; *q; q++) if (*q == '/') *q = '-';
  for (const char *p = ver; *p; p++) if (!isalnum((unsigned char)*p) && !strchr(".~^_+-", *p)) { fprintf(stderr, "bad version %s\n", ver); return 2; }
  snprintf(resfile, sizeof resfile, RESDIR "/%s-%s.result", op, ver);
  if (strcmp(op, "enroll") && strcmp(op, "raise") && strcmp(op, "stage") && strcmp(op, "sync")) result("error", "unknown operation %s", op);
  if (!strcmp(op, "sync") && strcmp(ver, "booted")) result("error", "sync takes no version: sync-booted");
  if (!strcmp(op, "stage")) { char *o = read_file(OSREL, NULL); if (!o) result("error", "no " OSREL); stage(o); }

  char *a[] = {"/usr/sbin/cryptsetup", "isLuks", DEV, NULL};
  if (access(DEV, F_OK) || run(a, NULL)) result("noop", "/var not TPM-bound (no LUKS2 var partition), nothing to do");

  char *osr = read_file(OSREL, NULL), bv[64], be[16], bmin[16];
  if (!osr || osrel_get(osr, "IMAGE_VERSION", bv, sizeof bv) || osrel_get(osr, "FOILBIRD_PCR_EPOCH", be, sizeof be) || !is_number(be))
    result("error", OSREL " lacks IMAGE_VERSION or FOILBIRD_PCR_EPOCH");
  long booted = atol(be);
  char *ownpem = read_file(OWNKEY, NULL), own[2048]; if (!ownpem) result("error", "no " OWNKEY); pem_body(ownpem, own, sizeof own);
  mkdir(ST, 0755); mkdir(KEYS, 0755);
  char p[PATH_MAX]; snprintf(p, sizeof p, KEYS "/%ld.pem", booted);
  if (access(p, F_OK) && write_atomic(p, ownpem, strlen(ownpem))) say("cannot record the booted epoch key: %m");
  if (load_tokens()) result("error", "cannot read the LUKS2 header of " DEV);
  snprintf(g_own, sizeof g_own, "%s", own); g_booted = booted; g_report = 1;
  int norph = remove_orphans();
  recover_enrolling();
  recover_wiping();
  if (!token_for_key(own)) say("the booted PCR key has no working key slot (/var was opened with another one?)");
  if (!strcmp(op, "sync")) { write_epochs(own, booted);
    result("ok", "boot: %d orphaned token(s), %d slot(s) of an interrupted enroll removed, nothing else wiped", norph, nrep_intr); }

  if (!strcmp(op, "enroll")) {
    char srel[4096], keyfile[PATH_MAX], sv[64], se[16];
    verify_staged(ver, srel, sizeof srel, keyfile, sizeof keyfile);
    if (osrel_get(srel, "IMAGE_VERSION", sv, sizeof sv) || strcmp(sv, ver)) result("refused", "UKI .osrel IMAGE_VERSION is not %s", ver);
    if (osrel_get(srel, "FOILBIRD_PCR_EPOCH", se, sizeof se) || !is_number(se)) result("refused", "UKI .osrel has no FOILBIRD_PCR_EPOCH");
    long e = atol(se); char *kp = read_file(keyfile, NULL), key[2048]; pem_body(kp, key, sizeof key);
    g_staged_ep = e;   /* verified: the report's upper bound for epoch-keys/ */
    if (e < booted) result("refused", "release %s has epoch %ld, older than the booted epoch %ld", ver, e, booted);
    if (e == booted && strcmp(key, own)) result("refused", "release %s claims the booted epoch %ld with another PCR key", ver, e);
    snprintf(p, sizeof p, KEYS "/%ld.pem", e);
    char *known = read_file(p, NULL);
    if (known) { char kb[2048]; pem_body(known, kb, sizeof kb); free(known);
      if (strcmp(kb, key)) result("refused", "epoch %ld already has another PCR key recorded", e); }
    if (token_for_key(key)) { write_atomic(p, kp, strlen(kp)); write_epochs(own, booted);
      result("ok", "epoch %ld of release %s already has a key slot", e, ver); }
    char *en[] = {"/usr/bin/systemd-cryptenroll", "--unlock-tpm2-device=auto", "--tpm2-device=auto", "--tpm2-pcrs=" ENROLL_PCRS,
                  "--tpm2-public-key-pcrs=" ENROLL_PUBKEY_PCRS, NULL, DEV, NULL};
    char opt[PATH_MAX + 32]; snprintf(opt, sizeof opt, "--tpm2-public-key=%s", keyfile); en[5] = opt;
    /* the key first: a power loss right after cryptenroll must not leave a slot of a key of unknown epoch */
    if (write_atomic(p, kp, strlen(kp))) result("error", "cannot record the key of epoch %ld: %m", e);
    journal_write(e);   /* the keyslot comes before its token: a cut in between is undone by the next run */
#ifdef FOILBIRD_VAR_EPOCH_LAB
    lab_crash_after_keyslot();
#endif
    int rc = run(en, NULL); load_tokens();
    const struct tok *t = token_for_key(key);
    if (rc || !t) { recover_enrolling(); write_epochs(own, booted); result("error", "systemd-cryptenroll rc=%d, slot for epoch %ld %s", rc, e, t ? "present" : "missing"); }
    journal_drop();
    write_epochs(own, booted);
    result("ok", "epoch %ld of release %s enrolled: token %d, key slot %d", e, ver, t->id, t->ks[0]);
  }

  /* raise */
  if (strcmp(ver, bv)) result("refused", "release %s is not the booted release %s", ver, bv);
  snprintf(p, sizeof p, ST "/committed/%s", ver);
  if (access(p, F_OK)) result("refused", "release %s is not committed (no %s)", ver, p);
  if (osrel_get(osr, "FOILBIRD_MIN_VERSION", bmin, sizeof bmin) || !is_number(bmin)) result("error", OSREL " lacks FOILBIRD_MIN_VERSION");
  if (!token_for_key(own)) result("refused", "the booted PCR key has no working key slot");
  int w[64], nw = 0, rt[MAXTOK], nr = 0;
  for (int i = 0; i < ntok; i++)   /* never wipe a slot whose key could not be read: it might be the own one */
    if (!toks[i].key[0] && token_live(&toks[i])) result("error", "token %d: cannot read its PCR key, nothing wiped", toks[i].id);
  int trusted = staged_trusted(booted);   /* kept besides the booted key: only the verified staged release's key */
  esp_guard(bv);
  long tep[MAXTOK];   /* epoch of each token's key from epoch-keys/: for the log and report only */
  for (int i = 0; i < ntok; i++) {
    tep[i] = strcmp(toks[i].key, own) ? epoch_of(toks[i].key, own, booted) : booted;
    if (!strcmp(toks[i].key, own) || !token_live(&toks[i])) continue;
    if (trusted && !strcmp(toks[i].key, g_staged_key)) { say("token %d: key of the verified staged release %s (epoch %ld), kept", toks[i].id, g_staged_ver, g_staged_ep); continue; }
    if (tep[i] < 0) say("token %d: key of unknown epoch (not in " KEYS ", not enrolled by us): wiped", toks[i].id);
    else if (tep[i] >= booted) say("token %d: key listed as epoch %ld in " KEYS " (unsigned), not the verified staged release: wiped", toks[i].id, tep[i]);
    rt[nr++] = toks[i].id; }
  /* A slot of a removed token that a kept systemd-tpm2 token names too is not wiped here: root can add our slot to an
     old token's keyslots, and the cascade of --wipe-slot would take our token with it. It is unassigned from the old token
     instead; a slot that is not ours under our token is wiped by the reconciliation below. Only a token of the booted key
     keeps it (named_by_kept): not one of another type, not one of the staged release's key. */
  for (int i = 0; i < ntok; i++) { if (!in_list(rt, nr, toks[i].id)) continue;
    for (int k = 0; k < toks[i].nks; k++) { int sl = toks[i].ks[k];
      if (!slot_exists(sl) || in_list(w, nw, sl)) continue;
      if (named_by_kept(sl, rt, nr)) { say("token %d: key slot %d is named by a kept systemd-tpm2 token too: unassigned, not wiped", toks[i].id, sl); continue; }
      if (nw < 64) w[nw++] = sl;
      if ((tep[i] < 0 || tep[i] >= booted) && nrep_wiped < 64) rep_wiped[nrep_wiped++] = sl; } }
  if (nr) {
    if (nw) wiping_write(w, nw);
    prepare_wipe(w, nw, rt, nr);
    int rc = nw ? wipe_slots(w, nw) : 0; remove_orphans();
    for (int i = 0; i < ntok; i++) if (strcmp(toks[i].key, own) && !(trusted && !strcmp(toks[i].key, g_staged_key)) && token_live(&toks[i])) {
      write_epochs(own, booted); result("error", "wipe of %d slot(s) rc=%d, token %d (neither the booted nor the staged key) still has a slot, " WIPING " kept", nw, rc, toks[i].id); }
    for (int k = 0; k < nw; k++) if (slot_exists(w[k])) { write_epochs(own, booted); result("error", "wipe of key slot %d failed rc=%d, " WIPING " kept", w[k], rc); }
    if (nw) wiping_drop();
    say("wiped %d key slot(s) of other epochs (not the booted, not the verified staged key), rc=%d", nw, rc);
  } else { nrep_wiped = 0; say("no key slots of other epochs to wipe"); }
  reconcile_booted_epoch(own);
  long cur = 0; char *c = read_file(ST "/min_version", NULL); if (c) { cur = atol(c); free(c); }
  long nm = atol(bmin) > cur ? atol(bmin) : cur; char mv[32]; snprintf(mv, sizeof mv, "%ld\n", nm);
  if (write_atomic(ST "/min_version", mv, strlen(mv))) { write_epochs(own, booted); result("error", "cannot write " ST "/min_version: %m"); }
  write_epochs(own, booted);
  result("ok", "release %s: %s, min_version %ld", ver, nw ? "older epochs wiped" : "nothing to wipe", nm);
}
