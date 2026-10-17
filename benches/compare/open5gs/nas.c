/*
 * The NAS code of Open5GS, as compare.sh runs it: built from Open5GS's
 * source tree with OGS_5GS for its 5GS messages or OGS_EPS for its EPS ones.
 *
 *   open5gs-nas-<5gs|eps> check <5gs|eps> <fixtures>
 *   open5gs-nas-<5gs|eps> run <decode|encode> <5gs|eps> <messages> <passes>
 *
 * check prints, for each message of a file of the fixtures, its name,
 * whether Open5GS decodes it (1 or 0), and whether it encodes what it
 * decoded to the same octets. run does the operation on each message of the
 * file, passes times, and prints the nanoseconds, the allocations and the
 * octets allocated per message, and the peak memory of the program in KiB.
 * A message is decoded from the packet buffer that Open5GS's decoder reads,
 * made once for each message, and given back its octets after each decode.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>

#ifdef OGS_5GS
#include "ogs-nas-5gs.h"
typedef ogs_nas_5gs_message_t message_t;
#define MOBILITY 0x7e
#define decode_mobility ogs_nas_5gmm_decode
#define decode_session ogs_nas_5gsm_decode
#define encode_mobility ogs_nas_5gmm_encode
#define encode_session ogs_nas_5gsm_encode
#else
#include "ogs-nas-eps.h"
typedef ogs_nas_eps_message_t message_t;
#define MOBILITY 0x07
#define decode_mobility ogs_nas_emm_decode
#define decode_session ogs_nas_esm_decode
#define encode_mobility ogs_nas_emm_encode
#define encode_session ogs_nas_esm_encode
#endif

/* The allocator of the program, which counts the allocations of every
 * library and their octets, and gives them to that of the C library. */
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);
static unsigned long long allocations, allocated;

void *malloc(size_t size)
{
    allocations++;
    allocated += size;
    return __libc_malloc(size);
}

void *calloc(size_t count, size_t size)
{
    allocations++;
    allocated += count * size;
    return __libc_calloc(count, size);
}

void *realloc(void *pointer, size_t size)
{
    allocations++;
    allocated += size;
    return __libc_realloc(pointer, size);
}

void free(void *pointer)
{
    __libc_free(pointer);
}

struct message {
    char name[128];
    unsigned char octets[4096];
    size_t length;
};

static struct message *messages(const char *path, size_t *count)
{
    static char line[16384];
    struct message *all = NULL;
    size_t used = 0, room = 0;
    FILE *file = fopen(path, "r");
    if (!file) {
        perror(path);
        exit(2);
    }
    while (fgets(line, sizeof line, file)) {
        char *tab = strchr(line, '\t');
        if (line[0] == '#' || !tab)
            continue;
        if (used == room) {
            room = room ? room * 2 : 128;
            all = __libc_realloc(all, room * sizeof *all);
        }
        struct message *m = &all[used++];
        *tab = 0;
        snprintf(m->name, sizeof m->name, "%.127s", line);
        m->length = 0;
        for (char *hex = tab + 1; hex[0] && hex[1] && hex[0] != '\n'; hex += 2) {
            unsigned int octet;
            sscanf(hex, "%2x", &octet);
            m->octets[m->length++] = (unsigned char)octet;
        }
    }
    fclose(file);
    *count = used;
    return all;
}

/* Decode `m` into `decoded`, from a packet buffer that is returned, since
 * a decoded message points into it. */
static ogs_pkbuf_t *decode(const struct message *m, message_t *decoded, int *rv)
{
    ogs_pkbuf_t *pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_pkbuf_put_data(pkbuf, m->octets, m->length);
    if (m->octets[0] == MOBILITY)
        *rv = decode_mobility(decoded, pkbuf);
    else
        *rv = decode_session(decoded, pkbuf);
    return pkbuf;
}

static ogs_pkbuf_t *encode(const struct message *m, message_t *decoded)
{
    if (m->octets[0] == MOBILITY)
        return encode_mobility(decoded);
    return encode_session(decoded);
}

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e9 + t.tv_nsec;
}

int main(int argc, char **argv)
{
    ogs_pkbuf_config_t config;
    size_t count, i;
    struct message *all;
    message_t *decoded;
    int rv;

    ogs_core_initialize();
    ogs_pkbuf_default_init(&config);
    ogs_pkbuf_default_create(&config);
    ogs_log_install_domain(&__ogs_nas_domain, "nas", OGS_LOG_NONE);
    ogs_log_set_mask_level(NULL, OGS_LOG_NONE);

    if (argc == 4 && !strcmp(argv[1], "check")) {
        all = messages(argv[3], &count);
        decoded = __libc_calloc(1, sizeof *decoded);
        for (i = 0; i < count; i++) {
            ogs_pkbuf_t *pkbuf = decode(&all[i], decoded, &rv);
            int encodes = 0;
            if (rv == OGS_OK) {
                ogs_pkbuf_t *out = encode(&all[i], decoded);
                encodes = out && out->len == all[i].length &&
                    !memcmp(out->data, all[i].octets, all[i].length);
                if (out)
                    ogs_pkbuf_free(out);
            }
            ogs_pkbuf_free(pkbuf);
            printf("%s\t%d\t%d\n", all[i].name, rv == OGS_OK, encodes);
        }
        return 0;
    }
    if (argc == 6 && !strcmp(argv[1], "run")) {
        int encoding = !strcmp(argv[2], "encode");
        long passes = atol(argv[5]), pass;
        ogs_pkbuf_t **kept;
        unsigned long long allocations_before, allocated_before;
        double start, elapsed, operations;

        all = messages(argv[4], &count);
        decoded = __libc_calloc(count, sizeof *decoded);
        kept = __libc_calloc(count, sizeof *kept);
        for (i = 0; i < count; i++)
            kept[i] = decode(&all[i], &decoded[i], &rv);
        allocations_before = allocations;
        allocated_before = allocated;
        start = now();
        for (pass = 0; pass < passes; pass++) {
            for (i = 0; i < count; i++) {
                if (encoding) {
                    ogs_pkbuf_free(encode(&all[i], &decoded[i]));
                } else {
                    /* The octets that the decoder took, given back */
                    message_t message;
                    ogs_pkbuf_push(kept[i], all[i].length - kept[i]->len);
                    if (all[i].octets[0] == MOBILITY)
                        decode_mobility(&message, kept[i]);
                    else
                        decode_session(&message, kept[i]);
                }
            }
        }
        elapsed = now() - start;
        operations = (double)passes * count;
        {
            struct rusage usage;
            getrusage(RUSAGE_SELF, &usage);
            printf("%.1f %.2f %.0f %ld\n", elapsed / operations,
                   (allocations - allocations_before) / operations,
                   (allocated - allocated_before) / operations, usage.ru_maxrss);
        }
        return 0;
    }
    fprintf(stderr, "open5gs-nas (check <5gs|eps> <fixtures> | run <decode|encode> "
            "<5gs|eps> <messages> <passes>)\n");
    return 2;
}
