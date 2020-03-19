/*
 * Block driver for the Backy Backup File Format
 *
 * Copyright (c) 2019 Peter Lieven <pl@kamp.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "block/block_int.h"
#include "block/qdict.h"
#include "sysemu/block-backend.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "qemu/cutils.h"
#include "migration/blocker.h"
#include "qemu/error-report.h"
#include <lzo/lzo1x.h>

#include "json.h"
#include "MurmurHash3.h"

extern void _Z19MurmurHash3_x64_128PKvijPv ( const void * key, int len, uint32_t seed, void * out );

#define DEDUP_MAC_NAME "mmh3-x64-128"
#define DEDUP_MAC_SIZE 128
#define DEDUP_MAC_SIZE_BYTES DEDUP_MAC_SIZE / 8
#define DEDUP_MAC_SIZE_STR DEDUP_MAC_SIZE / 4 + 1
#define DEDUP_HASH_FILENAME_MAX 512
#define mmh3 _Z19MurmurHash3_x64_128PKvijPv

/**************************************************************/

#define BACKY_CACHE_SIZE 128
#define BACKY_CACHE_TIMEOUT 15000
#define EVENT_INTERVAL 1000

typedef struct BDRVBackyState {
    QemuMutex lock;
    Error *migration_blocker;
    void *zeroblock;
    unsigned int block_size;
    unsigned int version;
    uint64_t filesize;
    uint64_t block_count;
    uint8_t* block_mapping;
    uint8_t* block_is_compressed;
    char zeroblock_hash[DEDUP_MAC_SIZE_BYTES];
    uint32_t crc32c_expected;
    uint8_t *read_buf;
    char *chunk_dir;
    uint64_t cache_ts[BACKY_CACHE_SIZE];
    uint64_t cache_chunk_nr[BACKY_CACHE_SIZE];
    uint8_t *cache_chunk_buf[BACKY_CACHE_SIZE];
    QEMUTimer *event_timer;
} BDRVBackyState;

static const char h2d[256] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0,0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

static void backy_detach_aio_context(BlockDriverState *bs)
{
    BDRVBackyState *s = bs->opaque;

    if (s->event_timer) {
        timer_del(s->event_timer);
        timer_free(s->event_timer);
        s->event_timer = NULL;
    }
}

static void backy_events(void *opaque)
{
    BDRVBackyState *s = opaque;
    long i, cnt = 0;
    uint64_t now;

    qemu_mutex_lock(&s->lock);
    now = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    for (i = 0; i < BACKY_CACHE_SIZE; i++) {
        if (s->cache_ts[i] && now - s->cache_ts[i] > BACKY_CACHE_TIMEOUT) {
            s->cache_ts[i] = 0;
            s->cache_chunk_nr[i] = 0;
            qemu_vfree(s->cache_chunk_buf[i]);
            s->cache_chunk_buf[i] = NULL;
        }
        if (s->cache_ts[i]) cnt++;
    }
    qemu_mutex_unlock(&s->lock);

    timer_mod(s->event_timer,
              qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + EVENT_INTERVAL);
}

static void backy_attach_aio_context(BlockDriverState *bs,
                                     AioContext *new_context)
{
    BDRVBackyState *s = bs->opaque;

    s->event_timer = aio_timer_new(new_context,
                                   QEMU_CLOCK_REALTIME, SCALE_MS,
                                   backy_events, s);
    timer_mod(s->event_timer,
              qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + EVENT_INTERVAL);
}

static int backy_open(BlockDriverState *bs, QDict *options, int flags,
                    Error **errp)
{
    BDRVBackyState *s = bs->opaque;
    QemuOpts *opts = NULL;
    Error *local_err = NULL;
    int ret = -EINVAL;
    json_char *buf = NULL;
    json_value* value = NULL, *mapping = NULL;
    unsigned int i, j, k;
    long lastseq = -1;

    s->version = 1;
    s->filesize = 0;     /* size of the uncompressed data */
    s->block_count = 0;
    s->block_mapping = NULL;
    s->block_is_compressed = NULL;
    s->crc32c_expected = 0xffffffff;

    qemu_mutex_init(&s->lock);

    /* No write support yet */
    ret = bdrv_apply_auto_read_only(bs, NULL, errp);
    if (ret < 0) {
        return ret;
    }

    /* Disable migration when Backy images are used */
    error_setg(&s->migration_blocker, "The backy format used by node '%s' "
               "does not support live migration",
               bdrv_get_device_or_node_name(bs));
    ret = migrate_add_blocker(s->migration_blocker, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        error_free(s->migration_blocker);
        goto fail;
    }

    bs->file = bdrv_open_child(NULL, options, "file", bs, &child_file,
                               false, errp);
    if (!bs->file) {
        return -EINVAL;
    }

    buf = g_malloc(bdrv_getlength(bs->file->bs));

    ret = bdrv_pread(bs->file, 0, buf, bdrv_getlength(bs->file->bs));
    if (ret < 0) {
        error_setg(errp, "Unable to read backy file");
        goto fail;
    }

    json_settings settings = { .settings = json_fast_string_parse };

    value = json_parse_ex(&settings, (json_char*) buf, bdrv_getlength(bs->file->bs), 0);

    if (!value || value->type != json_object) {
        error_setg(errp, "Unable to parse backy file");
        goto fail;
    }

    s->zeroblock = g_malloc0(s->block_size);
    mmh3(s->zeroblock, s->block_size, 0, &s->zeroblock_hash[0]);

    for (i = 0; i < value->u.object.length; i++) {
        json_char *name = value->u.object.values[i].name;
        json_value *val = value->u.object.values[i].value;
        if (val->type == json_integer && !strcmp(name, "size")) {
            s->filesize = val->u.integer;
        } else if (val->type == json_integer && !strcmp(name, "blocksize")) {
            s->block_size = val->u.integer;
        } else if (val->type == json_integer && !strcmp(name, "version")) {
            s->version = val->u.integer;
        } else if (val->type == json_string && !strcmp(name, "hash")) {
            if (val->u.string.length != strlen(DEDUP_MAC_NAME) || strncmp(DEDUP_MAC_NAME, val->u.string.ptr, strlen(DEDUP_MAC_NAME))) {
                 error_setg(errp, "unsupported hash: '%.*s'", val->u.string.length, val->u.string.ptr);
                 goto fail;
            }
        } else if (val->type == json_string && !strcmp(name, "crc32c")) {
            /* not needed */
        } else if (val->type == json_object && !strcmp(name, "metadata")) {
            /* not needed */
        } else if (val->type == json_object && !strcmp(name, "mapping")) {
            if (s->version < 3) {
                s->block_count = val->u.object.length;
            }
            mapping = val;
        } else {
            error_setg(errp, "json parser error: unexpected token '%s' (type %d)", name, val->type);
            goto fail;
        }
    }

    if (s->version < 1 || s->version > 3) {
        error_setg(errp, "unsupported version %d", s->version);
        goto fail;
    }
    if (s->version == 1 && s->block_size != 4096*1024) {
        error_setg(errp, "unsupported version 1 block size %u", s->block_size);
        goto fail;
    }
    if (!mapping) {
        error_setg(errp, "json file lacks mapping object");
        goto fail;
    }

    if (s->version < 3) {
        if (s->block_count != (s->filesize + s->block_size - 1) / s->block_size) {
            error_setg(errp, "invalid number of chunks: expected %lu found %lu", (s->filesize + s->block_size - 1) / (s->block_size), s->block_count);
            goto fail;
        }
    } else {
        s->block_count = (s->filesize + s->block_size - 1) / (s->block_size);
    }

    /* process mapping */
    s->block_mapping = g_malloc((DEDUP_MAC_SIZE_BYTES) * s->block_count);
    if (s->version == 2) {
        s->block_is_compressed = g_malloc0(s->block_count);
    }
    if ((s->version < 3 && mapping->u.object.length  != s->block_count) || mapping->u.object.length > s->block_count) {
        error_setg(errp, "json parser error: invalid number of mapping entries found: expected %lu found %u", s->block_count, mapping->u.object.length);
        goto fail;
    }
    for (j = 0; j < mapping->u.object.length; j++) {
        json_value *entry = mapping->u.object.values[j].value;
        unsigned long seq = strtoul(mapping->u.object.values[j].name, NULL, 0);
        if (seq >= s->block_count) {
            error_setg(errp, "json parser error: invalid sequence in mapping: max %lu found %lu", s->block_count - 1, seq);
            goto fail;
        }
        if (s->version > 2) {
            for (k = lastseq + 1; k < seq; k++) {
                memcpy(&s->block_mapping[k * DEDUP_MAC_SIZE_BYTES], &s->zeroblock_hash[0], DEDUP_MAC_SIZE_BYTES);
                lastseq = k;
            }
        }
        if (seq != lastseq + 1) {
            error_setg(errp, "json parser error: invalid sequence in mapping: expected %lu found %lu", lastseq + 1, seq);
            goto fail;
        }
        if (entry->type != json_string) {
            error_setg(errp, "json parser error: invalid json_type for mapping entry %u", j);
            goto fail;
        }
        if (entry->u.string.length != DEDUP_MAC_SIZE / 4) {
            error_setg(errp, "json parser error: invalid mac size in mapping: expected %d found %d", DEDUP_MAC_SIZE / 4, entry->u.string.length);
            goto fail;
        }
        for (k = 0; k < DEDUP_MAC_SIZE_BYTES; k++) {
            s->block_mapping[seq * DEDUP_MAC_SIZE_BYTES + k] = (h2d[(int)entry->u.string.ptr[k * 2]] << 4) +
                                                                h2d[(int)entry->u.string.ptr[k * 2 + 1]];
        }
        lastseq = seq;
    }
    if (s->version > 2) {
        for (k = lastseq + 1; k < s->block_count; k++) {
            memcpy(&s->block_mapping[k * DEDUP_MAC_SIZE_BYTES], &s->zeroblock_hash[0], DEDUP_MAC_SIZE_BYTES);
            lastseq = k;
        }
    }

    s->chunk_dir = bdrv_dirname(bs, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        error_free(s->migration_blocker);
        goto fail;
    }
    s->chunk_dir = g_realloc(s->chunk_dir, strlen(s->chunk_dir) + 7);
    sprintf(s->chunk_dir, "%schunks", s->chunk_dir);

    s->read_buf = qemu_blockalign(bs, s->block_size);

    ret = 0;

    bs->total_sectors = (int64_t) DIV_ROUND_UP(s->filesize, BDRV_SECTOR_SIZE);

    backy_attach_aio_context(bs, bdrv_get_aio_context(bs));

fail:
    qemu_opts_del(opts);
    json_value_free(value);
    g_free(buf);
    return ret;
}

static int backy_reopen_prepare(BDRVReopenState *state,
                              BlockReopenQueue *queue, Error **errp)
{
    return 0;
}

static int backy_get_info(BlockDriverState *bs, BlockDriverInfo *bdi)
{
    BDRVBackyState *s = (BDRVBackyState *)bs->opaque;
    bdi->cluster_size = s->block_size;
    return 0;
}

static void backy_dedup_hash_sprint(u_int8_t *hash, uint8_t *s) {
    int i;
    static const char *d2h = "0123456789abcdef";
    for (i = 0; i < DEDUP_MAC_SIZE_BYTES; i++, s+=2, hash++)
    {
        s[0] = d2h[(hash[0] >> 4) & 0xf];
        s[1] = d2h[hash[0] & 0xf];
    }
}

static void backy_dedup_hash_filename(BDRVBackyState *s, char* filename, u_int8_t * hash, int compressed)
{
    int i;
    snprintf(filename,DEDUP_HASH_FILENAME_MAX, "%s/%02x/%02x/", s->chunk_dir, hash[0], hash[1]);
    for (i=0; i < DEDUP_MAC_SIZE_BYTES;i++) {
        sprintf(filename + i * 2 + strlen(s->chunk_dir) + 2 * 3 + 1, "%02x", hash[i]);
    }
    sprintf(filename + i * 2 + strlen(s->chunk_dir) + 2 * 3 + 1, compressed ? ".chunk.lzo" : ".chunk");
}

static int coroutine_fn
backy_co_preadv(BlockDriverState *bs, uint64_t offset, uint64_t bytes,
              QEMUIOVector *qiov, int flags)
{
    BDRVBackyState *s = bs->opaque;
    uint64_t bytes2, chunk_nr, offset0 = offset;
    u_int8_t *chunk_ptr;
    uint8_t chunk_hash[DEDUP_MAC_SIZE_STR] = {};
    int ret = -EIO;

    qemu_mutex_lock(&s->lock);
    while (bytes > 0) {
        bytes2 = MIN(bytes, ROUND_UP(offset + 1, s->block_size) - offset);
        chunk_nr = offset / s->block_size;
        chunk_ptr = s->block_mapping + chunk_nr * DEDUP_MAC_SIZE_BYTES;
        backy_dedup_hash_sprint(chunk_ptr, (u_int8_t*) &chunk_hash);

        if (!memcmp(chunk_ptr, s->zeroblock_hash, DEDUP_MAC_SIZE_BYTES)) {
            qemu_iovec_memset(qiov, offset - offset0, 0, bytes2);
        } else {
            uint64_t expected_size = MIN(s->block_size, s->filesize - chunk_nr * s->block_size);
            ssize_t rd_bytes;
            char chunk_filename[DEDUP_HASH_FILENAME_MAX];
            unsigned long out_buf_sz = s->block_size;
            int fd;
            uint64_t cache_min_ts = UINT64_MAX;
            long i, cache_min_slot = 0;
            uint8_t *chunk_buf = NULL;

            for (i = 0; i < BACKY_CACHE_SIZE; i++) {
                if (s->cache_ts[i] && s->cache_chunk_nr[i] == chunk_nr) {
                    chunk_buf = s->cache_chunk_buf[i];
                    s->cache_ts[i] = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
                    break;
                }
            }

            if (!chunk_buf) {
                for (i = 0; i < BACKY_CACHE_SIZE; i++) {
                    if (s->cache_ts[i] < cache_min_ts) {
                        cache_min_ts = s->cache_ts[i];
                        cache_min_slot = i;
                    }
                }

                s->cache_ts[cache_min_slot] = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
                s->cache_chunk_nr[cache_min_slot] = chunk_nr;
                if (!s->cache_chunk_buf[cache_min_slot]) {
                    s->cache_chunk_buf[cache_min_slot] = qemu_blockalign(bs, s->block_size);
                }
                chunk_buf = s->cache_chunk_buf[cache_min_slot];

                backy_dedup_hash_filename(s, chunk_filename, chunk_ptr, s->version != 2 || s->block_is_compressed[chunk_nr]);
                fd = open((char*)chunk_filename, O_RDONLY); //XXX: we need to use qemu open functions here
                if (fd < 0) {
                    if (s->version != 2 || s->block_is_compressed[chunk_nr]) {
                        error_report("could not open %s (%s)", chunk_filename, strerror(errno));
                        goto out;
                    }
                    if (errno == ENOENT) {
                        backy_dedup_hash_filename(s, chunk_filename, chunk_ptr, 1);
                        fd = open((char*)chunk_filename, O_RDONLY);
                        if (fd < 0) {
                            error_report("could not open %s (%s)", chunk_filename, strerror(errno));
                            goto out;
                        }
                        s->block_is_compressed[chunk_nr] = 1;
                    }
                }
                rd_bytes = read(fd, s->block_is_compressed[chunk_nr] ? s->read_buf : chunk_buf, s->block_size);
                if (rd_bytes < 0) {
                    error_report("read failed at chunk %" PRIu64 "(%s)", chunk_nr, strerror(errno));
                    close(fd);
                    goto out;
                }
                close(fd);

                if (s->block_is_compressed[chunk_nr]) {
                    uint64_t decompressed_size;
                    if (rd_bytes < 5 + 3 || s->read_buf[0] != 0xf0) {
                        error_report("lzo header error (length): seq %lu rd_bytes %ld", chunk_nr, rd_bytes);
                        goto out;
                    }
                    decompressed_size = s->read_buf[1] << 24 | s->read_buf[2] << 16 | s->read_buf[3] << 8 | s->read_buf[4];
                    if (decompressed_size != expected_size) {
                        error_report("lzo data has unexpected size (expected %lu found %lu)", expected_size, decompressed_size);
                        goto out;
                    }
                    ret = lzo1x_decompress_safe(s->read_buf + 5, rd_bytes - 5, chunk_buf, &out_buf_sz, NULL);
                    if (ret != LZO_E_OK) {
                        error_report("lzo1x_decompress failed, return     = %d\n", ret);
                        ret = -EIO;
                        goto out;
                    }
                } else {
                    if (rd_bytes < expected_size) {
                        error_report("short read. read %ld bytes, expected size is %"PRIu64"\n", rd_bytes, expected_size);
                        goto out;
                    }
                }
            }

            qemu_iovec_from_buf(qiov, offset - offset0, chunk_buf + offset % s->block_size, bytes2);
        }

        offset += bytes2;
        bytes -= bytes2;
    }

    ret = 0;

out:
    qemu_mutex_unlock(&s->lock);

    return ret;
}

static void backy_close(BlockDriverState *bs)
{
    BDRVBackyState *s = bs->opaque;
    long i;
    g_free(s->zeroblock);
    g_free(s->block_mapping);
    g_free(s->block_is_compressed);
    g_free(s->chunk_dir);
    qemu_vfree(s->read_buf);
    for (i = 0; i < BACKY_CACHE_SIZE; i++) {
        qemu_vfree(s->cache_chunk_buf[i]);
    }
    backy_detach_aio_context(bs);
    qemu_mutex_destroy(&s->lock);
}

static BlockDriver bdrv_backy = {
    .format_name    = "backy",
    .instance_size  = sizeof(BDRVBackyState),
    .bdrv_open                  = backy_open,
    .bdrv_close                 = backy_close,
    .bdrv_co_preadv             = backy_co_preadv,
    .bdrv_get_info              = backy_get_info,
    .bdrv_reopen_prepare        = backy_reopen_prepare,
    .bdrv_child_perm            = bdrv_format_default_perms,
    .bdrv_detach_aio_context    = backy_detach_aio_context,
    .bdrv_attach_aio_context    = backy_attach_aio_context,
};

static void bdrv_backy_init(void)
{
    bdrv_register(&bdrv_backy);
}

block_init(bdrv_backy_init);
