/*
 * QEMU Block driver for native access to files on a Quobyte Volume
 *
 * Copyright (c) 2016-19 Peter Lieven <pl@kamp.de>
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
#include <poll.h>
#include "qemu-common.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "block/block_int.h"
#include "trace.h"
#include "qemu/iov.h"
#include "qemu/uuid.h"
#include "qemu/uri.h"
#include "qemu/cutils.h"
#include "qemu/uuid.h"
#include "qemu/option.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-misc.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "sysemu/sysemu.h"
#include "block/thread-pool.h"
#include "block/raw-aio.h"

#include "quobyte.h"

typedef struct QuobyteClient {
    struct quobyte_fh *fh;
    blksize_t st_blksize;
    off_t st_size;
    AioContext *aio_context;
    bool has_discard;
    uint32_t cluster_size;
    int64_t last_sync;
    int64_t first_unsynced_write;
    uint64_t unsynced_bytes;
    unsigned long *allocmap; /* the allocmap has only hint character */
    long allocmap_size;
    char *filename;
    char *path;
    char *metadata_path;
} QuobyteClient;

typedef struct QuobyteAIORequest {
    BlockDriverState *bs;
    int aio_type;
    uint64_t offset;
    uint64_t bytes;
    QEMUIOVector *qiov;
    int flags;
} QuobyteAIORequest;

#define STACKBUF_MAX 4096
#define SLOW_REQUEST_MS 5000

static int quobyte_aio_worker(void *arg)
{
    QuobyteAIORequest *req = arg;
    QuobyteClient *client = req->bs->opaque;
    int ret = -EINVAL;
    char *buf = NULL, *local_buf = NULL;
    char stackbuf[STACKBUF_MAX];
    int64_t req_time, req_start = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

    if (req->qiov) {
        if (req->qiov->niov > 1 || req->aio_type == QEMU_AIO_WRITE) {
            if (req->bytes <= STACKBUF_MAX) {
                buf = &stackbuf[0];
            } else {
                buf = g_try_malloc(req->bytes);
                if (buf == NULL) {
                    return -ENOMEM;
                }
                local_buf = buf;
            }
        } else {
            buf = req->qiov->iov[0].iov_base;
        }
    }

    switch (req->aio_type) {
    case QEMU_AIO_READ:
        ret = quobyte_read(client->fh, buf, req->offset, req->bytes);

        if (ret > req->bytes || ret < 0) {
            ret = -EIO;
            break;
        }

        if (buf != req->qiov->iov[0].iov_base) {
            qemu_iovec_from_buf(req->qiov, 0, buf, ret);
        }

        /* zero pad short reads */
        if (ret < req->qiov->size) {
            qemu_iovec_memset(req->qiov, ret, 0, req->bytes - ret);
        }

        ret = 0;
        break;
    case QEMU_AIO_WRITE:
        qemu_iovec_to_buf(req->qiov, 0, buf, req->qiov->size);

        ret = quobyte_write(client->fh, buf, req->offset, req->bytes, !!(req->flags & BDRV_REQ_FUA));
        if (ret != req->bytes) {
            ret = -EIO;
            break;
        }

        ret = 0;
        break;
    case QEMU_AIO_FLUSH:
        ret = quobyte_fsync(client->fh);
        if (ret) {
            ret = -EIO;
        }
        break;
    case QEMU_AIO_DISCARD:
        ret = quobyte_fallocate(client->fh, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                                req->offset, req->bytes);
        if (ret) {
            ret = -EIO;
        }
        break;

    default:
        error_report("invalid qb request (0x%x)\n", req->aio_type);
        break;
    }

    g_free(local_buf);

    req_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - req_start;

    if (ret) {
        error_report("quobyte_aio_worker failed request: req %p type %d offset %"PRIu64" bytes %"PRIu64" flags %d ret %d errno %d time %"PRIi64"ms",
                     req, req->aio_type, req->offset, req->bytes, req->flags, ret, errno, req_time);
    } else if (req_time >= SLOW_REQUEST_MS) {
        error_report("quobyte_aio_worker SLOW request: req %p type %d offset %"PRIu64" bytes %"PRIu64" flags %d ret %d errno %d time %"PRIi64"ms",
                     req, req->aio_type, req->offset, req->bytes, req->flags, ret, errno, req_time);
    }

    return ret;
}

static int coroutine_fn quobyte_submit_co(BlockDriverState *bs, int type,
                          uint64_t offset, uint64_t bytes, QEMUIOVector *qiov, int flags)
{
    QuobyteAIORequest req = {};
    QuobyteClient *client = bs->opaque;
    ThreadPool *pool;

    req.bs = bs;
    req.aio_type = type;
    req.offset = offset;
    req.bytes = bytes;
    req.flags = flags;

    if (qiov) {
        assert(qiov->size == bytes);
    }
    req.qiov = qiov;

    pool = aio_get_thread_pool(client->aio_context);
    return thread_pool_submit_co(pool, quobyte_aio_worker, &req);
}

static void quobyte_allocmap_free(QuobyteClient *client)
{
    g_free(client->allocmap);
    client->allocmap = NULL;
}

static int quobyte_allocmap_init(QuobyteClient *client)
{
    quobyte_allocmap_free(client);

    assert(client->cluster_size);
    client->allocmap_size =
        DIV_ROUND_UP(client->st_size, client->cluster_size);

    client->allocmap = bitmap_try_new(client->allocmap_size);
    if (!client->allocmap) {
        return -ENOMEM;
    }

    /* default to all clusters allocated */
    bitmap_set(client->allocmap, 0, client->allocmap_size);

    return 0;
}

static void
quobyte_allocmap_update(QuobyteClient *client, int64_t offset,
                        int64_t bytes, bool allocated)
{
    int64_t cl_num_expanded, nb_cls_expanded, cl_num_shrunk, nb_cls_shrunk;

    if (client->allocmap == NULL) {
        return;
    }

    assert(offset + bytes <= client->st_size);

    /* expand to entirely contain all affected clusters */
    assert(client->cluster_size);
    cl_num_expanded = offset / client->cluster_size;
    nb_cls_expanded = DIV_ROUND_UP(offset + bytes,
                                   client->cluster_size) - cl_num_expanded;
    /* shrink to touch only completely contained clusters */
    cl_num_shrunk = DIV_ROUND_UP(offset, client->cluster_size);
    nb_cls_shrunk = (offset + bytes) / client->cluster_size - cl_num_shrunk;
    if (allocated) {
        bitmap_set(client->allocmap, cl_num_expanded, nb_cls_expanded);
    } else {
        if (nb_cls_shrunk > 0) {
            bitmap_clear(client->allocmap, cl_num_shrunk, nb_cls_shrunk);
        }
    }
}

static void
quobyte_allocmap_set_allocated(QuobyteClient *client, int64_t offset,
                             int64_t bytes)
{
    quobyte_allocmap_update(client, offset, bytes, true);
}

static void
quobyte_allocmap_set_unallocated(QuobyteClient *client, int64_t offset,
                               int64_t bytes)
{
    /* Note: if cache.direct=on the fifth argument to quobyte_allocmap_update
     * is ignored, so this will in effect be an quobyte_allocmap_set_invalid.
     */
    quobyte_allocmap_update(client, offset, bytes, false);
}

static inline bool
quobyte_allocmap_is_allocated(QuobyteClient *client, int64_t offset,
                              int64_t bytes)
{
    unsigned long size;
    if (client->allocmap == NULL) {
        return true;
    }
    assert(client->cluster_size);
    size = DIV_ROUND_UP(offset + bytes, client->cluster_size);
    return !(find_next_bit(client->allocmap, size,
                           offset / client->cluster_size) == size);
}

static long
quobyte_allocmap_count_allocated(QuobyteClient *client)
{
    long allocated = -1;
    if (client->allocmap == NULL) {
        return -1;
    }
    allocated = slow_bitmap_count_one(client->allocmap, client->allocmap_size);
    fprintf(stderr, "quobyte file %s has approximately %lu of %lu clusters allocated\n",
            client->path, allocated, client->allocmap_size);
    return allocated;
}


static int
coroutine_fn quobyte_co_preadv(BlockDriverState *bs, uint64_t offset,
                               uint64_t bytes, QEMUIOVector *iov,
                               int flags)
{
    return quobyte_submit_co(bs, QEMU_AIO_READ, offset, bytes, iov, flags);
}

static int
coroutine_fn quobyte_co_pwritev(BlockDriverState *bs, uint64_t offset,
                                uint64_t bytes, QEMUIOVector *iov,
                                int flags)
{
    QuobyteClient *client = bs->opaque;
    if (!(flags & BDRV_REQ_FUA)) {
        if (!client->unsynced_bytes) {
            client->first_unsynced_write = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
        }
        client->unsynced_bytes += bytes;
    }
    if (offset + bytes > client->st_size) {
        quobyte_allocmap_free(client);
        client->st_size = offset + bytes;
    }
    quobyte_allocmap_set_allocated(client, offset, bytes);
    return quobyte_submit_co(bs, QEMU_AIO_WRITE, offset, bytes, iov, flags);
}

static int coroutine_fn quobyte_co_flush(BlockDriverState *bs)
{
    QuobyteClient *client = bs->opaque;
    int64_t sync_age = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - client->last_sync;
    int64_t write_age = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - client->first_unsynced_write;

    if (client->unsynced_bytes >= 1048576 && write_age > 10000) {
        error_report("quobyte_co_flush: last_sync %ld ms ago, first_unsynced_write %ld ms ago, unsynced bytes %" PRIu64,
                     sync_age, write_age, client->unsynced_bytes);
    }
    client->unsynced_bytes = 0;
    client->last_sync = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

    return quobyte_submit_co(bs, QEMU_AIO_FLUSH, 0, 0, NULL, 0);
}

static int
coroutine_fn quobyte_co_pdiscard_internal(BlockDriverState *bs, int64_t offset, int count)
{
    QuobyteClient *client = bs->opaque;
    int ret;

    if (!client->has_discard) {
        return -ENOTSUP;
    }

    ret = quobyte_submit_co(bs, QEMU_AIO_DISCARD, offset, count, NULL, 0);

    if (!ret) {
        quobyte_allocmap_set_unallocated(client, offset, count);
    }

    return ret;
}

static int
coroutine_fn quobyte_co_pdiscard(BlockDriverState *bs, int64_t offset, int count)
{
    QuobyteClient *client = bs->opaque;
    int64_t offset_shrunk, count_shrunk;
    int alloc_cnt, ret;

    offset_shrunk = QEMU_ALIGN_UP(offset, client->cluster_size);
    count_shrunk = QEMU_ALIGN_DOWN(offset + count, client->cluster_size) - offset_shrunk;

    while (count_shrunk > 0) {
        if (!quobyte_allocmap_is_allocated(client, offset_shrunk, client->cluster_size)) {
            /* skip unalloacted clusters */
            offset_shrunk += client->cluster_size;
            count_shrunk -= client->cluster_size;
            continue;
        }
        for (alloc_cnt = 1; alloc_cnt < count_shrunk / client->cluster_size; alloc_cnt++) {
            /* determinate size of continuous allocated */
            if (!quobyte_allocmap_is_allocated(client, offset_shrunk + alloc_cnt * client->cluster_size, client->cluster_size)) {
                break;
            }
        }
        assert(offset_shrunk >= offset);
        assert(offset_shrunk + alloc_cnt * client->cluster_size <= offset + count);
        assert(alloc_cnt * client->cluster_size <= INT_MAX);
        ret = quobyte_co_pdiscard_internal(bs, offset_shrunk, alloc_cnt * client->cluster_size);
        if (ret) {
            return ret;
        }
        offset_shrunk += alloc_cnt * client->cluster_size;
        count_shrunk -= alloc_cnt * client->cluster_size;
    }

    return 0;
}

static int
coroutine_fn quobyte_co_pwrite_zeroes(BlockDriverState *bs, int64_t offset,
                                      int count, BdrvRequestFlags flags)
{
    QuobyteClient *client = bs->opaque;
    if (flags & BDRV_REQ_MAY_UNMAP) {
        if (offset + count > client->st_size) {
            quobyte_allocmap_free(client);
            client->st_size = offset + count;
        }
        return quobyte_co_pdiscard_internal(bs, offset, count);
    }
    return -ENOTSUP;
}

/* TODO Convert to fine grained options */
static QemuOptsList runtime_opts = {
    .name = "quobyte",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = "filename",
            .type = QEMU_OPT_STRING,
            .help = "URL to the Quobyte File",
        },
        { /* end of list */ }
    },
};

static char *quobyteRegistry;
static unsigned quobyteClients;

// QEMUQBM char[7]
// flags uint8_t (bit 1 = active)
// filesize uint64_t
// clustersize uint32_t
// file_id char[64]
// allocmaphint uint8_t[BITS_TO_LONGS(client->allocmap_size) * sizeof(unsigned long)]

static void quobyte_write_metadata(QuobyteClient *client) {
    struct quobyte_fh *fh;
    ssize_t file_id_sz;
    char file_id[64] = {};
    int flags = O_RDWR | O_DIRECT;
    uint8_t md_flags = 0x0;

    if (!client->metadata_path || !client->allocmap) {
        return;
    }
    if (quobyte_allocmap_count_allocated(client) < client->allocmap_size) {
        /* only create the matadata file if there are unallocated sectors */
        flags |= O_CREAT;
    }
    fh = quobyte_open(client->metadata_path, flags, 0600);
    if (!fh) {
        if (flags & O_CREAT) {
            error_report("failed to create quobyte metadata file %s", client->metadata_path);
        }
        return;
    }
    quobyte_write(fh, "QEMUQBM", 0, 7, false);
    quobyte_write(fh, (const void*)&md_flags, 7, 1, false);
    quobyte_write(fh, (const void*)&client->st_size, 8, sizeof(client->st_size), false);
    quobyte_write(fh, (const void*)&client->cluster_size, 16, sizeof(client->cluster_size), false);
    if ((file_id_sz = quobyte_getxattr(client->path, "quobyte.file_id", &file_id[0], sizeof(file_id) - 1)) < 0) {
        error_report("quobyte file %s could not retrieve quobyte.file_id: %s (%d)\n", client->path, strerror(errno), errno);
        if (fh) {
            quobyte_close(fh);
        }
        return;
    }
    quobyte_write(fh, &file_id[0], 20, sizeof(file_id), false);
    quobyte_write(fh, (const void*)client->allocmap, 84, BITS_TO_LONGS(client->allocmap_size) * sizeof(unsigned long), false);
    quobyte_close(fh);

    fprintf(stderr, "quobyte metadata written to %s\n", client->metadata_path);
}

static void quobyte_read_metadata(QuobyteClient *client) {
    struct quobyte_fh *fh;
    ssize_t file_id_sz;
    char file_id[64] = {};
    ssize_t allocmap_size;
    char buf[64];
    assert(sizeof(client->st_size) == 8);
    assert(sizeof(client->cluster_size) == 4);
    if (!client->metadata_path || !client->allocmap) {
        return;
    }
    fh = quobyte_open(client->metadata_path, O_RDWR | O_DIRECT, 0600);
    if (!fh) {
        return;
    }
    if (quobyte_read(fh, buf, 0, 7) != 7) {
        goto err;
    }
    if (memcmp(buf, "QEMUQBM", 7)) {
        goto err;
    }
    if (quobyte_read(fh, buf, 7, 1) != 1) {
        goto err;
    }
    if (buf[0] & 1) {
        error_report("cannot trust metadata from active client, maybe we recover from a crash?");
        goto err;
    }
    if (quobyte_read(fh, buf, 8, sizeof(client->st_size)) != sizeof(client->st_size)) {
        goto err;
    }
    if (memcmp(buf, (const void*)&client->st_size, 8)) {
        error_report("cannot use quobyte metadata from %s, filesize has changed", client->metadata_path);
        return;
    }
    if (quobyte_read(fh, buf, 16, sizeof(client->cluster_size)) != sizeof(client->cluster_size)) {
        goto err;
    }
    if (memcmp(buf, (const void*)&client->cluster_size, 4)) {
        error_report("cannot use quobyte metadata from %s, clustersize has changed", client->metadata_path);
        return;
    }
    if ((file_id_sz = quobyte_getxattr(client->path, "quobyte.file_id", &file_id[0], sizeof(file_id) - 1)) < 0) {
        error_report("quobyte file %s could not retrieve quobyte.file_id: %s (%d)\n", client->path, strerror(errno), errno);
        return;
    }
    if (quobyte_read(fh, buf, 20, sizeof(file_id)) != sizeof(file_id)) {
        goto err;
    }
    if (memcmp(buf, file_id, sizeof(file_id))) {
        error_report("cannot use quobyte metadata from %s, file_id has changed", client->metadata_path);
        return;
    }
    allocmap_size = BITS_TO_LONGS(client->allocmap_size) * sizeof(unsigned long);
    if (quobyte_read(fh, (void*)client->allocmap, 84, allocmap_size) != allocmap_size) {
        goto err;
    }
    /* set active */
    buf[0] = 0x1;
    if (quobyte_write(fh, buf, 7, 1, false) != 1) {
        goto err;
    }

    quobyte_close(fh);
    fprintf(stderr, "quobyte metadata read from %s\n", client->metadata_path);
    quobyte_allocmap_count_allocated(client);
    return;
err:
    if (fh) {
        quobyte_close(fh);
    }
    quobyte_allocmap_init(client);
    error_report("failed to read quobyte metadata from %s", client->metadata_path);
    return;
}

static int quobyte_lock_fcntl(struct quobyte_fh *fh, int64_t start, int64_t len, int cmd, int fl_type)
{
    int ret;
    struct flock fl = {
        .l_whence = SEEK_SET,
        .l_start  = start,
        .l_len    = len,
        .l_type   = fl_type,
    };
    do {
        ret = quobyte_lock(fh, cmd, &fl);
    } while (ret == -1 && errno == EINTR);
    return ret == -1 ? -errno : 0;
}

static void quobyte_client_close(QuobyteClient *client)
{
    quobyteClients--;
    if (client->fh) {
        int64_t sync_age = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - client->last_sync;
        int64_t write_age = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - client->first_unsynced_write;
        if (client->unsynced_bytes) {
            error_report("quobyte_client_close: last_sync %ld ms ago, first_unsynced_write %ld ms ago, unsynced bytes %" PRIu64,
                         sync_age, write_age, client->unsynced_bytes);
        }
        quobyte_close(client->fh);
        quobyte_write_metadata(client);
    }
    if (!quobyteClients && quobyteRegistry) {
        quobyte_destroy_adapter();
        g_free(quobyteRegistry);
        quobyteRegistry = NULL;
    }
    quobyte_allocmap_free(client);
    g_free(client->filename);
    g_free(client->path);
    g_free(client->metadata_path);
    memset(client, 0, sizeof(QuobyteClient));
}

static void quobyte_file_close(BlockDriverState *bs)
{
    QuobyteClient *client = bs->opaque;
    quobyte_client_close(client);
}

static int64_t quobyte_client_open(QuobyteClient *client, const char *filename,
                                   int flags, Error **errp, int open_flags)
{
    int64_t ret = -EINVAL;
    struct stat st;
    URI *uri;
    struct timespec tstart={}, tend={};
    double tdiff;

    uri = uri_parse(filename);
    if (!uri) {
        error_setg(errp, "Invalid URL specified");
        goto fail;
    }
    if (!uri->server) {
        error_setg(errp, "Invalid URL specified");
        goto fail;
    }

    if (!quobyteRegistry) {
        if (qemu_get_vm_name()) {
            UuidInfo *uuid_info;
            char *procname;
            uuid_info = qmp_query_uuid(NULL);
            if (strcmp(uuid_info->UUID, UUID_NONE) == 0) {
                procname = g_strdup_printf("%s using qemu %s",
                                           qemu_get_vm_name(), QEMU_VERSION);
            } else {
                procname = g_strdup_printf("%s (%s) using qemu %s",
                                           qemu_get_vm_name(), uuid_info->UUID,
                                           QEMU_VERSION);
            }
            quobyte_set_process_name(procname);
            g_free(procname);
        }
        clock_gettime(CLOCK_MONOTONIC, &tstart);
        if (quobyte_create_adapter(uri->server)) {
            error_setg(errp, "Registration failed.");
            goto fail;
        }
        clock_gettime(CLOCK_MONOTONIC, &tend);
        tdiff = ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec);
        if (tdiff > .25) {
            error_report("quobyte_create_adapter took about %.5f seconds", tdiff);
        }
        quobyteRegistry = g_strdup(uri->server);
    } else if (strncmp(uri->server, quobyteRegistry, strlen(quobyteRegistry))) {
        error_setg(errp, "All connections must go to the same Quobyte registry.");
        goto fail;
    }

    quobyteClients++;

    clock_gettime(CLOCK_MONOTONIC, &tstart);
    client->fh = quobyte_open(uri->path, flags | O_DIRECT, 0600);
    if (!client->fh) {
        error_setg(errp, "Failed to open/create file: %s", strerror(errno));
        goto fail;
    }
    clock_gettime(CLOCK_MONOTONIC, &tend);
    tdiff = ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
            ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec);
    if (tdiff > .25) {
        error_report("quobyte_open took about %.5f seconds", tdiff);
    }

    ret = quobyte_fstat(client->fh, &st) ? -errno : 0;
    if (ret) {
        error_setg(errp, "Failed to fstat file: %s", strerror(-ret));
        goto fail;
    }

    if (!(open_flags & BDRV_O_INACTIVE) && st.st_size) {
        ret = quobyte_lock_fcntl(client->fh, 0, 1, F_SETLK, F_WRLCK);
        if (ret) {
            error_setg(errp, "Could not set exclusive lock, is another process using this image?");
            goto fail;
        }
    }

    ret = DIV_ROUND_UP(st.st_size, BDRV_SECTOR_SIZE);
    client->st_blksize = st.st_blksize;
    client->st_size = st.st_size;
    client->has_discard = true;
    client->last_sync = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    client->filename = g_strdup(filename);
    client->path = g_strdup(uri->path);
    client->metadata_path = g_strdup_printf("%s.qemu_md", client->path);

    goto out;
fail:
    quobyte_client_close(client);
out:
    uri_free(uri);
    return ret;
}

static int quobyte_file_open(BlockDriverState *bs, QDict *options, int flags,
                             Error **errp) {
    QuobyteClient *client = bs->opaque;
    int64_t ret;
    QemuOpts *opts;
    Error *local_err = NULL;

    client->aio_context = bdrv_get_aio_context(bs);

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto out;
    }
    ret = quobyte_client_open(client, qemu_opt_get(opts, "filename"),
                          (flags & BDRV_O_RDWR) ? O_RDWR : O_RDONLY,
                          errp, bs->open_flags);
    if (ret < 0) {
        goto out;
    }

    client->cluster_size = quobyte_get_object_size(client->fh);

    if (!(flags & BDRV_O_INACTIVE)) {
        quobyte_allocmap_init(client);
        quobyte_read_metadata(client);
    }

    bs->total_sectors = ret;
    bs->supported_write_flags = BDRV_REQ_FUA;
    bs->supported_zero_flags = BDRV_REQ_MAY_UNMAP;

    ret = 0;
out:
    qemu_opts_del(opts);
    return ret;
}

static QemuOptsList quobyte_create_opts = {
    .name = "quobyte-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(quobyte_create_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "Virtual disk size"
        },
        { /* end of list */ }
    }
};

static int coroutine_fn quobyte_file_co_create_opts(const char *url, QemuOpts *opts,
                                                    Error **errp)
{
    int64_t ret = 0, total_size = 0;
    QuobyteClient *client = g_new0(QuobyteClient, 1);

    client->aio_context = qemu_get_aio_context();

    /* Read out options */
    total_size = ROUND_UP(qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0),
                          BDRV_SECTOR_SIZE);

    ret = quobyte_client_open(client, url, O_CREAT | O_RDWR, errp, 0);
    if (ret < 0) {
        goto out;
    }
    ret = quobyte_ftruncate(client->fh, total_size) ? -errno : 0;
    if (!ret) {
        client->cluster_size = quobyte_get_object_size(client->fh);
        client->st_size = total_size;
        quobyte_allocmap_init(client);
        quobyte_allocmap_set_unallocated(client, 0, total_size);
    }
out:
    quobyte_client_close(client);
    g_free(client);
    return ret;
}

static int64_t quobyte_get_allocated_file_size(BlockDriverState *bs)
{
    QuobyteClient *client = bs->opaque;
    return quobyte_get_allocated_bytes(client->fh);
}

static int coroutine_fn
quobyte_file_co_truncate(BlockDriverState *bs, int64_t offset,
                         PreallocMode prealloc, Error **errp)
{
    QuobyteClient *client = bs->opaque;
    uint64_t old_size = client->st_size;
    int ret;

    if (prealloc != PREALLOC_MODE_OFF) {
        error_setg(errp, "Unsupported preallocation mode '%s'",
                   PreallocMode_str(prealloc));
        return -ENOTSUP;
    }

    ret = quobyte_ftruncate(client->fh, offset) ? -errno : 0;
    if (ret < 0) {
        error_setg_errno(errp, -ret, "Failed to truncate file");
        return ret;
    }

    client->st_size = offset;
    if (offset > old_size) {
        fprintf(stderr, "quobyte_file_co_truncate: size increased from %" PRIu64" to %" PRIu64 ". threating new clusters as unallocated\n", old_size, client->st_size);
        client->allocmap_size = DIV_ROUND_UP(client->st_size, client->cluster_size);
        client->allocmap = g_try_realloc(client->allocmap, BITS_TO_LONGS(client->allocmap_size) * sizeof(unsigned long));
        quobyte_allocmap_set_unallocated(client, old_size, client->st_size - old_size);
    } else if (offset < old_size) {
        quobyte_allocmap_init(client);
    }

    return 0;
}

static void quobyte_attach_aio_context(BlockDriverState *bs,
                                       AioContext *new_context)
{
    QuobyteClient *client = bs->opaque;
    client->aio_context = new_context;
}

static void quobyte_detach_aio_context(BlockDriverState *bs)
{

}

static int quobyte_reopen_prepare(BDRVReopenState *state,
                                  BlockReopenQueue *queue, Error **errp)
{
    return 0;
}

static int quobyte_get_info(BlockDriverState *bs, BlockDriverInfo *bdi)
{
    QuobyteClient *client = bs->opaque;
    bdi->cluster_size = client->cluster_size;
    return 0;
}

static void quobyte_refresh_limits(BlockDriverState *bs, Error **errp)
{
    QuobyteClient *client = bs->opaque;
    bs->bl.request_alignment = client->st_blksize;
    bs->bl.pdiscard_alignment = pow2ceil(client->cluster_size);
    bs->bl.pwrite_zeroes_alignment = pow2ceil(client->cluster_size);
    bs->bl.max_pdiscard = 1 << 26; /* 64 MByte */
}

static void coroutine_fn quobyte_co_invalidate_cache(BlockDriverState *bs,
                                                     Error **errp) {
    QuobyteClient *client = bs->opaque;
    fprintf(stderr, "quobyte_co_invalidate_cache invoked\n");
    if (quobyte_lock_fcntl(client->fh, 0, 1, F_SETLK, F_WRLCK)) {
        error_setg(errp, "Could not set exclusive lock, is another process using this image?");
        return;
    }
    quobyte_allocmap_init(client);
    quobyte_read_metadata(client);
}

static int quobyte_inactivate(BlockDriverState *bs) {
    QuobyteClient *client = bs->opaque;
    fprintf(stderr, "quobyte_inactivate invoked\n");
    quobyte_write_metadata(client);
    g_free(client->metadata_path);
    client->metadata_path = NULL;
    quobyte_lock_fcntl(client->fh, 0, 1, F_SETLK, F_UNLCK);
    return 0;
}


static BlockDriver bdrv_quobyte = {
    .format_name                    = "quobyte",
    .protocol_name                  = "quobyte",

    .instance_size                  = sizeof(QuobyteClient),
    .bdrv_needs_filename            = true,
    .create_opts                    = &quobyte_create_opts,

    .bdrv_has_zero_init             = bdrv_has_zero_init_1,
    .bdrv_get_allocated_file_size   = quobyte_get_allocated_file_size,
    .bdrv_get_info                  = quobyte_get_info,
    .bdrv_co_truncate               = quobyte_file_co_truncate,
    .bdrv_refresh_limits            = quobyte_refresh_limits,

    .bdrv_file_open                 = quobyte_file_open,
    .bdrv_close                     = quobyte_file_close,
    .bdrv_co_create_opts            = quobyte_file_co_create_opts,
    .bdrv_reopen_prepare            = quobyte_reopen_prepare,

    .bdrv_co_preadv                 = quobyte_co_preadv,
    .bdrv_co_pwritev                = quobyte_co_pwritev,
    .bdrv_co_flush_to_disk          = quobyte_co_flush,
    .bdrv_co_pdiscard               = quobyte_co_pdiscard,
    .bdrv_co_pwrite_zeroes          = quobyte_co_pwrite_zeroes,

    .bdrv_co_invalidate_cache       = quobyte_co_invalidate_cache,
    .bdrv_inactivate                = quobyte_inactivate,

    .bdrv_attach_aio_context        = quobyte_attach_aio_context,
    .bdrv_detach_aio_context        = quobyte_detach_aio_context,
};

static void quobyte_block_init(void)
{
    bdrv_register(&bdrv_quobyte);
}

block_init(quobyte_block_init);
