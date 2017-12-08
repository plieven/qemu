/*
 * QEMU Block driver for native access to files on a Quobyte Volume
 *
 * Copyright (c) 2016-17 Peter Lieven <pl@kamp.de>
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
#include "qmp-commands.h"
#include "sysemu/sysemu.h"

#include "quobyte.h"

typedef struct QuobyteClient {
    struct quobyte_fh *fh;
    blksize_t st_blksize;
    AioContext *aio_context;
    bool has_discard;
    uint32_t cluster_size;
} QuobyteClient;

typedef struct QuobyteRequest {
  int result;
  int complete;
  struct quobyte_iocb iocb;
  Coroutine *co;
  QEMUBH *bh;
  QuobyteClient *client;
} QuobyteRequest;

#define QUOBYTE_CONCURRENT_REQS 8

static void quobyte_co_generic_bh_cb(void *opaque)
{
    QuobyteRequest *req = opaque;
    req->complete = 1;
    qemu_bh_delete(req->bh);
    qemu_coroutine_enter(req->co);
}

static void
quobyte_co_generic_cb(QuobyteRequest *req, int ret)
{
    req->result = ret;
    if (req->co) {
        req->bh = aio_bh_new(req->client->aio_context,
                             quobyte_co_generic_bh_cb, req);
        qemu_bh_schedule(req->bh);
    } else {
        req->complete = 1;
    }
}

static int quobyteAioContext = -1;

static void quobyte_co_init_request(QuobyteClient *client, QuobyteRequest *req)
{
    assert(quobyteAioContext >= 0);
    *req = (QuobyteRequest) {
        .co               = qemu_coroutine_self(),
        .client           = client,
        .iocb = (struct quobyte_iocb) { .io_context  = quobyteAioContext,
                                        .file_handle = client->fh,
                                      }
    };
}

static int
coroutine_fn quobyte_co_preadv(BlockDriverState *bs, uint64_t offset,
                               uint64_t bytes, QEMUIOVector *iov,
                               int flags)
{
    QuobyteClient *client = bs->opaque;
    QuobyteRequest req;

    quobyte_co_init_request(client, &req);
    req.iocb.op_code = QB_READ;
    req.iocb.offset = offset;
    req.iocb.length = bytes;

    if (iov->niov > 1) {
        req.iocb.buffer = g_malloc(bytes);
    } else {
        req.iocb.buffer = iov->iov[0].iov_base;
    }

    if (quobyte_aio_submit_with_callback(quobyteAioContext, &req.iocb,
                                         (void*) quobyte_co_generic_cb, &req)) {
        if (iov->niov > 1) {
            g_free(req.iocb.buffer);
        }
        return -EIO;
    }

    while (!req.complete) {
        qemu_coroutine_yield();
    }

    if (req.result > iov->size || req.result < 0) {
        if (iov->niov > 1) {
            g_free(req.iocb.buffer);
        }
        return -EIO;
    }

    if (iov->niov > 1) {
        qemu_iovec_from_buf(iov, 0, req.iocb.buffer, req.result);
        g_free(req.iocb.buffer);
    }

    /* zero pad short reads */
    if (req.result < iov->size) {
        qemu_iovec_memset(iov, req.result, 0, iov->size - req.result);
    }

    return 0;
}


static int
coroutine_fn quobyte_co_pwritev(BlockDriverState *bs, uint64_t offset,
                                uint64_t bytes, QEMUIOVector *iov,
                                int flags)
{
    QuobyteClient *client = bs->opaque;
    QuobyteRequest req;

    quobyte_co_init_request(client, &req);
    req.iocb.op_code = (flags & BDRV_REQ_FUA) ? QB_WRITE_SYNC : QB_WRITE;
    req.iocb.offset = offset;
    req.iocb.length = bytes;
    /* We sadly always have to create a bounce buffer since the guest may invalidate
     * the page while we are writing the data to the DATA SERVICE. As Quobyte
     * creates checksums for the payload this will lead to CRC errors otherwise. */
    req.iocb.buffer = g_malloc(bytes);
    qemu_iovec_to_buf(iov, 0, req.iocb.buffer, bytes);

    if (quobyte_aio_submit_with_callback(quobyteAioContext, &req.iocb,
                                         (void*) quobyte_co_generic_cb, &req)) {
        g_free(req.iocb.buffer);
        return -EIO;
    }

    while (!req.complete) {
        qemu_coroutine_yield();
    }

    g_free(req.iocb.buffer);

    if (req.result != bytes) {
        return -EIO;
    }

    return 0;
}

static int coroutine_fn quobyte_co_flush(BlockDriverState *bs)
{
    QuobyteClient *client = bs->opaque;
    QuobyteRequest req;

    quobyte_co_init_request(client, &req);
    req.iocb.op_code = QB_FSYNC;

    if (quobyte_aio_submit_with_callback(quobyteAioContext, &req.iocb,
                                         (void*) quobyte_co_generic_cb, &req)) {
        return -EIO;
    }

    while (!req.complete) {
        qemu_coroutine_yield();
    }

    if (req.result) {
        return -EIO;
    }

    return 0;
}

static int
coroutine_fn quobyte_co_pdiscard(BlockDriverState *bs, int64_t offset, int count)
{
    QuobyteClient *client = bs->opaque;
    QuobyteRequest req;

    if (!client->has_discard) {
        return -ENOTSUP;
    }

    quobyte_co_init_request(client, &req);
    req.iocb.op_code = QB_FALLOCATE;
    req.iocb.offset = offset;
    req.iocb.length = count;
    req.iocb.mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

    if (quobyte_aio_submit_with_callback(quobyteAioContext, &req.iocb,
                                         (void*) quobyte_co_generic_cb, &req)) {
        return -EIO;
    }

    while (!req.complete) {
        qemu_coroutine_yield();
    }

    if (req.result != count) {
        client->has_discard = false;
        return -ENOTSUP;
    }

    return 0;
}

static int
coroutine_fn quobyte_co_pwrite_zeroes(BlockDriverState *bs, int64_t offset,
                                      int count, BdrvRequestFlags flags)
{
    if (flags & BDRV_REQ_MAY_UNMAP) {
        return quobyte_co_pdiscard(bs, offset, count);
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

static void quobyte_client_close(QuobyteClient *client)
{
    quobyteClients--;
    if (client->fh) {
        quobyte_close(client->fh);
    }
    if (!quobyteClients && quobyteRegistry) {
        if (quobyteAioContext >= 0) {
            quobyte_aio_destroy(quobyteAioContext);
            quobyteAioContext = -1;
        }
        quobyte_destroy_adapter();
        g_free(quobyteRegistry);
        quobyteRegistry = NULL;
    }
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

        if (quobyte_create_adapter(uri->server)) {
            error_setg(errp, "Registration failed.");
            goto fail;
        }
        quobyteRegistry = g_strdup(uri->server);
    } else if (strncmp(uri->server, quobyteRegistry, strlen(quobyteRegistry))) {
        error_setg(errp, "All connections must go to the same Quobyte registry.");
        goto fail;
    }

    quobyteClients++;

    client->fh = quobyte_open(uri->path, flags | O_DIRECT, 0600);
    if (!client->fh) {
        error_setg(errp, "Failed to open/create file: %s", strerror(errno));
        goto fail;
    }

    ret = quobyte_fstat(client->fh, &st) ? -errno : 0;
    if (ret) {
        error_setg(errp, "Failed to fstat file: %s", strerror(-ret));
        goto fail;
    }

    ret = DIV_ROUND_UP(st.st_size, BDRV_SECTOR_SIZE);
    client->st_blksize = st.st_blksize;
    client->has_discard = true;
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

    if (quobyteAioContext < 0) {
        int concurrent_reqs = QUOBYTE_CONCURRENT_REQS;
        if (getenv("QUOBYTE_CONCURRENT_REQS")) {
            concurrent_reqs = atoi(getenv("QUOBYTE_CONCURRENT_REQS"));
            error_report("setting concurrent reqs to %d\n", concurrent_reqs);
        }
        quobyteAioContext = quobyte_aio_setup(concurrent_reqs);
        if (quobyteAioContext < 0) {
            ret = -errno;
            goto out;
        }
    }

    client->cluster_size = quobyte_get_object_size(client->fh);
    assert(client->cluster_size > 0);

    bs->total_sectors = ret;
    bs->supported_write_flags = BDRV_REQ_FUA;
    bs->supported_zero_flags = BDRV_REQ_MAY_UNMAP;

    ret = 0;
out:
    qemu_opts_del(opts);
    return ret;
}

static QemuOptsList quobyte_create_opts = {
    .name = "nfs-create-opts",
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

static int quobyte_file_create(const char *url, QemuOpts *opts, Error **errp)
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
    ret = quobyte_ftruncate(client->fh, total_size) ? errno : 0;
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

static int quobyte_file_truncate(BlockDriverState *bs, int64_t offset)
{
    QuobyteClient *client = bs->opaque;
    return quobyte_ftruncate(client->fh, offset) ? errno : 0;
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
    bdi->can_write_zeroes_with_unmap = true;
    return 0;
}

static void quobyte_refresh_limits(BlockDriverState *bs, Error **errp)
{
    QuobyteClient *client = bs->opaque;
    bs->bl.request_alignment = client->st_blksize;
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
    .bdrv_truncate                  = quobyte_file_truncate,
    .bdrv_refresh_limits            = quobyte_refresh_limits,

    .bdrv_file_open                 = quobyte_file_open,
    .bdrv_close                     = quobyte_file_close,
    .bdrv_create                    = quobyte_file_create,
    .bdrv_reopen_prepare            = quobyte_reopen_prepare,

    .bdrv_co_preadv                 = quobyte_co_preadv,
    .bdrv_co_pwritev                = quobyte_co_pwritev,
    .bdrv_co_flush_to_disk          = quobyte_co_flush,
    .bdrv_co_pdiscard               = quobyte_co_pdiscard,
    .bdrv_co_pwrite_zeroes          = quobyte_co_pwrite_zeroes,

    .bdrv_attach_aio_context        = quobyte_attach_aio_context,
    .bdrv_detach_aio_context        = quobyte_detach_aio_context,
};

static void quobyte_block_init(void)
{
    bdrv_register(&bdrv_quobyte);
}

block_init(quobyte_block_init);
