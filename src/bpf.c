/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdint.h>
#include <stdbool.h>
#include "assert.h"

#include "femtocontainer/femtocontainer.h"
#include "femtocontainer/instruction.h"
#include "femtocontainer/config.h"

extern int femto_container_run(femto_container_t *bpf, const void *ctx, int64_t *result);

static int _execute(femto_container_t *bpf, void *ctx, int64_t *result)
{
    assert(bpf->flags & FC_FLAG_SETUP_DONE);
    return femto_container_run(bpf, ctx, result);
}

int bpf_execute(femto_container_t *bpf, void *ctx, size_t ctx_len, int64_t *result)
{
    (void)ctx;
    (void)ctx_len;
    bpf->arg_region.start = NULL;
    bpf->arg_region.len = 0;

    return _execute(bpf, ctx, result);
}

int bpf_execute_ctx(femto_container_t *bpf, void *ctx, size_t ctx_len, int64_t *result)
{
    bpf->arg_region.start = ctx;
    bpf->arg_region.len = ctx_len;
    bpf->arg_region.flag = (FC_MEM_REGION_READ | FC_MEM_REGION_WRITE);

    return _execute(bpf, ctx, result);
}

void bpf_setup(femto_container_t *bpf)
{
    bpf->stack_region.start = bpf->stack;
    bpf->stack_region.len = bpf->stack_size;
    bpf->stack_region.flag = (FC_MEM_REGION_READ | FC_MEM_REGION_WRITE);
    bpf->stack_region.next = &bpf->data_region;

    bpf->data_region.start = femto_container_data(bpf);
    bpf->data_region.len = femto_container_header(bpf)->data_len;
    bpf->data_region.flag = (FC_MEM_REGION_READ | FC_MEM_REGION_WRITE);
    bpf->data_region.next = &bpf->rodata_region;

    bpf->rodata_region.start = femto_container_rodata(bpf);
    bpf->rodata_region.len = femto_container_header(bpf)->rodata_len;
    bpf->rodata_region.flag = FC_MEM_REGION_READ;
    bpf->rodata_region.next = &bpf->arg_region;

    bpf->arg_region.next = NULL;
    bpf->arg_region.start = NULL;
    bpf->arg_region.len = 0;

    bpf->flags |= FC_FLAG_SETUP_DONE;
}

void bpf_add_region(femto_container_t *bpf, fc_mem_region_t *region,
                    void *start, size_t len, uint8_t flags)
{
    region->next = bpf->arg_region.next;
    region->start = start;
    region->len = len;
    region->flag = flags;
    bpf->arg_region.next = region;
}

void fc_init(void)
{
    femto_container_store_init();
}
