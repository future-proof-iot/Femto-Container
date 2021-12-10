/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "femtocontainer/femtocontainer.h"

uint32_t bpf_vm_store_local(bpf_t *bpf, uint32_t key, uint32_t value, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)a3;
    (void)a4;
    (void)a5;
    return (uint32_t)bpf_store_update_local(bpf, key, value);
}

uint32_t bpf_vm_store_global(bpf_t *bpf, uint32_t key, uint32_t value, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;
    return (uint32_t)bpf_store_update_global(key, value);
}

uint32_t bpf_vm_fetch_local(bpf_t *bpf, uint32_t key, uint32_t value, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;
    if (bpf_store_allowed(bpf, (void*)value, sizeof(uint32_t)) < 0) {
        return -1;
    }
    return (uint32_t)bpf_store_fetch_local(bpf, key, (uint32_t*)(uintptr_t)value);
}

uint32_t bpf_vm_fetch_global(bpf_t *bpf, uint32_t key, uint32_t value, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)bpf;
    (void)a3;
    (void)a4;
    (void)a5;
    if (bpf_store_allowed(bpf, (void*)value, sizeof(uint32_t)) < 0) {
        return -1;
    }
    return (uint32_t)bpf_store_fetch_global(key, (uint32_t*)(uintptr_t)value);
}
