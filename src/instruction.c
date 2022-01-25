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

#include "femtocontainer/femtocontainer.h"
#include "femtocontainer/builtin_shared.h"
#include "femtocontainer/builtin_calls.h"
#include "femtocontainer/instruction.h"
#include "femtocontainer/config.h"

#define ENABLE_DEBUG (1)
#include "debug.h"

static inline size_t opcode2size(uint8_t opcode)
{
    static const size_t lookup[] = {
        [0] = 4,
        [1] = 2,
        [2] = 1,
        [3] = 8,
    };

    unsigned size = (opcode >> 3) & 0x03;
    return lookup[size];
}
static int _check_mem(const bpf_t *bpf, uint8_t size, const intptr_t addr, uint8_t type)
{
    const intptr_t end = addr + size;
    for (const bpf_mem_region_t *region = &bpf->stack_region; region; region = region->next) {
        if ((addr >= (intptr_t)(region->start)) &&
                (end <= (intptr_t)(region->start + region->len)) &&
                (region->flag & type)) {

            return 0;
        }
    }

    DEBUG("Denied access to %p with len %u\n",(void*)addr, end - addr);
    return -1;
}

static inline int _check_load(const bpf_t *bpf, uint8_t size, const intptr_t addr)
{
    return _check_mem(bpf, size, addr, BPF_MEM_REGION_READ);
}

static inline int _check_store(const bpf_t *bpf, uint8_t size, const intptr_t addr)
{
    return _check_mem(bpf, size, addr, BPF_MEM_REGION_WRITE);
}

int fc_store_allowed(const bpf_t *bpf, void *addr, size_t size)
{
    return _check_store(bpf, size, (intptr_t)addr);
}

int fc_load_allowed(const bpf_t *bpf, void *addr, size_t size)
{
    return _check_load(bpf, size, (intptr_t)addr);
}

static f12r_call_t _fc_get_call(uint32_t num)
{
    switch(num) {
        case BPF_FUNC_BPF_STORE_LOCAL:
            return &bpf_vm_store_local;
        case BPF_FUNC_BPF_STORE_GLOBAL:
            return &bpf_vm_store_global;
        case BPF_FUNC_BPF_FETCH_LOCAL:
            return &bpf_vm_fetch_local;
        case BPF_FUNC_BPF_FETCH_GLOBAL:
            return &bpf_vm_fetch_global;
        default:
            return NULL;
    }
}

/* ALU type instructions */
static int _alu64(uint8_t opcode, uint64_t *src, uint64_t *dst)
{
    uint8_t instruction = opcode & BPF_INSTRUCTION_ALU_OP_MASK;

    switch (instruction) {
        case BPF_INSTRUCTION_ALU_ADD:
            *dst += *src;
            break;
        case BPF_INSTRUCTION_ALU_SUB:
            *dst -= *src;
            break;
        case BPF_INSTRUCTION_ALU_MUL:
            *dst *= *src;
            break;
        case BPF_INSTRUCTION_ALU_DIV:
            *dst /= *src;
            break;
        case BPF_INSTRUCTION_ALU_OR:
            *dst |= *src;
            break;
        case BPF_INSTRUCTION_ALU_AND:
            *dst &= *src;
            break;
        case BPF_INSTRUCTION_ALU_LSH:
            *dst <<= *src;
            break;
        case BPF_INSTRUCTION_ALU_RSH:
            *dst >>= *src;
            break;
        case BPF_INSTRUCTION_ALU_NEG:
            *dst = -*dst;
            break;
        case BPF_INSTRUCTION_ALU_MOD:
            *dst %= *src;
            break;
        case BPF_INSTRUCTION_ALU_XOR:
            *dst ^= *src;
            break;
        case BPF_INSTRUCTION_ALU_MOV:
            *dst = *src;
            break;
        case BPF_INSTRUCTION_ALU_ARSH:
            (*(int64_t*)dst) >>= *src;
            break;
        default:
            return BPF_ILLEGAL_INSTRUCTION;
    }

    return BPF_OK;
}

static int _alu32(uint8_t opcode, uint64_t *src, uint64_t *dst)
{
    int res = _alu64(opcode, src, dst);
    *dst &= UINT32_MAX;
    return res;
}

/* Load instructions */
static int _ld(const bpf_instruction_t **pc, uint64_t *src, uint64_t *dst)
{
    (void)src;
    const bpf_instruction_t *instruction = *pc;
    uint8_t opcode = instruction->opcode;

    switch(opcode) {
        case 0x18: /* LDDW */
            *dst = ((uint64_t)instruction[0].immediate) +
                    ((uint64_t)instruction[1].immediate << 32);
            (*pc)++;
            break;
        /* Other BPF instructions are Linux socket/filter specific */
        default:
            return BPF_ILLEGAL_INSTRUCTION;
    }

    return BPF_OK;
}

/* Returns 1 if the code should jump, zero on no jump, negative on error */
static int _jump_cond(uint8_t opcode, uint64_t *src, uint64_t *dst)
{
    uint8_t instruction = opcode & BPF_INSTRUCTION_ALU_OP_MASK;

    switch (instruction) {
        case BPF_INSTRUCTION_BRANCH_JA:
            return 1;
        case BPF_INSTRUCTION_BRANCH_JEQ:
            return (*dst == *src);
        case BPF_INSTRUCTION_BRANCH_JGT:
            return (*dst > *src);
        case BPF_INSTRUCTION_BRANCH_JGE:
            return (*dst >= *src);
        case BPF_INSTRUCTION_BRANCH_JLT:
            return (*dst < *src);
        case BPF_INSTRUCTION_BRANCH_JLE:
            return (*dst <= *src);
        case BPF_INSTRUCTION_BRANCH_JSET:
            return (*dst & *src);
        case BPF_INSTRUCTION_BRANCH_JNE:
            return (*dst != *src);
        case BPF_INSTRUCTION_BRANCH_JSGT:
            return (*(int64_t*)dst > *(int64_t*)src);
        case BPF_INSTRUCTION_BRANCH_JSGE:
            return (*(int64_t*)dst >= *(int64_t*)src);
        case BPF_INSTRUCTION_BRANCH_JSLT:
            return (*(int64_t*)dst < *(int64_t*)src);
        case BPF_INSTRUCTION_BRANCH_JSLE:
            return (*(int64_t*)dst <= *(int64_t*)src);
        default:
            return BPF_ILLEGAL_INSTRUCTION;
    }
}

static int _jump(const bpf_instruction_t **pc, uint64_t *src, uint64_t *dst)
{
    const bpf_instruction_t *instruction = *pc;

    int res = _jump_cond(instruction->opcode, src, dst);
    if (res < 0) {
        return res;
    }
    if (res > 0) {
        *pc += instruction->offset;
    }
    return BPF_OK;
}

static int _load_x(const bpf_t *bpf, const bpf_instruction_t *instruction, uint64_t *regmap)
{
    const uint8_t *src = (uint8_t*)(uintptr_t)regmap[instruction->src];
    intptr_t addr = (intptr_t)(src + instruction->offset);

    if (_check_load(bpf, opcode2size(instruction->opcode), addr) < 0) {
        return BPF_ILLEGAL_MEM;
    }

    switch(instruction->opcode) {
        case 0x79:
            regmap[instruction->dst] = *(const uint64_t*)(src + instruction->offset);
            break;
        case 0x61:
            regmap[instruction->dst] = *(const uint32_t*)(src + instruction->offset);
            break;
        case 0x69:
            regmap[instruction->dst] = *(const uint16_t*)(src + instruction->offset);
            break;
        case 0x71:
            regmap[instruction->dst] = *(const uint8_t*)(src + instruction->offset);
            break;
        default:
            return BPF_ILLEGAL_INSTRUCTION;
    }
    return BPF_OK;
}

static int _store(const bpf_t *bpf, const bpf_instruction_t *instruction, uint64_t *regmap)
{
    uint8_t *dst = (uint8_t*)(uintptr_t)regmap[instruction->dst];
    intptr_t addr = (intptr_t)(dst + instruction->offset);

    if (_check_store(bpf, opcode2size(instruction->opcode), addr) < 0) {
        return BPF_ILLEGAL_MEM;
    }

    switch(instruction->opcode) {
        case 0x7a:
            *(uint64_t*)addr = instruction->immediate;
            break;
        case 0x62:
            *(uint32_t*)addr = instruction->immediate;
            break;
        case 0x6a:
            *(uint16_t*)addr = instruction->immediate;
            break;
        case 0x72:
            *(uint8_t*)addr = instruction->immediate;
            break;
        default:
            return BPF_ILLEGAL_INSTRUCTION;
    }
    return BPF_OK;
}

static int _store_x(const bpf_t *bpf, const bpf_instruction_t *instruction, uint64_t *regmap)
{
    uint8_t *dst = (uint8_t*)(uintptr_t)regmap[instruction->dst];
    intptr_t addr = (intptr_t)(dst + instruction->offset);

    if (_check_store(bpf, opcode2size(instruction->opcode), addr) < 0) {
        return BPF_ILLEGAL_MEM;
    }

    switch(instruction->opcode) {
        case 0x7b:
            *(uint64_t*)addr = regmap[instruction->src];
            break;
        case 0x63:
            *(uint32_t*)addr = regmap[instruction->src];
            break;
        case 0x6b:
            *(uint16_t*)addr = regmap[instruction->src];
            break;
        case 0x73:
            *(uint8_t*)addr = regmap[instruction->src];
            break;
        default:
            return BPF_ILLEGAL_INSTRUCTION;
    }
    return BPF_OK;
}

static int _instruction(bpf_t *bpf, uint64_t *regmap,
                        const bpf_instruction_t **pc)
{
    (void)bpf;
    const bpf_instruction_t *instruction = *pc;

    /* Setup values for alu-based instructions */
    int64_t immediate = instruction->immediate;
    uint64_t *dst = &regmap[instruction->dst];
    uint64_t *src = (instruction->opcode & BPF_INSTRUCTION_ALU_S_MASK) ?
        &regmap[instruction->src] :
        (uint64_t*)&immediate;

    switch (instruction->opcode & BPF_INSTRUCTION_CLS_MASK) {
        case BPF_INSTRUCTION_CLS_ALU64:
            return _alu64(instruction->opcode, src, dst);
        case BPF_INSTRUCTION_CLS_ALU32:
            return _alu32(instruction->opcode, src, dst);
        case BPF_INSTRUCTION_CLS_BRANCH:
            return _jump(pc, src, dst);
        case BPF_INSTRUCTION_CLS_LD:
            return _ld(pc, src, dst);
        case BPF_INSTRUCTION_CLS_ST:
            return _store(bpf, instruction, regmap);
        case BPF_INSTRUCTION_CLS_STX:
            return _store_x(bpf, instruction, regmap);
        case BPF_INSTRUCTION_CLS_LDX:
            return _load_x(bpf, instruction, regmap);
        default:
            return BPF_ILLEGAL_INSTRUCTION;
    }
}

int bpf_run(bpf_t *bpf, const void *ctx, int64_t *result)
{
    uint64_t regmap[11] = { 0 };
    regmap[1] = (uint64_t)(uintptr_t)ctx;
    regmap[10] = (uint64_t)(uintptr_t)(bpf->stack + bpf->stack_size);
    bool end = false;

    int res = bpf_verify_preflight(bpf);
    if (res < 0) {
        return res;
    }

    const bpf_instruction_t *pc= (const bpf_instruction_t*)rbpf_text(bpf);

    while (!end) {
        int res = _instruction(bpf, regmap, &pc);
        if (res < 0) {
            if (pc->opcode == 0x85) {
                bpf_call_t call = _bpf_get_call(pc->immediate);
                if (call) {
                    regmap[0] = (*(call))(bpf,
                                          regmap[1],
                                          regmap[2],
                                          regmap[3],
                                          regmap[4],
                                          regmap[5]);
                }
                else {
                    return BPF_ILLEGAL_CALL;
                }
            }
            else if (pc->opcode == 0x95) {
                break;
            }
            else {
                intptr_t instruction = (uint8_t*)pc - bpf->application;
                DEBUG("Illegal %d, access PC: 0x%x, loc: %u\n", res, instruction, instruction/8 );
                return res;
            }
        }
        pc++;
        if ((uint8_t*)pc >= (bpf->application + bpf->application_len)) {
            end = true;
        }
    }

    *result = regmap[0];
    return BPF_OK;
}
