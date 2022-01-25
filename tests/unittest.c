#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "femtocontainer/femtocontainer.h"
#include "femtocontainer/instruction.h"

static uint8_t _f12r_stack[512];

/* 2 load, 1 under test and the return */
#define NUM_INSTRUCTIONS    4

bpf_instruction_t boilerplate[] = {
    {
        .opcode = 0x79, /* LDXDW */
        .dst = 0,
        .src = 1,
    },
    {
        .opcode = 0x79, /* LDXDW */
        .dst = 2,
        .src = 1,
        .offset = 8,
    }
};

typedef struct {
    int64_t arg1;
    int64_t arg2;
    int64_t result;
} test_context_t;

typedef struct {
    f12r_header_t header;
    uint8_t rodata[68];
    uint64_t text[NUM_INSTRUCTIONS + 1];
} test_application_t;

typedef struct {
    bpf_instruction_t instruction;
    char *name;
    test_context_t context;
} test_content_t;

static const test_content_t tests[] = {
    {
        .instruction = {
            .opcode = 0x0f,
            .src = 2,
        },
        .name = "ALU Add",
        .context = {
            1,
            2,
            3,
        },
    },
};

#define NUM_TESTS   (sizeof(tests)/sizeof(test_content_t))

static test_application_t test_app;

static void add_instruction(const bpf_instruction_t *instr, test_application_t *test_app)
{
    test_app->header.data_len = 0;
    test_app->header.rodata_len = 68;
    test_app->header.text_len = sizeof(uint64_t) * NUM_INSTRUCTIONS;

    memcpy(&test_app->text[0], boilerplate, sizeof(boilerplate));
    memcpy(&test_app->text[2], instr, sizeof(bpf_instruction_t));
    static const bpf_instruction_t return_instr = {
        .opcode = BPF_INSTRUCTION_CLS_BRANCH | BPF_INSTRUCTION_BRANCH_EXIT
    };
    memcpy(&test_app->text[NUM_INSTRUCTIONS - 1], &return_instr, sizeof(bpf_instruction_t));
}

int main()
{
    for (size_t idx = 0; idx < NUM_TESTS; idx++) {
        add_instruction(&tests[idx].instruction, &test_app);

        f12r_t femtoc = {
            .application = (uint8_t*)&test_app,
            .application_len = sizeof(test_app),
            .stack = _f12r_stack,
            .stack_size = sizeof(_f12r_stack),
        };

        f12r_setup(&femtoc);
        int64_t res = 0;
        int result = f12r_execute_ctx(&femtoc,
                                      (void*)&tests[idx].context,
                                      sizeof(test_context_t), &res);
        assert(result == FC_OK);
        assert(res == tests[idx].context.result);
    }

    return 0;
}
