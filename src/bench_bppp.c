/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdint.h>

#include "../include/secp256k1_bppp.h"
#include "../include/secp256k1.h"
#include "util.h"
#include "bench.h"

#include "group.h"
#include "scalar.h"

#define MAX_PROOF_SIZE 500

struct secp256k1_ecmult_multi_batch
{
    secp256k1_ge *points;
    secp256k1_scalar *scalars;
    size_t n_members;
    size_t capacity;
};

typedef struct
{
    secp256k1_context *ctx;
    secp256k1_bppp_generators *gens;
    secp256k1_scratch_space *scratch;
    secp256k1_pedersen_commitment commit;
    unsigned char *proofs;
    unsigned char blind[32];
    unsigned char nonce[32];
    size_t proof_len;
    size_t n_bits;
    size_t base;
    uint64_t min_value;
    uint64_t value;
} bench_bppp_data;

typedef struct
{
    secp256k1_context *ctx;
    secp256k1_bppp_generators *gens;
    secp256k1_scratch_space *scratch;
    secp256k1_pedersen_commitment commit;
    unsigned char *proofs;
    unsigned char blind[32];
    unsigned char nonce[32];
    size_t proof_len;
    size_t n_bits;
    size_t base;
    uint64_t min_value;
    uint64_t value;
    struct secp256k1_ecmult_multi_batch *range_batch;
    size_t batch_size;
} bench_bppp_batch_data;

static void bench_bppp_setup(void *arg)
{
    bench_bppp_data *data = (bench_bppp_data *)arg;

    data->min_value = 0;
    data->value = 100;
    data->proof_len = MAX_PROOF_SIZE;
    memset(data->blind, 0x77, 32);
    memset(data->nonce, 0x0, 32);
    CHECK(secp256k1_pedersen_commit(data->ctx, &data->commit, data->blind, data->value, secp256k1_generator_h));

    CHECK(secp256k1_bppp_rangeproof_prove(data->ctx, data->scratch, data->gens, secp256k1_generator_h, data->proofs, &data->proof_len, data->n_bits, data->base, data->value, 0, &data->commit, data->blind, data->nonce, NULL, 0));
    CHECK(secp256k1_bppp_rangeproof_verify(data->ctx, data->scratch, data->gens, secp256k1_generator_h, data->proofs, data->proof_len, data->n_bits, data->base, data->min_value, &data->commit, NULL, 0));
}

static void bench_batch_bppp_setup(void *arg)
{
    bench_bppp_batch_data *data = (bench_bppp_batch_data *)arg;

    data->min_value = 0;
    data->value = 100;
    data->proof_len = MAX_PROOF_SIZE;
    memset(data->blind, 0x77, 32);
    memset(data->nonce, 0x0, 32);
    CHECK(secp256k1_pedersen_commit(data->ctx, &data->commit, data->blind, data->value, secp256k1_generator_h));
}

static void bench_bppp_prove(void *arg, int iters)
{
    bench_bppp_data *data = (bench_bppp_data *)arg;
    int i;

    for (i = 0; i < iters; i++)
    {
        data->nonce[1] = i;
        data->nonce[2] = i >> 8;
        data->nonce[3] = i >> 16;
        data->proof_len = MAX_PROOF_SIZE;
        CHECK(secp256k1_bppp_rangeproof_prove(data->ctx, data->scratch, data->gens, secp256k1_generator_h, &data->proofs[i * MAX_PROOF_SIZE], &data->proof_len, data->n_bits, data->base, data->value, 0, &data->commit, data->blind, data->nonce, NULL, 0));
    }
}

static void bench_bppp_verify(void *arg, int iters)
{
    bench_bppp_data *data = (bench_bppp_data *)arg;
    int i;

    for (i = 0; i < iters; i++)
    {
        CHECK(secp256k1_bppp_rangeproof_verify(data->ctx, data->scratch, data->gens, secp256k1_generator_h, &data->proofs[i * MAX_PROOF_SIZE], data->proof_len, data->n_bits, data->base, data->min_value, &data->commit, NULL, 0));
    }
}

static void bench_bppp_batch_prove(void *arg, int iters)
{
    bench_bppp_batch_data *data = (bench_bppp_batch_data *)arg;

    int i = 0;
    size_t j = 0;
    size_t threshold;

    for (i = 0; i < iters; i++)
    {
        threshold = 100000;
        data->range_batch = secp256k1_bppp_rangeproof_batch_create(data->ctx, threshold);
        data->nonce[1] = i;
        data->nonce[2] = i >> 8;
        data->nonce[3] = i >> 16;
        for (j = 0; j < data->batch_size; j++)
        {
            data->nonce[1] = i;
            data->nonce[2] = i >> 8;
            data->nonce[3] = i >> 16;
            data->proof_len = MAX_PROOF_SIZE;
            CHECK(secp256k1_bppp_rangeproof_prove(data->ctx, data->scratch, data->gens, secp256k1_generator_h, &data->proofs[i * MAX_PROOF_SIZE], &data->proof_len, data->n_bits, data->base, data->value, 0, &data->commit, data->blind, data->nonce, NULL, 0));
        }
    }
}

static void bench_bppp_batch_verify(void *arg, int iters)
{
    bench_bppp_batch_data *data = (bench_bppp_batch_data *)arg;

    int i = 0;
    size_t j = 0;
    size_t threshold = 100000;
    for (i = 0; i < iters; i++)
    {
        data->nonce[1] = i;
        data->nonce[2] = i >> 8;
        data->nonce[3] = i >> 16;
        data->range_batch = secp256k1_bppp_rangeproof_batch_create(data->ctx, threshold);
        for (j = 0; j < data->batch_size; j++)
        {
            CHECK(secp256k1_bppp_rangeproof_batch_add(data->ctx, data->scratch, data->gens, secp256k1_generator_h, &data->proofs[i * MAX_PROOF_SIZE], /*data->proof_len*/ 456, data->n_bits, data->base, data->min_value, &data->commit, data->range_batch));
        }
        CHECK(secp256k1_bppp_rangeproof_batch_verify(data->ctx, data->scratch, data->range_batch));
        secp256k1_bppp_rangeproof_batch_destroy(data->ctx, data->range_batch);
    }
}

int main(void)
{
    bench_bppp_data data;
    int iters = get_iters(64);
    char test_name[64];
    bench_bppp_batch_data batch_data;
    size_t threshold;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    data.gens = secp256k1_bppp_generators_create(data.ctx, 24);
    data.scratch = secp256k1_scratch_space_create(data.ctx, 80 * 1024);
    data.proofs = (unsigned char *)malloc(iters * MAX_PROOF_SIZE);

    data.n_bits = 1ul << 6;
    data.base = 16;

    sprintf(test_name, "bppp_prove_64bits_16base");
    run_benchmark(test_name, bench_bppp_prove, bench_bppp_setup, NULL, &data, 4, iters);

    sprintf(test_name, "bppp_verify_64bits_16base");
    run_benchmark(test_name, bench_bppp_verify, bench_bppp_setup, NULL, &data, 20, iters);

    batch_data.ctx = data.ctx;
    batch_data.gens = data.gens;
    batch_data.scratch = secp256k1_scratch_space_create(batch_data.ctx, 800 * 1024);
    batch_data.proofs = data.proofs;
    batch_data.n_bits = 1ul << 6;
    batch_data.base = 16;

    threshold = 100000; /* batch size -> should we init this somewhere else? */

    batch_data.range_batch = secp256k1_bppp_rangeproof_batch_create(batch_data.ctx, threshold);
    batch_data.batch_size = 100;
    sprintf(test_name, "batch_prove_batch_size_100");
    run_benchmark(test_name, bench_bppp_batch_prove, bench_batch_bppp_setup, NULL, &batch_data, 1, get_iters(1));
    sprintf(test_name, "batch_verify_batch_size_100");
    run_benchmark(test_name, bench_bppp_batch_verify, bench_batch_bppp_setup, NULL, &batch_data, 20, get_iters(10));


    secp256k1_scratch_space_destroy(batch_data.ctx, batch_data.scratch);
    batch_data.scratch = secp256k1_scratch_space_create(batch_data.ctx, 800 * 1024);
    batch_data.range_batch = secp256k1_bppp_rangeproof_batch_create(batch_data.ctx, threshold);
    batch_data.batch_size = 1000;
    sprintf(test_name, "batch_prove_batch_size_1000");
    run_benchmark(test_name, bench_bppp_batch_prove, bench_batch_bppp_setup, NULL, &batch_data, 1, get_iters(1));
    sprintf(test_name, "batch_verify_batch_size_1000");
    run_benchmark(test_name, bench_bppp_batch_verify, bench_batch_bppp_setup, NULL, &batch_data, 20, get_iters(10));


    secp256k1_scratch_space_destroy(batch_data.ctx, batch_data.scratch);
    batch_data.scratch = secp256k1_scratch_space_create(batch_data.ctx, 800 * 1024);
    batch_data.range_batch = secp256k1_bppp_rangeproof_batch_create(batch_data.ctx, threshold);
    batch_data.batch_size = 10000;
    sprintf(test_name, "batch_prove_batch_size_10000");
    run_benchmark(test_name, bench_bppp_batch_prove, bench_batch_bppp_setup, NULL, &batch_data, 1, get_iters(1));
    sprintf(test_name, "batch_verify_batch_size_10000");
    run_benchmark(test_name, bench_bppp_batch_verify, bench_batch_bppp_setup, NULL, &batch_data, 20, get_iters(10));


    secp256k1_scratch_space_destroy(data.ctx, data.scratch);
    secp256k1_scratch_space_destroy(batch_data.ctx, batch_data.scratch);
    free(data.proofs);
    secp256k1_bppp_generators_destroy(data.ctx, data.gens);
    secp256k1_context_destroy(data.ctx);

    return 0;
}
