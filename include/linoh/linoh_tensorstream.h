#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "linoh/linoh_c.h"

typedef struct linoh_tensorstream linoh_tensorstream_t;

typedef struct {
    uint64_t    tensor_id;
    uint32_t    total_shards;
    uint32_t    timeout_ms;
    linoh_multimodal_channel_t channel_type;
} linoh_tensorstream_config_t;

linoh_tensorstream_t *linoh_tensorstream_create(
    linoh_connection_t *conn,
    const linoh_tensorstream_config_t *config);

void linoh_tensorstream_free(linoh_tensorstream_t *ts);

size_t linoh_tensorstream_send_shard(
    linoh_tensorstream_t *ts,
    uint32_t shard_idx,
    const uint8_t *data,
    size_t data_len,
    int is_last);

int linoh_tensorstream_recv_one(linoh_tensorstream_t *ts);

int linoh_tensorstream_is_complete(linoh_tensorstream_t *ts);

size_t linoh_tensorstream_received_count(linoh_tensorstream_t *ts);

size_t linoh_tensorstream_total_size(linoh_tensorstream_t *ts);

size_t linoh_tensorstream_copy_to(
    linoh_tensorstream_t *ts,
    uint8_t *buf,
    size_t buf_size);

uint64_t linoh_tensorstream_tensor_id(linoh_tensorstream_t *ts);

uint32_t linoh_tensorstream_timeout_ms(linoh_tensorstream_t *ts);

#ifdef __cplusplus
}
#endif
