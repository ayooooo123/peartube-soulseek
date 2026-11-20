#ifndef PEARTUBE_SOULSEEK_H
#define PEARTUBE_SOULSEEK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct slsk_client slsk_client_t;

typedef struct slsk_state {
  uint8_t connected;
  uint8_t logged_in;
  uint32_t privileges;
  uint16_t listen_port;
} slsk_state_t;

typedef struct slsk_file {
  char *username;
  uint8_t slots;
  uint32_t queue;
  uint32_t speed;
  char *filename;
  uint64_t size;
  int64_t bitrate;      /* -1 when absent */
  int64_t sample_rate;  /* -1 when absent */
  int64_t bit_depth;    /* -1 when absent */
  int64_t length_secs;  /* -1 when absent */
} slsk_file_t;

typedef struct slsk_file_list {
  slsk_file_t *items;
  size_t len;
  size_t cap;
} slsk_file_list_t;

typedef struct slsk_download_result {
  char *path;
  uint64_t size;
  uint64_t resumed_from;
} slsk_download_result_t;

typedef void (*slsk_log_cb)(
  void *ctx,
  const char *level,
  const char *event,
  const char *message
);

typedef void (*slsk_state_done_cb)(
  void *req_ctx,
  const char *err,
  slsk_state_t state
);

typedef void (*slsk_files_done_cb)(
  void *req_ctx,
  const char *err,
  slsk_file_list_t *list
);

typedef void (*slsk_progress_cb)(
  void *req_ctx,
  uint64_t bytes_downloaded,
  uint64_t total_bytes,
  double speed_bytes_per_sec,
  int64_t queue_place, /* -1 when unknown */
  const char *phase
);

typedef void (*slsk_download_done_cb)(
  void *req_ctx,
  const char *err,
  slsk_download_result_t *result
);

slsk_client_t *slsk_client_new(uint16_t listen_port);
void slsk_client_free(slsk_client_t *client);

slsk_state_t slsk_client_state(const slsk_client_t *client);

void slsk_client_set_logger(
  slsk_client_t *client,
  slsk_log_cb cb,
  void *ctx
);

void slsk_client_login_async(
  const slsk_client_t *client,
  const char *server,
  uint16_t port,
  const char *username,
  const char *password,
  slsk_state_done_cb done,
  void *req_ctx
);

void slsk_client_search_async(
  const slsk_client_t *client,
  const char *query,
  uint64_t timeout_ms,
  slsk_files_done_cb done,
  void *req_ctx
);

void slsk_client_browse_async(
  const slsk_client_t *client,
  const char *username,
  uint64_t timeout_ms,
  slsk_files_done_cb done,
  void *req_ctx
);

void slsk_client_download_async(
  const slsk_client_t *client,
  const char *username,
  const char *filename,
  const char *dest_path,
  slsk_progress_cb on_progress,
  slsk_download_done_cb done,
  void *req_ctx
);

void slsk_file_list_free(slsk_file_list_t *list);
void slsk_download_result_free(slsk_download_result_t *res);

#ifdef __cplusplus
}
#endif

#endif /* PEARTUBE_SOULSEEK_H */
