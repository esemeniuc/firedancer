#define BLOCKHASH_LG_RING_CNT 4UL
#define FD_TILE_TEST
#include "fd_resolv_tile.c"

char const *
fd_vinyl_strerror( int err ) {
  (void)err;
  return "test vinyl stub";
}

#define TEST_BAM_RESOLVE_CTX_T       fd_resolv_ctx_t
#define TEST_BAM_RESOLVE_OUT_CNT     3UL
#define TEST_BAM_RESOLVE_BAM_OUT_IDX 2UL
#define TEST_BAM_RESOLVE_HAS_REPLAY  1
#define TEST_BAM_RESOLVE_IN_KIND     IN_KIND_DEDUP
#include "../../disco/bam/test_bam_resolve_common.c"
