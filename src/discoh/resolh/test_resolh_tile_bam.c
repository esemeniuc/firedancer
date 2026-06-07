#define BLOCKHASH_LG_RING_CNT 4UL
#define FD_TILE_TEST
#include "fd_resolh_tile.c"

void
fd_ext_bank_release( void const * bank ) {
  (void)bank;
}

int
fd_ext_bank_load_account( void const *  bank,
                          int           fixed_root,
                          uchar const * addr,
                          uchar *       owner,
                          uchar *       data,
                          ulong *       data_sz ) {
  (void)bank;
  (void)fixed_root;
  (void)addr;
  (void)owner;
  (void)data;
  (void)data_sz;
  return 0;
}

#define TEST_BAM_RESOLVE_CTX_T                    fd_resolh_tile_t
#define TEST_BAM_RESOLVE_OUT_CNT                  2UL
#define TEST_BAM_RESOLVE_BAM_OUT_IDX              1UL
#define TEST_BAM_RESOLVE_IN_KIND                  FD_RESOLH_IN_KIND_FRAGMENT
#define TEST_BAM_RESOLVE_RUN_UNKNOWN_BLOCKHASH    1
#include "../../disco/bam/test_bam_resolve_common.c"
