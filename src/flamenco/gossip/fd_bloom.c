#include "fd_bloom.h"

#include "../../util/rng/fd_rng.h"

#include <math.h>

static const double FD_BLOOM_LN_2 = 0.69314718055994530941723212145818;

FD_FN_CONST ulong
fd_bloom_align( void ) {
  return FD_BLOOM_ALIGN;
}

FD_FN_CONST ulong
fd_bloom_footprint( double false_positive_rate,
                    ulong  max_bits ) {
  if( FD_UNLIKELY( false_positive_rate<=0.0 ) ) return 0UL;
  if( FD_UNLIKELY( false_positive_rate>=1.0 ) ) return 0UL;

  if( FD_UNLIKELY( max_bits<1UL || max_bits>32768UL ) ) return 0UL;

  ulong num_keys = (ulong)( (double)max_bits*FD_BLOOM_LN_2 );

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_BLOOM_ALIGN, sizeof(fd_bloom_t) );
  l = FD_LAYOUT_APPEND( l, 8UL,            num_keys           );
  l = FD_LAYOUT_APPEND( l, 1UL,            (max_bits+7UL)/8UL );
  return FD_LAYOUT_FINI( l, FD_BLOOM_ALIGN );
}

void *
fd_bloom_new( void *     shmem,
              fd_rng_t * rng,
              double     false_positive_rate,
              ulong      max_bits ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_bloom_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( false_positive_rate<=0.0 ) ) return NULL;
  if( FD_UNLIKELY( false_positive_rate>=1.0 ) ) return NULL;

  if( FD_UNLIKELY( max_bits<1UL || max_bits>32768UL ) ) return NULL;
  
  if( FD_UNLIKELY( !rng ) ) return NULL;

  ulong num_keys = (ulong)( (double)max_bits*FD_BLOOM_LN_2 );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_bloom_t * bloom = FD_SCRATCH_ALLOC_APPEND( l, FD_BLOOM_ALIGN, sizeof(fd_bloom_t) );
  void * _keys = FD_SCRATCH_ALLOC_APPEND( l, 8UL, num_keys );
  void * _bits = FD_SCRATCH_ALLOC_APPEND( l, 1UL, (max_bits+7UL)/8UL );

  bloom->keys      = (ulong *)_keys;
  bloom->keys_len  = 0UL;
  bloom->bits      = (ulong *)_bits;
  bloom->bits_len  = 0UL;

  bloom->hash_seed = 0UL;
  bloom->rng       = rng;

  bloom->false_positive_rate = false_positive_rate;
  bloom->max_bits = max_bits;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( bloom->magic ) = FD_BLOOM_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)bloom;
}

fd_bloom_t *
fd_bloom_join( void * shbloom ) {
  if( FD_UNLIKELY( !shbloom ) ) {
    FD_LOG_WARNING(( "NULL shbloom" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shbloom, fd_bloom_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shbloom" ));
    return NULL;
  }

  fd_bloom_t * bloom = (fd_bloom_t *)shbloom;

  if( FD_UNLIKELY( bloom->magic!=FD_BLOOM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return bloom;
}

void
fd_bloom_initialize( fd_bloom_t * bloom,
                     ulong        num_items ) {
  double num_bits = ceil( ((double)num_items * log( bloom->false_positive_rate )) / log( 1.0 / pow( 2.0, log( 2.0 ) ) ) );
  num_bits = fmax( 1.0, fmin( (double)bloom->max_bits, num_bits ) );

  ulong num_keys = fd_ulong_if( num_items==0UL, 0UL, fd_ulong_max( 1UL, (ulong)( round( ((double)num_bits/(double)num_items) * FD_BLOOM_LN_2 ) ) ) );
  for( ulong i=0UL; i<num_keys; i++ ) bloom->keys[ i ] = fd_rng_ulong( bloom->rng );

  bloom->keys_len = num_keys;
  bloom->bits_len = (ulong)num_bits;
  fd_memset( bloom->bits, 0, (ulong)((num_bits+7UL)/8UL) );

  bloom->hash_seed = fd_rng_ulong( bloom->rng );
}

void
fd_bloom_insert( fd_bloom_t *  bloom,
                 uchar const * key,
                 ulong         key_sz ) {
  ulong hash = fd_hash( bloom->hash_seed, key, key_sz );

  for( ulong i=0UL; i<bloom->keys_len; i++ ) {
    ulong bit = (hash ^ bloom->keys[ i ]) % bloom->bits_len;
    bloom->bits[ bit / 8UL ] |= (1UL << (bit % 8UL));
  }
}

int
fd_bloom_contains( fd_bloom_t *  bloom,
                   uchar const * key,
                   ulong         key_sz ) {
  ulong hash = fd_hash( bloom->hash_seed, key, key_sz );
  for( ulong i=0UL; i<bloom->keys_len; i++ ) {
    ulong bit = (hash ^ bloom->keys[ i ]) % bloom->bits_len;
    if( !(bloom->bits[ bit / 8UL ] & (1UL << (bit % 8UL))) ) {
      return 0;
    }
  }
  return 1;
}
