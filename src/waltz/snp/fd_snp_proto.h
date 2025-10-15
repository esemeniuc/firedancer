#ifndef HEADER_snp_proto_h
#define HEADER_snp_proto_h

/* snp_proto.h defines SNP protocol data structures. */

#include "../../util/fd_util_base.h"
#include "../../util/rng/fd_rng.h"
#include "../../ballet/aes/fd_aes_base.h"
#include <stdio.h> /* sprintf */

/* SNP_MTU controls the maximum supported UDP payload size. */

#define FD_SNP_MTU     (1536UL) /* FD_SNP_MTU is currently 24 x 64 */
#define FD_SNP_MTU_MIN (1200UL)

#define FD_SNP_ALIGN   (128UL)
#define FD_SNP_ALIGNED __attribute__((aligned(128UL)))

/* SNP_V{...} identify SNP versions. */

#define FD_SNP_V1  ((uchar)0x01)

/* SNP_TYPE_{...} identify SNP packet types. */

#define FD_SNP_TYPE_NULL               ((uchar)0x00) /* invalid */

#define FD_SNP_TYPE_HS_CLIENT_INIT     ((uchar)0x01)
#define FD_SNP_TYPE_HS_SERVER_INIT     ((uchar)0x02)
#define FD_SNP_TYPE_HS_CLIENT_CONT     ((uchar)0x03)
#define FD_SNP_TYPE_HS_SERVER_FINI     ((uchar)0x04)
#define FD_SNP_TYPE_HS_CLIENT_FINI     ((uchar)0x05)
#define FD_SNP_TYPE_PAYLOAD            ((uchar)0x0F)

#define FD_SNP_TYPE_HS_SERVER_FINI_SIG ((uchar)0xF4) /* invalid on wire */
#define FD_SNP_TYPE_HS_CLIENT_FINI_SIG ((uchar)0xF5) /* invalid on wire */
#define FD_SNP_TYPE_HS_DONE            ((uchar)0xFF) /* invalid on wire */

/* SNP_SUITE_{...} defines cipher suite IDs.

   Each suite consists of:
   - A signature scheme for authentication
   - A key exchange mechanism
   - An authenticated encrypted scheme
   - A hash function for key expansion */

#define SNP_SUITE_S0  ((ushort)0x0000)  /* Ed25519 auth, unencrypted */
#define SNP_SUITE_S1  ((ushort)0x0001)  /* Ed25519 auth, X25519 KEX, AES-128-GCM AEAD, HMAC-SHA256 hash */

/* SNP_SESSION_ID_SZ is the byte size of the session ID. */

#define SNP_SESSION_ID_SZ (8UL)

/* SNP_COOKIE_SZ is the cookie byte size used in the handshake
   mechanism.  (Handshake cookies are analogous to TCP SYN cookies). */

#define SNP_COOKIE_SZ (8UL)

#define SNP_COOKIE_KEY_SZ (16UL)

#define SNP_ED25519_KEY_SZ (32UL)
#define SNP_STATE_KEY_SZ   (16UL)

#define FD_SNP_TO_SIGN_SZ  (40UL)

/* SNP_MAC_SZ is the byte size of the MAC tag in authenticated packets */

#define SNP_MAC_SZ (16UL)

/* SNP_BASIC_PAYLOAD_MTU is the MTU of the payload carried by the
   0x1 frame type */

#define SNP_BASIC_PAYLOAD_MTU (FD_SNP_MTU - SNP_SESSION_ID_SZ - SNP_MAC_SZ - 1)

#define FD_SNP_MAX_BUF (2UL)

#define FD_SNP_MAX_SESSION_TMP (3)

#define FD_SNP_MAGIC (0xf17eda2ce7552299UL)


struct fd_snp_config {
  double tick_per_us;  /* tick_per_us: clock ticks per microsecond */
  long   keep_alive_ms;
  long   handshake_retry_ms;

  /* identity pubkey */
  uchar identity[ SNP_ED25519_KEY_SZ ];

  /* Private members */

  fd_rng_t     _rng[1];
  fd_aes_key_t _state_enc_key[1];
  fd_aes_key_t _state_dec_key[1];
};
typedef struct fd_snp_config fd_snp_config_t;


/* Packets */

struct FD_SNP_ALIGNED fd_snp_pkt {
  /* used both by packets cache, and last sent packets - preferably,
     data should be FD_SNP_ALIGNED, so placing it at the top of the
     struct. */
  uchar  data[ FD_SNP_MTU ];

  /* fd_pool */
  ulong  next;

  /* only used by last sent packets */
  ulong  meta;

  /* only used by packets cache */
  ulong  session_id;
  ushort data_sz;
  uchar  send; // send or recv

  /* force sizeof(fd_snp_pkt_t)==2048 for feng shui (cf fd_pool.c) */
  uchar  _padding[ 2048 - 1563 ];
};
typedef struct fd_snp_pkt fd_snp_pkt_t;
FD_STATIC_ASSERT( sizeof(fd_snp_pkt_t)==2048UL, fd_snp_pkt_t );

#define POOL_NAME      fd_snp_pkt_pool
#define POOL_T         fd_snp_pkt_t
#include "../../util/tmpl/fd_pool.c"

/* Connections */

#define FD_SNP_STATE_INVALID     (0x00)
#define FD_SNP_STATE_CLIENT_INIT (0x01)
#define FD_SNP_STATE_SERVER_INIT (0x02)
#define FD_SNP_STATE_CLIENT_CONT (0x03)
#define FD_SNP_STATE_SERVER_FINI (0x04)
#define FD_SNP_STATE_CLIENT_FINI (0x05)
#define FD_SNP_STATE_ESTABLISHED (0xFF)

/* SNP_TOKEN_SZ is the byte size of the "random token" value.  Both
   client and server mix in their token value into the handshake
   commitment to prevent replay attacks. */
#define SNP_TOKEN_SZ (16UL)

struct FD_SNP_ALIGNED fd_snp_conn {
  ulong next; // fd_pool

  ulong session_id; // can be removed if needed
  ulong peer_addr;
  ulong peer_session_id;

  /* Flow control */
  long  flow_rx_alloc;
  long  flow_rx_level;
  long  flow_rx_wmark;
  long  flow_tx_level;
  long  flow_tx_wmark;

  uchar state;
  uchar is_server;
  uchar is_multicast;

  fd_snp_pkt_t * last_pkt;

  long  last_sent_ts;
  long  last_recv_ts;
  uchar retry_cnt;

  /* public key. Access via: fd_snp_conn_pubkey() */
  uchar * _pubkey;

  /* peer public key. Access via: fd_snp_conn_peer_pubkey() */
  uchar _peer_pubkey[ 32 ];

  /* Memory area for key material:
     - For established connections: 2x 256-bit keys (HMAC-SHA-256-128, RFC 4868)
     - During handshake: Noise hash transcript, and symmetric encryption key
     - For client, before Noise, ephemeral DH keypair  */
  uchar _sensitive_keys[ 64 ];
};
typedef struct fd_snp_conn fd_snp_conn_t;

#define POOL_NAME      fd_snp_conn_pool
#define POOL_T         fd_snp_conn_t
#include "../../util/tmpl/fd_pool.c"

struct __attribute__((aligned(16))) fd_snp_conn_map {
  ulong           key;
  fd_snp_conn_t * val;
};
typedef struct fd_snp_conn_map fd_snp_conn_map_t;

#define MAP_NAME        fd_snp_conn_map
#define MAP_T           fd_snp_conn_map_t
#define MAP_MEMOIZE     0
#define MAP_HASH_T      ulong
#define MAP_KEY_HASH(k) (k)
#include "../../util/tmpl/fd_map_dynamic.c"






struct fd_snp_payload {
   ushort sz;
   uchar  data[SNP_BASIC_PAYLOAD_MTU];
};

typedef struct fd_snp_payload fd_snp_payload_t;

/* snp_hdr_t is the common SNP header shared by all packets. */

struct __attribute__((packed)) snp_hdr {
  uint  version_type;
  ulong session_id;
};

typedef struct snp_hdr snp_hdr_t;

/* snp_hs_hdr_t is the SNP header shared by all handshake packets. */

struct __attribute__((packed)) snp_hs_hdr {
  snp_hdr_t base;
  ulong     src_session_id;
};

typedef struct snp_hs_hdr snp_hdr_hs_t;


FD_PROTOTYPES_BEGIN

static inline int
fd_snp_rng( uchar * buf, ulong buf_sz ) {
  if( FD_LIKELY( fd_rng_secure( buf, buf_sz )!=NULL ) ) {
    return (int)buf_sz;
  }
  return -1;
}

static inline long
fd_snp_timestamp_ms( void ) {
  return fd_log_wallclock() / 1000000;
}

/* snp_hdr_{version,type} extract the version and type fields from
   an snp_hdr_t. */

FD_FN_PURE static inline uchar
snp_hdr_version( snp_hdr_t const * hdr ) {
  return (uchar)( hdr->version_type >> (24+4) );
}

FD_FN_PURE static inline uchar
snp_hdr_type( snp_hdr_t const * hdr ) {
  return (uchar)( (hdr->version_type >> 24) & 0x0F );
}

/* snp_hdr_version_type assembles the version_type compound field. */

FD_FN_CONST static inline uint
fd_snp_hdr_version_type( uint version,
                         uint type ) {
  return (uint)( ( version << 4 ) | ( type & 0x0F ) ) << 24
    | (uint)'S' << 0
    | (uint)'N' << 8
    | (uint)'P' << 16;
}

static inline char*
fd_snp_log_conn( fd_snp_conn_t * conn ) {
  static char buf[256];
  if( !conn ) return "";
  uint   ip4  = (uint  )( conn->peer_addr>>0  );
  ushort port = (ushort)( conn->peer_addr>>32 );
  sprintf( buf, "session_id=%016lx peer=%u.%u.%u.%u:%u",
    conn->session_id, (ip4>>0)&0xff, (ip4>>8)&0xff, (ip4>>16)&0xff, (ip4>>24)&0xff, port );
  return buf;
}

FD_PROTOTYPES_END

#endif /* HEADER_snp_proto_h */
