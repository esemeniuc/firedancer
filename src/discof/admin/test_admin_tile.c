#include "fd_admin_tile.c"

#include <stdlib.h>

#define TEST_SIGN_CNT (2UL)

static fd_admin_tile_ctx_t ctx;
static fd_keyswitch_t      voter [1];
static fd_keyswitch_t      txsend[1];
static fd_keyswitch_t      sign  [ TEST_SIGN_CNT ];

static void
setup( int alpenglow ) {
  memset( &ctx, 0, sizeof(ctx) );
  ctx.alpenglow           = alpenglow;
  ctx.voter_name          = alpenglow ? "votor" : "tower";
  ctx.voter_av_keyswitch  = fd_keyswitch_join( fd_keyswitch_new( voter,  FD_KEYSWITCH_STATE_UNLOCKED ) );
  ctx.txsend_av_keyswitch = fd_keyswitch_join( fd_keyswitch_new( txsend, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.voter_av_keyswitch && ctx.txsend_av_keyswitch );
  for( ulong i=0UL; i<TEST_SIGN_CNT; i++ ) {
    ctx.sign_av_keyswitch[ i ] = fd_keyswitch_join( fd_keyswitch_new( &sign[ i ], FD_KEYSWITCH_STATE_UNLOCKED ) );
    FD_TEST( ctx.sign_av_keyswitch[ i ] );
  }
  ctx.sign_av_keyswitch_cnt = TEST_SIGN_CNT;
}

static void
sign_expect( ulong state,
             ulong param ) {
  for( ulong i=0UL; i<TEST_SIGN_CNT; i++ ) {
    FD_TEST( sign[ i ].state==state );
    if( state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) FD_TEST( sign[ i ].param==param );
  }
}

static void
sign_complete( void ) {
  for( ulong i=0UL; i<TEST_SIGN_CNT; i++ ) fd_keyswitch_state( &sign[ i ], FD_KEYSWITCH_STATE_COMPLETED );
}

/* The sign tiles learn a new authorized voter before the vote producing
   tile (tower, or votor under Alpenglow) does. */

static void
test_add_authorized_voter( int alpenglow ) {
  setup( alpenglow );
  uchar keypair[ 64 ]; memset( keypair, 0x33, sizeof(keypair) );
  ulong result = 0UL;
  ulong state  = FD_ADD_AUTH_VOTER_STATE_UNLOCKED;

  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_LOCKED && voter->state==FD_KEYSWITCH_STATE_LOCKED );

  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED );
  sign_expect( FD_KEYSWITCH_STATE_SWITCH_PENDING, FD_KEYSWITCH_PARAM_AV_ADD );
  FD_TEST( voter->state==FD_KEYSWITCH_STATE_LOCKED );

  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED );
  sign_complete();
  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED );

  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_VOTER_TILE_REQUESTED );
  FD_TEST( voter->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && voter->param==FD_KEYSWITCH_PARAM_AV_ADD );
  fd_keyswitch_state( voter, FD_KEYSWITCH_STATE_COMPLETED );
  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_VOTER_TILE_UPDATED );

  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_UNLOCK_REQUESTED && voter->state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
  fd_keyswitch_state( voter, FD_KEYSWITCH_STATE_UNLOCKED );
  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_UNLOCKED && !result );
  FD_TEST( txsend->state==FD_KEYSWITCH_STATE_UNLOCKED );
}

/* The vote producing tile drops its authorized voters before the sign
   tiles do.  Only the tower's votes pass through TxSend, so only the
   tower path drains it. */

static void
test_remove_all_authorized_voters( int alpenglow ) {
  setup( alpenglow );
  ulong state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED;

  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_LOCKED && voter->state==FD_KEYSWITCH_STATE_LOCKED );

  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_VOTER_TILE_REQUESTED );
  FD_TEST( voter->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && voter->param==FD_KEYSWITCH_PARAM_AV_CLEAR );
  sign_expect( FD_KEYSWITCH_STATE_UNLOCKED, 0UL );

  voter->result = 42UL;
  fd_keyswitch_state( voter, FD_KEYSWITCH_STATE_COMPLETED );
  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_VOTER_TILE_CLEARED );

  poll_remove_all_authorized_voters( &ctx, &state );
  if( alpenglow ) {
    FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSHED );
    FD_TEST( txsend->state==FD_KEYSWITCH_STATE_UNLOCKED );
  } else {
    FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSH_REQUESTED );
    FD_TEST( txsend->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && txsend->param==42UL );
    fd_keyswitch_state( txsend, FD_KEYSWITCH_STATE_COMPLETED );
    poll_remove_all_authorized_voters( &ctx, &state );
    FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSHED );
  }
  sign_expect( FD_KEYSWITCH_STATE_UNLOCKED, 0UL );

  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_SIGN_TILE_REQUESTED );
  sign_expect( FD_KEYSWITCH_STATE_SWITCH_PENDING, FD_KEYSWITCH_PARAM_AV_CLEAR );
  sign_complete();
  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_SIGN_TILE_CLEARED );

  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCK_REQUESTED && voter->state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
  fd_keyswitch_state( voter, FD_KEYSWITCH_STATE_UNLOCKED );
  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED );
}

/* Use the command queue so rejection must complete and wipe the request
   before another command can reuse its slot.  A NULL topology ensures
   that no rejected request can enter the identity-switch state machine. */

static ulong
submit_set_identity( fd_adminctl_set_identity_t const * req,
                     ulong                             req_sz,
                     ulong                             expected_result ) {
  uchar identity_before[ 32 ];
  fd_memcpy( identity_before, ctx.identity_pubkey, sizeof(identity_before) );
  fd_keyswitch_t voter_before  = *voter;
  fd_keyswitch_t txsend_before = *txsend;
  fd_keyswitch_t sign_before[ TEST_SIGN_CNT ];
  fd_memcpy( sign_before, sign, sizeof(sign_before) );

  void * payload;
  ulong payload_max;
  ulong slot_idx = fd_adminctl_reserve( ctx.adminctl, &payload, &payload_max );
  FD_TEST( slot_idx!=ULONG_MAX && req_sz<=payload_max );
  fd_memcpy( payload, req, req_sz );
  fd_adminctl_publish( ctx.adminctl, slot_idx, FD_ADMINCTL_CMD_SET_IDENTITY, req_sz );

  int charge_busy = 0;
  int opt_poll_in = 1;
  for( ulong i=0UL; i<FD_ADMINCTL_SLOT_CNT && !charge_busy; i++ )
    after_credit( &ctx, NULL, &opt_poll_in, &charge_busy );
  FD_TEST( charge_busy );

  /* Check before wait/reuse: reserve also zeros the command payload. */
  for( ulong i=0UL; i<req_sz; i++ ) FD_TEST( !((uchar *)payload)[ i ] );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, slot_idx )==expected_result );
  FD_TEST( fd_memeq( ctx.identity_pubkey, identity_before, sizeof(identity_before) ) );
  FD_TEST( fd_memeq( voter,  &voter_before,  sizeof(voter_before) ) );
  FD_TEST( fd_memeq( txsend, &txsend_before, sizeof(txsend_before) ) );
  FD_TEST( fd_memeq( sign,   sign_before,   sizeof(sign_before) ) );
  return slot_idx;
}

static void
test_set_identity_unsupported( void ) {
  setup( 1 );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx.sha512 ) ) );
  fd_memset( ctx.identity_pubkey, 0x77, sizeof(ctx.identity_pubkey) );
  void * mem = aligned_alloc( fd_adminctl_align(), fd_adminctl_footprint() );
  FD_TEST( mem );
  ctx.adminctl = fd_adminctl_join( fd_adminctl_new( mem ) );
  FD_TEST( ctx.adminctl );

  fd_adminctl_set_identity_t req = { .version = FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION };
  fd_memset( req.keypair, 0x11, 32UL );
  fd_ed25519_public_from_private( req.keypair+32UL, req.keypair, ctx.sha512 );

  ulong slot_idx = submit_set_identity( &req, sizeof(req), FD_ADMINCTL_RESULT_UNSUPPORTED );
  FD_TEST( submit_set_identity( &req, sizeof(req), FD_ADMINCTL_RESULT_UNSUPPORTED )==slot_idx );

  submit_set_identity( &req, sizeof(ulong)-1UL, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
  submit_set_identity( &req, sizeof(req)-1UL, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
  req.version++;
  submit_set_identity( &req, sizeof(req), FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH );
  req.version--;
  req.keypair[ 32 ] ^= 1U;
  submit_set_identity( &req, sizeof(req), FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH );

  /* Tower keeps its existing validation behavior as well. */
  ctx.alpenglow = 0;
  submit_set_identity( &req, sizeof(req), FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH );
  free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_add_authorized_voter( 0 );
  test_add_authorized_voter( 1 );
  test_remove_all_authorized_voters( 0 );
  test_remove_all_authorized_voters( 1 );
  test_set_identity_unsupported();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
