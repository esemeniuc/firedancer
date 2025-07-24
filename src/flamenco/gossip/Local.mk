$(call add-hdrs,fd_gossip.h fd_gossip_out.h)
$(call add-objs,fd_gossip fd_gossip_msg_ser fd_gossip_msg_parse fd_gossip_msg_ser fd_gossip_out,fd_flamenco)

$(call add-hdrs,fd_bloom.h)
$(call add-objs,fd_bloom fd_active_set fd_ping_tracker,fd_flamenco)

$(call add-hdrs,fd_contact_info.h)
$(call add-objs,fd_contact_info,fd_flamenco)

$(call add-hdrs,fd_gossip_update_msg.h)

$(call make-unit-test,test_bloom,test_bloom,fd_flamenco fd_util)
$(call run-unit-test,test_bloom)

$(call make-unit-test,test_active_set,test_active_set,fd_flamenco fd_util)
$(call run-unit-test,test_active_set)

$(call make-unit-test,test_ping_tracker,test_ping_tracker,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_ping_tracker)
