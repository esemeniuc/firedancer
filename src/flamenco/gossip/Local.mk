$(call add-hdrs,fd_bloom.h)
$(call add-objs,fd_bloom fd_active_set fd_ping_tracker,fd_flamenco)

$(call make-unit-test,test_bloom,test_bloom,fd_flamenco fd_util)
$(call run-unit-test,test_bloom)

$(call make-unit-test,test_active_set,test_active_set,fd_flamenco fd_util)
$(call run-unit-test,test_active_set)

$(call make-unit-test,test_ping_tracker,test_ping_tracker,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_ping_tracker)
