APPLICATION = qos_app

# If no BOARD is found in the environment, use this default:
BOARD ?= iotlab-m3

BOARD_WHITELIST := fox iotlab-m3 msba2 mulle native pba-d-01-kw2x samr21-xpro


# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../RIOT


USEMODULE += gnrc_netdev_default

CFLAGS += -DDEVELHELP
CFLAGS += -DDEBUG_ASSERT_VERBOSE
CFLAGS += -DUSE_LINKLAYER
#CFLAGS += -DUSE_RONR
CFLAGS += -DCCNL_UAPI_H_
CFLAGS += -DUSE_SUITE_NDNTLV
CFLAGS += -DNEEDS_PREFIX_MATCHING
CFLAGS += -DNEEDS_PACKET_CRAFTING
#CFLAGS += -DCCNL_CACHE_SIZE=20
#CFLAGS += -DCCNL_DEFAULT_MAX_PIT_ENTRIES=5
CFLAGS += -DCCNL_FACE_TIMEOUT=8
CFLAGS += -DCCNL_INTEREST_TIMEOUT=10
CFLAGS += -DCCNL_MAX_INTEREST_RETRANSMIT=5
CFLAGS += -DCCNL_INTEREST_RETRANS_TIMEOUT=2000
CFLAGS += -DCCNL_THREAD_PRIORITY="THREAD_PRIORITY_MAIN-3"
CFLAGS += -DCCNL_STACK_SIZE="THREAD_STACKSIZE_DEFAULT+THREAD_EXTRA_STACKSIZE_PRINTF"
CFLAGS += -DCCNL_QUEUE_SIZE=128
CFLAGS += -D_NETIF_NETAPI_MSG_QUEUE_SIZE=64
#CFLAGS += -DCCNL_CONTENT_TIMEOUT=3

#CFLAGS += -DTLSF_BUFFER="40960"
CFLAGS += -DTLSF_BUFFER="46080"
#CFLAGS += -DTLSF_BUFFER="51200"

CFLAGS += -Wno-error=builtin-declaration-mismatch
CFLAGS += -Wno-error=array-bounds

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

USEMODULE += ps
USEMODULE += shell
USEMODULE += shell_commands
# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += evtimer
USEMODULE += auto_init_gnrc_netif
USEMODULE += timex
USEMODULE += xtimer
USEMODULE += random
USEMODULE += prng_xorshift
USEMODULE += netstats_l2
#USEMODULE += l2filter_blacklist

USEPKG += ccn-lite

include $(RIOTBASE)/Makefile.include
