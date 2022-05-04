# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)


XDP_TARGETS  := xdp_kern xdp_redirect_kern
USER_TARGETS := host_proc host_proc_veth

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

include $(COMMON_DIR)/common.mk
LIBS += -lpthread -lrt
