# SPDX-License-Identifier: BSD-3-Clause
# Phicomm N1 (Amlogic S905D) DWMAC1000 native PMD. Needs the n1_dma helper module.

if not is_linux or not dpdk_conf.has('RTE_ARCH_ARM64')
    build = false
    reason = 'only supported on Linux arm64'
    subdir_done()
endif

sources = files('n1_pmd.c')
