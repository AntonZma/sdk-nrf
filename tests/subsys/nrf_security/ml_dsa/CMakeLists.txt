#
# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

# target_compile_definitions(app PUBLIC PSA_NEED_OBERON_SHAKE128 PSA_NEED_OBERON_SHAKE256)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ml_dsa)

target_sources(app PRIVATE src/main.c)
