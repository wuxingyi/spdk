/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "spdk/stdinc.h"

#include "spdk/vhost.h"

#include "spdk_internal/init.h"

static void
vhost_blk_subsystem_init_done(int rc)
{
	spdk_subsystem_init_next(rc);
}

static void
vhost_blk_subsystem_init(void)
{
	spdk_vhost_blk_init(vhost_blk_subsystem_init_done);
}

static void
vhost_blk_subsystem_fini_done(void)
{
	spdk_subsystem_fini_next();
}

static void
vhost_blk_subsystem_fini(void)
{
	spdk_vhost_blk_fini(vhost_blk_subsystem_fini_done);
}

static struct spdk_subsystem g_spdk_subsystem_vhost_blk = {
	.name = "vhost_blk",
	.init = vhost_blk_subsystem_init,
	.fini = vhost_blk_subsystem_fini,
	.write_config_json = spdk_vhost_blk_config_json,
};

SPDK_SUBSYSTEM_REGISTER(g_spdk_subsystem_vhost_blk);
SPDK_SUBSYSTEM_DEPEND(vhost_blk, bdev)
