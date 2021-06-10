// SPDX-License-Identifier: GPL-2.0
/**
 * @file trn_rpc_protocol_handlers_1.c
 * @author Sherif Abdelwahab (@zasherif)
 *         Phu Tran          (@phudtran)
 *
 * @brief RPC handlers. Primarly allocate and populate data structs,
 * and update the ebpf maps through user space APIs.
 *
 * @copyright Copyright (c) 2019 The Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>
#include <search.h>
#include <stdlib.h>
#include <stdint.h>

#include "rpcgen/trn_rpc_protocol.h"
#include "trn_transit_xdp_usr.h"
#include "trn_agent_xdp_usr.h"
#include "trn_log.h"
#include "trn_transitd.h"

#define TRANSITLOGNAME "transit"
#define TRN_MAX_ITF 265
#define TRN_MAX_VETH 2048
#define PRIMARY 0
#define SUPPLEMENTARY 1
#define EXCEPTION 2

void rpc_transit_remote_protocol_1(struct svc_req *rqstp,
				   register SVCXPRT *transp);

int trn_itf_table_init()
{
	int rc;
	rc = hcreate((TRN_MAX_VETH + TRN_MAX_ITF) * 1.3);
	return rc;
}

void trn_itf_table_free()
{
	/* TODO: At the moment, this is only called before exit, so there
     *  is no actual need to free table elements one by one. If this
     *  is being called while the dameon remains running, we will need
     *  to maintain the keys in a separate data-structure and free
     *  them one-by-one. */

	hdestroy();
}

int trn_itf_table_insert(char *itf, struct user_metadata_t *md)
{
	INTF_INSERT();
}

struct user_metadata_t *trn_itf_table_find(char *itf)
{
	INTF_FIND();
}

void trn_itf_table_delete(char *itf)
{
	INTF_DELETE();
}

int trn_vif_table_insert(char *itf, struct agent_user_metadata_t *md)
{
	INTF_INSERT();
}

struct agent_user_metadata_t *trn_vif_table_find(char *itf)
{
	INTF_FIND();
}

void trn_vif_table_delete(char *itf)
{
	INTF_DELETE();
}


int *load_transit_xdp_1_svc(rpc_trn_xdp_intf_t *xdp_intf, struct svc_req *rqstp)
{
	UNUSED(rqstp);
	static int result = -1;

	int rc;
	bool unload_error = false;
	char *itf = xdp_intf->interface;
	int xdp_flag = xdp_intf->xdp_flag;
	char *kern_path = xdp_intf->xdp_path;
	struct user_metadata_t empty_md;
	struct user_metadata_t *md = trn_itf_table_find(itf);

	if (md) {
		TRN_LOG_INFO("meatadata for interface %s already exist.", itf);
	} else {
		TRN_LOG_INFO("creating meatadata for interface %s.", itf);
		md = malloc(sizeof(struct user_metadata_t));
	}

	if (!md) {
		TRN_LOG_ERROR("Failure allocating memory for user_metadata_t");
		result = RPC_TRN_FATAL;
		goto error;
	}

	memset(md, 0, sizeof(struct user_metadata_t));

	// Set all interface index slots to unused
	int i;
	for (i = 0; i < TRAN_MAX_ITF; i++) {
		md->itf_idx[i] = TRAN_UNUSED_ITF_IDX;
	}

	strcpy(md->pcapfile, xdp_intf->pcapfile);
	md->pcapfile[255] = '\0';
	md->xdp_flags = xdp_intf->xdp_flag;

	TRN_LOG_DEBUG("load_transit_xdp_1 path: %s, pcap: %s",
		      xdp_intf->xdp_path, xdp_intf->pcapfile);

	rc = trn_user_metadata_init(md, itf, kern_path, md->xdp_flags);

	if (rc != 0) {
		TRN_LOG_ERROR(
			"Failure initializing or loading transit XDP program for interface %s",
			itf);
		result = RPC_TRN_FATAL;
		goto error;
	}

	rc = trn_itf_table_insert(itf, md);
	if (rc != 0) {
		TRN_LOG_ERROR(
			"Failure populating interface table when loading XDP program on %s",
			itf);
		result = RPC_TRN_ERROR;
		unload_error = true;
		goto error;
	}

	TRN_LOG_INFO("Successfully loaded transit XDP on interface %s", itf);

	result = 0;
	return &result;

error:
	if (unload_error) {
		trn_user_metadata_free(md);
	}
	free(md);
	return &result;
}

int *unload_transit_xdp_1_svc(rpc_intf_t *argp, struct svc_req *rqstp)
{
	UNUSED(rqstp);
	static int result = -1;
	int rc;
	char *itf = argp->interface;

	TRN_LOG_DEBUG("unload_transit_xdp_1 interface: %s", itf);

	struct user_metadata_t *md = trn_itf_table_find(itf);

	if (!md) {
		TRN_LOG_ERROR("Cannot find interface metadata for %s", itf);
		result = RPC_TRN_ERROR;
		goto error;
	}

	rc = trn_user_metadata_free(md);

	if (rc != 0) {
		TRN_LOG_ERROR(
			"Cannot free XDP metadata, transit program may still be running");
		result = RPC_TRN_ERROR;
		goto error;
	}
	trn_itf_table_delete(itf);

	result = 0;
	return &result;

error:
	return &result;
}

int *load_transit_agent_xdp_1_svc(rpc_trn_xdp_intf_t *xdp_intf,
				  struct svc_req *rqstp)
{
	UNUSED(rqstp);
	static int result = -1;

	int rc;
	bool unload_error = false;
	/* The transit agent always runs on vif */
	char *itf = xdp_intf->interface;
	char *kern_path = xdp_intf->xdp_path;
	int xdp_flag = xdp_intf->xdp_flag;

	struct agent_user_metadata_t *md = trn_vif_table_find(itf);
	if (md) {
		TRN_LOG_INFO("meatadata for interface %s already exist.", itf);
	} else {
		md = malloc(sizeof(struct agent_user_metadata_t));
	}
	if (!md) {
		TRN_LOG_ERROR(
			"Failure allocating memory for agent_user_metadata_t");
		result = RPC_TRN_FATAL;
		goto error;
	}

	memset(md, 0, sizeof(struct agent_user_metadata_t));

	strcpy(md->pcapfile, xdp_intf->pcapfile);
	md->pcapfile[255] = '\0';
	md->xdp_flags = xdp_intf->xdp_flag;

	TRN_LOG_DEBUG("load_transit_agent_xdp_1 path: %s, pcap: %s",
		      xdp_intf->xdp_path, xdp_intf->pcapfile);

	rc = trn_agent_metadata_init(md, itf, kern_path, md->xdp_flags);

	if (rc != 0) {
		TRN_LOG_ERROR("Failure initializing or loading transit agent "
			      "XDP program for interface %s",
			      itf);
		result = RPC_TRN_FATAL;
		goto error;
	}

	rc = trn_vif_table_insert(itf, md);
	if (rc != 0) {
		TRN_LOG_ERROR("Failure populating interface table when "
			      "loading agent XDP program on %s",
			      itf);
		result = RPC_TRN_ERROR;
		unload_error = true;
		goto error;
	}

	result = 0;
	return &result;

error:
	if (unload_error) {
		trn_agent_user_metadata_free(md);
	}
	free(md);
	return &result;
}

int *unload_transit_agent_xdp_1_svc(rpc_intf_t *argp, struct svc_req *rqstp)
{
	UNUSED(rqstp);
	static int result = -1;
	int rc;
	char *itf = argp->interface;

	TRN_LOG_DEBUG("unload_transit_agent_xdp_1 interface: %s", itf);

	struct agent_user_metadata_t *md = trn_vif_table_find(itf);

	if (!md) {
		TRN_LOG_ERROR("Cannot find virtual interface metadata for %s",
			      itf);
		result = RPC_TRN_ERROR;
		goto error;
	}

	rc = trn_agent_user_metadata_free(md);

	if (rc != 0) {
		TRN_LOG_ERROR("Cannot free XDP metadata,"
			      " transit agent program may still be running");
		result = RPC_TRN_ERROR;
		goto error;
	}

	trn_vif_table_delete(itf);

	result = 0;
	return &result;

error:
	return &result;
}

