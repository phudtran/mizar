// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * @file trn_agent_xdp_usr.c
 * @author Sherif Abdelwahab (@zasherif)
 *         Phu Tran          (@phudtran)
 *
 * @brief User space APIs to program transit agent
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

#include "extern/linux/err.h"
#include "trn_agent_xdp_usr.h"
#include "trn_log.h"

#define _REUSE_MAP_IF_PINNED(map)                                        	\
	do {									\
		int err_code;							\
		if (0 != (err_code = _reuse_pinned_map_if_exists(md->obj, 	\
			#map, 							\
			map##_path)))						\
		{ 								\
			TRN_LOG_INFO("failed to reuse shared map at %s, error code %d\n", map##_path, err_code); \
			return 1;						\
		}								\
	} while (0)

int trn_agent_user_metadata_free(struct agent_user_metadata_t *md)
{
	__u32 curr_prog_id = 0;

	if (bpf_get_link_xdp_id(md->ifindex, &curr_prog_id, md->xdp_flags)) {
		TRN_LOG_ERROR("bpf_get_link_xdp_id failed.");
		return 1;
	}

	if (md->prog_id == curr_prog_id)
		bpf_set_link_xdp_fd(md->ifindex, -1, md->xdp_flags);
	else if (!curr_prog_id)
		TRN_LOG_WARN("Couldn't find a prog id on a given interface.");
	else
		TRN_LOG_WARN("program on interface changed, not removing.");

	bpf_object__close(md->obj);

	return 0;
}

int trn_agent_bpf_maps_init(struct agent_user_metadata_t *md)
{
	md->jmp_table_map = bpf_map__next(NULL, md->obj);
	

	if (!md->jmp_table_map) {
		TRN_LOG_ERROR("Failure finding maps objects.");
		return 1;
	}

	md->jmp_table_fd = bpf_map__fd(md->jmp_table_map);


	return 0;
}




static int _trn_bpf_agent_prog_load_xattr(struct agent_user_metadata_t *md,
					  const struct bpf_prog_load_attr *attr,
					  struct bpf_object **pobj,
					  int *prog_fd)
{

	struct bpf_program *prog, *first_prog = NULL;

	md = NULL;

	*pobj = bpf_object__open(attr->file);

	if (IS_ERR_OR_NULL(*pobj)) {
		TRN_LOG_ERROR("Error openning bpf file: %s\n", attr->file);
		return 1;
	}

	/* Only one prog is supported */
	bpf_object__for_each_program(prog, *pobj)
	{
		bpf_program__set_xdp(prog);
		if (!first_prog)
			first_prog = prog;
	}

	bpf_object__load(*pobj);

	if (!first_prog) {
		TRN_LOG_ERROR("Failed to find XDP program in object file: %s\n",
			      attr->file);
		goto error;
	}

	*prog_fd = bpf_program__fd(first_prog);
	return 0;
error:
	TRN_LOG_ERROR("Error adding loading tranist agent from file %s.\n",
		      attr->file);
	bpf_object__close(*pobj);
	return 1;
}

int trn_agent_metadata_init(struct agent_user_metadata_t *md, char *itf,
			    char *agent_kern_path, int xdp_flags)
{
	int rc;
	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
	struct bpf_prog_load_attr prog_load_attr = { .prog_type =
							     BPF_PROG_TYPE_XDP,
						     .file = agent_kern_path };
	__u32 info_len = sizeof(md->info);

	md->xdp_flags = xdp_flags;

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		TRN_LOG_ERROR("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	snprintf(md->pcapfile, sizeof(md->pcapfile),
		 "/sys/fs/bpf/%s_transit_agent_pcap", itf);

	md->ifindex = if_nametoindex(itf);
	if (!md->ifindex) {
		TRN_LOG_ERROR("Error retrieving index of interface");
		return 1;
	}

	if (_trn_bpf_agent_prog_load_xattr(md, &prog_load_attr, &md->obj,
					   &md->prog_fd)) {
		TRN_LOG_ERROR("Error loading bpf: %s", agent_kern_path);
		return 1;
	}

	rc = trn_agent_bpf_maps_init(md);

	if (rc != 0) {
		return 1;
	}

	if (!md->prog_fd) {
		TRN_LOG_ERROR("load_bpf_file: %s", strerror(errno));
		return 1;
	}

	if (bpf_set_link_xdp_fd(md->ifindex, md->prog_fd, xdp_flags) < 0) {
		TRN_LOG_ERROR("link set xdp fd failed");
		return 1;
	}

	rc = bpf_obj_get_info_by_fd(md->prog_fd, &md->info, &info_len);
	if (rc != 0) {
		TRN_LOG_ERROR("can't get prog info - %s.", strerror(errno));
		return 1;
	}
	md->prog_id = md->info.id;

	return 0;
}
