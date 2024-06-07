/*
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "memcr.h"

#define CMD_LEN_MAX		(sizeof(struct service_command) + (2*sizeof(memcr_svc_checkpoint_options)) \
						 + MEMCR_DUMPDIR_LEN_MAX + sizeof(memcr_compress_alg))

static int xconnect(struct sockaddr *addr, socklen_t addrlen)
{
	int cd, ret;

	cd = socket(addr->sa_family, SOCK_STREAM, 0);
	if (cd < 0) {
		fprintf(stderr, "socket() failed: %m\n");
		return -1;
	}

	ret = connect(cd, addr, addrlen);
	if (ret < 0) {
		fprintf(stderr, "connect() failed: %m\n");
		close(cd);
		return ret;
	}

	return cd;
}

static int connect_unix(const char *path)
{
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	return xconnect((struct sockaddr *)&addr, sizeof(addr));
}

static int connect_tcp(int port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
		.sin_port = htons(port),
	};

	return xconnect((struct sockaddr *)&addr, sizeof(addr));
}

static int send_cmd(int cd, struct service_command cmd)
{
	int ret;
	struct service_response resp = {0};

ret = write(cd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd)) {
		fprintf(stderr, "%s() write request failed: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	ret = read(cd, &resp, sizeof(struct service_response));
	if (ret != sizeof(struct service_response)) {
		fprintf(stderr, "%s() read response failed: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	fprintf(stdout, "Procedure finished with %s status.\n", MEMCR_OK == resp.resp_code ? "OK" : "ERROR");

	return resp.resp_code;
}

static int send_cmd_v2(int cd, memcr_svc_cmd cmd, pid_t pid, const struct service_options *opt)
{
	int ret;
	struct service_response resp = {0};

	size_t cmd_size = 0;
	unsigned char cmd_buf[CMD_LEN_MAX];

	struct service_command cmd_cr = {.cmd = cmd, .pid = pid};
	memcpy(cmd_buf, &cmd_cr, sizeof(struct service_command));
	cmd_size += sizeof(struct service_command);

	if (opt && opt->is_dump_dir) {
		memcr_svc_checkpoint_options opt_id = MEMCR_CHECKPOINT_DUMPDIR;
		memcpy(cmd_buf+cmd_size, &opt_id, sizeof(memcr_svc_checkpoint_options));
		cmd_size += sizeof(memcr_svc_checkpoint_options);
		strncpy((char*)cmd_buf + cmd_size, opt->dump_dir, MEMCR_DUMPDIR_LEN_MAX);
		cmd_size += strlen(opt->dump_dir) + 1;
	}

	if (opt && opt->is_compress_alg) {
		memcr_svc_checkpoint_options opt_id = MEMCR_CHECKPOINT_COMPRESS_ALG;
		memcpy(cmd_buf+cmd_size, &opt_id, sizeof(memcr_svc_checkpoint_options));
		cmd_size += sizeof(memcr_svc_checkpoint_options);
		memcpy(cmd_buf+cmd_size, &opt->compress_alg, sizeof(memcr_compress_alg));
		cmd_size += sizeof(memcr_compress_alg);
	}

	struct service_command cmd_v2 = {.cmd = MEMCR_CMDS_V2, .pid = cmd_size};

	ret = write(cd, &cmd_v2, sizeof(cmd_v2));
	if (ret != sizeof(cmd_v2)) {
		fprintf(stderr, "%s() write request failed: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	ret = write(cd, cmd_buf, cmd_size);
	if (ret != cmd_size) {
		fprintf(stderr, "%s() write request failed: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	ret = read(cd, &resp, sizeof(struct service_response));
	if (ret != sizeof(struct service_response)) {
		fprintf(stderr, "%s() read response failed: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	fprintf(stdout, "Procedure finished with %s status.\n", MEMCR_OK == resp.resp_code ? "OK" : "ERROR");

	return resp.resp_code;
}

static void usage(const char *name, int status)
{
	fprintf(status ? stderr : stdout,
		"%s -l PORT|PATH -p PID [-c [-d DIR] [-z ALG] -r]\n" \
		"options: \n" \
		"  -h --help\t\thelp\n" \
		"  -l --location\t\tTCP port number of localhost memcr service\n" \
		"\t\t\t or filesystem path to memcr service UNIX socket\n" \
		"  -p --pid\t\tprocess ID to be checkpointed / restored\n" \
		"  -c --checkpoint\tsend checkpoint command to memcr service\n" \
		"  -d --dir\tdir where memory dump is stored of max length %d\n" \
		"  -z --compress\tcompress memory dump with selected algorithm: 'lz4', 'zstd' or disable with 'none'\n" \
		"  -r --restore\t\tsend restore command to memcr service\n" \
		"  -v --v1\t\tforce using old protocol\n",
		name, MEMCR_DUMPDIR_LEN_MAX);
	exit(status);
}

int main(int argc, char *argv[])
{
	int ret, cd, opt;
	int checkpoint = 0;
	int restore = 0;
	int port = -1;
	int option_index;
	char *comm_location = NULL;
	int pid = 0;
	const char *dump_dir_s = 0;
	const char *compress_alg_s = 0;
	struct service_options checkpoint_options = {0};
	int v1 = 0;

	struct option long_options[] = {
		{ "help",       0,  0,  'h'},
		{ "location",   1,  0,  'l'},
		{ "pid",        1,  0,  'p'},
		{ "checkpoint", 0,  0,  'c'},
		{ "dir",        1,  0,  'd'},
		{ "compress",   1,  0,  'z'},
		{ "restore",    0,  0,  'r'},
		{ "v1",         0,  0,  'v'},
		{ NULL,         0,  0,  0  }
	};

	while ((opt = getopt_long(argc, argv, "hl:p:cr", long_options, &option_index)) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0], 0);
				break;
			case 'l':
				comm_location = optarg;
				break;
			case 'p':
				pid = atoi(optarg);
				break;
			case 'c':
				checkpoint = 1;
				break;
			case 'd':
				dump_dir_s = optarg;
				break;
			case 'z':
				compress_alg_s = optarg;
				break;
			case 'r':
				restore = 1;
				break;
			case 'v':
				v1 = 1;
				break;
			default: /* '?' */
				usage(argv[0], 1);
				break;
		}
	}

	if (!pid || !comm_location) {
		fprintf(stderr, "Incorrect arguments provided!\n");
		usage(argv[0], 1);
		return -1;
	}

	if (!checkpoint && !restore) {
		fprintf(stderr, "You have to provide a command (checkpoint or restore or both)!\n");
		usage(argv[0], 1);
		return -1;
	}

	if (!checkpoint && (dump_dir_s || compress_alg_s)) {
		fprintf(stderr, "Dir dump and compression is available only for checkpoint!\n");
		usage(argv[0], 1);
		return -1;
	}

	if (dump_dir_s) {
		if (strlen(dump_dir_s) >= MEMCR_DUMPDIR_LEN_MAX) {
			fprintf(stderr, "Dir dump too long!\n");
			usage(argv[0], 1);
			return -1;
		}

		strcpy(checkpoint_options.dump_dir, dump_dir_s);
		checkpoint_options.is_dump_dir = 1;
	}

	if (compress_alg_s) {
		checkpoint_options.is_compress_alg = 1;
		if (strcmp(compress_alg_s, "none") == 0)
			checkpoint_options.compress_alg = MEMCR_COMPRESS_NONE;
		else if (strcmp(compress_alg_s, "lz4") == 0)
			checkpoint_options.compress_alg = MEMCR_COMPRESS_LZ4;
		else if (strcmp(compress_alg_s, "zstd") == 0)
			checkpoint_options.compress_alg = MEMCR_COMPRESS_ZSTD;
		else {
			fprintf(stderr, "Incorrect compression algorithm provided!\n");
			usage(argv[0], 1);
			return -1;
		}
	}

	port = atoi(comm_location);

	if (checkpoint) {
		fprintf(stdout, "Will checkpoint %d.\n", pid);

		if (port > 0)
			cd = connect_tcp(port);
		else
			cd = connect_unix(comm_location);

		if (cd < 0) {
			fprintf(stderr, "Connection creation failed!\n");
			return cd;
		}

		if (v1) {
			struct service_command cmd = {.cmd = MEMCR_CHECKPOINT, .pid = pid};
			ret = send_cmd(cd, cmd);
		} else
			ret = send_cmd_v2(cd, MEMCR_CHECKPOINT, pid, &checkpoint_options);

		close(cd);
	}

	if (restore) {
		fprintf(stdout, "Will restore %d.\n", pid);

		if (port > 0)
			cd = connect_tcp(port);
		else
			cd = connect_unix(comm_location);

		if (cd < 0) {
			fprintf(stderr, "Connection creation failed!\n");
			return cd;
		}

		if (v1) {
			struct service_command cmd = {.cmd = MEMCR_RESTORE, .pid = pid};
			ret = send_cmd(cd, cmd);
		} else
			ret = send_cmd_v2(cd, MEMCR_RESTORE, pid, NULL);

		close(cd);
	}

	fprintf(stdout, "Command executed, exiting.\n");
	return ret;
}

