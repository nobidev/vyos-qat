/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2021 - 2022 Intel Corporation */
#ifndef QAT_DBG_COMMON_H_
#define QAT_DBG_COMMON_H_

#define QATD_CRASH_DEBOUNCE_TIME 5
#define QATD_MAX_FILE_NAME 256
#define QATD_MAX_FILE_LINE 62
#define QATD_MAGIC 'q'
#define QATD_CMD_STATUS (1)
#define QATD_CMD_SYNC (2)
#define QATD_CMD_SEG_REQ (3)
#define QATD_CMD_SEG_REL (4)
#define QATD_CMD_CRASH_DUMP (5)
#define QATD_CMD_ERR_RESP (6)
#define QATD_CMD_BSF_TO_ID (7)

#define QATD_PARAM_SYSFS_DIR "qat_debug"
#define QATD_PARAM_ENABLED "enabled"
#define QATD_PARAM_DUMP_DIR "dump_dir"
#define QATD_PARAM_DUMP_DIR_SZ "dump_dir_size_mb"
#define QATD_PARAM_BUFFER_POOL_SZ "buffer_pool_size"
#define QATD_PARAM_BUFFER_SZ "buffer_size_mb"
#define QATD_PARAM_LEVEL "level"
#define QATD_PARAM_CS_ENABLED "cont_sync_enabled"
#define QATD_PARAM_CS_DIR "cont_sync_dir"
#define QATD_PARAM_CS_MAX_FILE_SZ "cont_sync_max_file_size_mb"
#define QATD_PARAM_CS_MAX_FILES_NO "cont_sync_max_files"
#define QATD_PARAM_DUMP_ON_P_CRASH "dump_on_process_crash"

#define QATD_1MB_SHIFT 20
#define QATD_MMAP_DEV_HEADER "Device"

enum qatd_buffer_state {
	QATD_BUFFER_FREE,
	QATD_BUFFER_BUSY
};

enum qatd_sync_mode {
	QATD_SYNC_ON_CRASH,
	QATD_SYNC_CONT
};

struct qatd_instance_config {
	/* Max size for crash dump in crash dump directory */
	unsigned long dump_dir_max_size;
	/* Max size of single cont-sync log file  */
	unsigned long cont_sync_max_file_size;
	/* Max number of files used by cont-sync */
	unsigned int cont_sync_max_files_no;
	/* Number of debug buffers in memory pool */
	unsigned int buffer_pool_size;
	/* Size of debug buffer */
	unsigned int buffer_size;
	/* Debug level */
	unsigned int debug_level;
	/* Flag - perform crash dump if process crash detected */
	unsigned int dump_on_proc_crash;
	/* Sync mode - continuous vs dump on crash */
	unsigned int sync_mode;
	/* Crash dump dir path */
	char dump_dir[QATD_MAX_FILE_NAME];
	/* Continuous sync directory */
	char cont_sync_dir[QATD_MAX_FILE_NAME];
} __packed;

struct qatd_buffer_desc {
	unsigned long owner_pid;
	struct qatd_ring_desc *ring;
	unsigned int id;
	enum qatd_buffer_state state;
};

#define IOCTL_QATD_STATUS                                                      \
	_IOWR(QATD_MAGIC, QATD_CMD_STATUS, struct qatd_ioctl_req)
#define IOCTL_QATD_SYNC_REQ                                                    \
	_IOWR(QATD_MAGIC, QATD_CMD_SYNC, struct qatd_ioctl_req)
#define IOCTL_QATD_BUFFER_REQ                                                  \
	_IOWR(QATD_MAGIC, QATD_CMD_SEG_REQ, struct qatd_ioctl_req)
#define IOCTL_QATD_BUFFER_RELEASE                                              \
	_IOWR(QATD_MAGIC, QATD_CMD_SEG_REL, struct qatd_ioctl_req)
#define IOCTL_QATD_CRASH_DUMP                                                  \
	_IOWR(QATD_MAGIC, QATD_CMD_CRASH_DUMP, struct qatd_ioctl_req)
#define IOCTL_QATD_ERR_RESP                                                    \
	_IOWR(QATD_MAGIC, QATD_CMD_ERR_RESP, struct qatd_ioctl_req)
#define IOCTL_QATD_BSF_TO_ID                                                   \
	_IOWR(QATD_MAGIC, QATD_CMD_BSF_TO_ID, struct qatd_ioctl_bsf2id_req)

#endif
