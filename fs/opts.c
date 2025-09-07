// SPDX-License-Identifier: GPL-2.0
/*
 * BFC Filesystem - Mount option parsing
 * 
 * Copyright (c) 2021 zombocoder (Taras Havryliak)
 * Copyright (c) 2024 bfcfs contributors
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/parser.h>

#include "bfcfs.h"

enum {
	Opt_source,
	Opt_verify,
	Opt_key,
	Opt_noreadahead,
	Opt_err
};

static const match_table_t tokens = {
	{Opt_source, "source=%s"},
	{Opt_verify, "verify=%s"},  
	{Opt_key, "key=%s"},
	{Opt_noreadahead, "noreadahead"},
	{Opt_err, NULL}
};

static int parse_verify_mode(const char *str, enum verify_mode *mode)
{
	if (strcmp(str, "none") == 0) {
		*mode = VERIFY_NONE;
	} else if (strcmp(str, "shallow") == 0) {
		*mode = VERIFY_SHALLOW;
	} else if (strcmp(str, "deep") == 0) {
		*mode = VERIFY_DEEP;
	} else {
		return -EINVAL;
	}
	return 0;
}

/**
 * bfcfs_parse_mount_options - Parse mount options string
 * @data: mount options string
 * @opts: output structure for parsed options
 *
 * Supported options:
 *   source=PATH      - Path to .bfc container file (required)
 *   verify=MODE      - Verification mode: none, shallow, deep (default: shallow)
 *   key=DESC         - Keyring descriptor override (default: bfcfs:<uuid>)
 *   noreadahead      - Disable readahead optimization
 *
 * Returns: 0 on success, -EINVAL on error
 */
int bfcfs_parse_mount_options(char *data, struct bfcfs_mount_opts *opts)
{
	substring_t args[MAX_OPT_ARGS];
	char *p;
	int token;
	int ret = 0;

	/* Set defaults */
	memset(opts, 0, sizeof(*opts));
	opts->verify = VERIFY_SHALLOW;
	opts->noreadahead = false;
	strcpy(opts->key_desc, "bfcfs:");  /* Will append UUID later */

	if (!data) {
		pr_err("bfcfs: no mount options provided\n");
		return -EINVAL;
	}

	while ((p = strsep(&data, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_source: {
			char *path = match_strdup(&args[0]);
			if (!path) {
				ret = -ENOMEM;
				break;
			}
			
			if (strlen(path) >= PATH_MAX) {
				pr_err("bfcfs: source path too long\n");
				kfree(path);
				ret = -ENAMETOOLONG;
				break;
			}
			
			strcpy(opts->source, path);
			kfree(path);
			break;
		}
		
		case Opt_verify: {
			char *mode_str = match_strdup(&args[0]);
			if (!mode_str) {
				ret = -ENOMEM;
				break;
			}
			
			ret = parse_verify_mode(mode_str, &opts->verify);
			if (ret) {
				pr_err("bfcfs: invalid verify mode '%s'\n", mode_str);
			}
			kfree(mode_str);
			break;
		}
		
		case Opt_key: {
			char *key_desc = match_strdup(&args[0]);
			if (!key_desc) {
				ret = -ENOMEM;
				break;
			}
			
			if (strlen(key_desc) >= sizeof(opts->key_desc)) {
				pr_err("bfcfs: key descriptor too long\n");
				kfree(key_desc);
				ret = -ENAMETOOLONG;
				break;
			}
			
			strcpy(opts->key_desc, key_desc);
			kfree(key_desc);
			break;
		}
		
		case Opt_noreadahead:
			opts->noreadahead = true;
			break;
			
		default:
			pr_err("bfcfs: unrecognized mount option '%s'\n", p);
			ret = -EINVAL;
			break;
		}
		
		if (ret)
			break;
	}

	/* Validate required options */
	if (ret == 0 && opts->source[0] == '\0') {
		pr_err("bfcfs: 'source' option is required\n");
		ret = -EINVAL;
	}

	if (ret == 0) {
		pr_debug("bfcfs: mount options parsed - source='%s', verify=%d, key='%s', noreadahead=%d\n",
			 opts->source, opts->verify, opts->key_desc, opts->noreadahead);
	}

	return ret;
}