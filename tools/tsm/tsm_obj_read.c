// SPDX-License-Identifier: GPL-2.0-only
/*
 * Userspace tool for the device-evidence generic netlink family.
 * Linux-only (netlink/genl); no Windows or portable-OS paths.
 */

#if 0
	python3 tools/net/ynl/pyynl/cli.py --family device-evidence --dump read \
	--json "{\"type-mask\": 512, \"subsys\": \"pci\", \"dev-name\": \"$(basename $pci_dev)\", \"flags\": 0}" \
	--output-json > json
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include <linux/netlink.h>
#include <linux/genetlink.h>

//#include <linux/device-evidence.h>
#define DEVICE_EVIDENCE_FAMILY_NAME	"device-evidence"
#define DEVICE_EVIDENCE_FAMILY_VERSION	1

#define DEVICE_EVIDENCE_MAX_OBJECT_SIZE	16777216
#define DEVICE_EVIDENCE_MAX_NONCE_SIZE	32

/*
 * Device security evidence request flags
 */
enum device_evidence_type_flag {
	DEVICE_EVIDENCE_TYPE_FLAG_CERT0 = 1,
	DEVICE_EVIDENCE_TYPE_FLAG_CERT1 = 2,
	DEVICE_EVIDENCE_TYPE_FLAG_CERT2 = 4,
	DEVICE_EVIDENCE_TYPE_FLAG_CERT3 = 8,
	DEVICE_EVIDENCE_TYPE_FLAG_CERT4 = 16,
	DEVICE_EVIDENCE_TYPE_FLAG_CERT5 = 32,
	DEVICE_EVIDENCE_TYPE_FLAG_CERT6 = 64,
	DEVICE_EVIDENCE_TYPE_FLAG_CERT7 = 128,
	DEVICE_EVIDENCE_TYPE_FLAG_VCA = 256,
	DEVICE_EVIDENCE_TYPE_FLAG_MEASUREMENTS = 512,
	DEVICE_EVIDENCE_TYPE_FLAG_REPORT = 1024,

	/* private: */
	DEVICE_EVIDENCE_TYPE_FLAG_MASK = 2047,
};

enum device_evidence_type {
	DEVICE_EVIDENCE_TYPE_CERT0,
	DEVICE_EVIDENCE_TYPE_CERT1,
	DEVICE_EVIDENCE_TYPE_CERT2,
	DEVICE_EVIDENCE_TYPE_CERT3,
	DEVICE_EVIDENCE_TYPE_CERT4,
	DEVICE_EVIDENCE_TYPE_CERT5,
	DEVICE_EVIDENCE_TYPE_CERT6,
	DEVICE_EVIDENCE_TYPE_CERT7,
	DEVICE_EVIDENCE_TYPE_VCA,
	DEVICE_EVIDENCE_TYPE_MEASUREMENTS,
	DEVICE_EVIDENCE_TYPE_REPORT,

	/* private: */
	__DEVICE_EVIDENCE_TYPE_MAX,
	DEVICE_EVIDENCE_TYPE_MAX = (__DEVICE_EVIDENCE_TYPE_MAX - 1)
};

enum {
	DEVICE_EVIDENCE_A_OBJECT_TYPE = 1,
	DEVICE_EVIDENCE_A_OBJECT_TYPE_MASK,
	DEVICE_EVIDENCE_A_OBJECT_FLAGS,
	DEVICE_EVIDENCE_A_OBJECT_SUBSYS,
	DEVICE_EVIDENCE_A_OBJECT_DEV_NAME,
	DEVICE_EVIDENCE_A_OBJECT_NONCE,
	DEVICE_EVIDENCE_A_OBJECT_GENERATION,
	DEVICE_EVIDENCE_A_OBJECT_COUNT,
	DEVICE_EVIDENCE_A_OBJECT_LENGTH,
	DEVICE_EVIDENCE_A_OBJECT_VAL,

	__DEVICE_EVIDENCE_A_OBJECT_MAX,
	DEVICE_EVIDENCE_A_OBJECT_MAX = (__DEVICE_EVIDENCE_A_OBJECT_MAX - 1)
};

enum {
	DEVICE_EVIDENCE_CMD_READ = 1,
	DEVICE_EVIDENCE_CMD_VALIDATE,

	__DEVICE_EVIDENCE_CMD_MAX,
	DEVICE_EVIDENCE_CMD_MAX = (__DEVICE_EVIDENCE_CMD_MAX - 1)
};

#define MAX_MSG_SIZE 4096

static const struct {
	const char *name;
	unsigned int type;
	unsigned int flag;
} evidence_types[] = {
	{ "cert0", DEVICE_EVIDENCE_TYPE_CERT0, DEVICE_EVIDENCE_TYPE_FLAG_CERT0 },
	{ "cert1", DEVICE_EVIDENCE_TYPE_CERT1, DEVICE_EVIDENCE_TYPE_FLAG_CERT1 },
	{ "cert2", DEVICE_EVIDENCE_TYPE_CERT2, DEVICE_EVIDENCE_TYPE_FLAG_CERT2 },
	{ "cert3", DEVICE_EVIDENCE_TYPE_CERT3, DEVICE_EVIDENCE_TYPE_FLAG_CERT3 },
	{ "cert4", DEVICE_EVIDENCE_TYPE_CERT4, DEVICE_EVIDENCE_TYPE_FLAG_CERT4 },
	{ "cert5", DEVICE_EVIDENCE_TYPE_CERT5, DEVICE_EVIDENCE_TYPE_FLAG_CERT5 },
	{ "cert6", DEVICE_EVIDENCE_TYPE_CERT6, DEVICE_EVIDENCE_TYPE_FLAG_CERT6 },
	{ "cert7", DEVICE_EVIDENCE_TYPE_CERT7, DEVICE_EVIDENCE_TYPE_FLAG_CERT7 },
	{ "vca", DEVICE_EVIDENCE_TYPE_VCA, DEVICE_EVIDENCE_TYPE_FLAG_VCA },
	{ "measurements", DEVICE_EVIDENCE_TYPE_MEASUREMENTS,
	  DEVICE_EVIDENCE_TYPE_FLAG_MEASUREMENTS },
	{ "report", DEVICE_EVIDENCE_TYPE_REPORT, DEVICE_EVIDENCE_TYPE_FLAG_REPORT },
};

static const char *evidence_type_name(unsigned int type)
{
	size_t i;

	for (i = 0; i < sizeof(evidence_types) / sizeof(evidence_types[0]); i++) {
		if (evidence_types[i].type == type)
			return evidence_types[i].name;
	}
	return "unknown";
}

static int parse_type(const char *s, unsigned int *type_mask)
{
	unsigned long id;
	char *end;
	size_t i;

	for (i = 0; i < sizeof(evidence_types) / sizeof(evidence_types[0]); i++) {
		if (!strcmp(s, evidence_types[i].name)) {
			*type_mask = evidence_types[i].flag;
			return 0;
		}
	}

	id = strtoul(s, &end, 0);
	if (!*s || *end)
		return -1;

	/* Numeric type id (0..MAX) */
	if (id <= DEVICE_EVIDENCE_TYPE_MAX) {
		*type_mask = 1U << id;
		return 0;
	}

	/* Otherwise treat as a flag bitmask */
	if (id > DEVICE_EVIDENCE_TYPE_FLAG_MASK)
		return -1;
	*type_mask = id;
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --dev-name <pci-device> (--type <name|id> | --type-mask <mask>)\n"
		"       [--subsys <name>] [--flags <flags>] [--nonce <path>] [--output <path>]\n"
		"\n"
		"  --type <name>       evidence type: cert0..cert7, vca, measurements, report\n"
		"                      or numeric type id (e.g. 9 for measurements)\n"
		"  --type-mask <mask>  flag bitmask (measurements=0x200, report=0x400, vca=0x100)\n"
		"  --nonce <path>      refresh dynamic evidence before read ('-' = stdin);\n"
		"                      required to populate measurements\n"
		"  --output <path>     write payload to file, or '-' for stdout\n"
		"  --subsys <name>     evidence provider (default: pci)\n",
		prog);
}

static void empty_type_hint(unsigned int type, int refreshed)
{
	switch (type) {
	case DEVICE_EVIDENCE_TYPE_VCA:
		fprintf(stderr,
			"  hint: vca is often omitted; try measurements (0x200) instead\n");
		break;
	case DEVICE_EVIDENCE_TYPE_MEASUREMENTS:
		if (!refreshed)
			fprintf(stderr,
				"  hint: measurements need --nonce to refresh (e.g. --nonce -)\n");
		break;
	case DEVICE_EVIDENCE_TYPE_REPORT:
		fprintf(stderr,
			"  hint: report is populated at lock; ensure the device is locked\n");
		break;
	default:
		break;
	}
}

/*
 * Reads up to @max_len bytes (inclusive ceiling 0..DEVICE_EVIDENCE_MAX_NONCE_SIZE).
 * Fails if the source has more than @max_len bytes available before EOF.
 */
static int read_nonce(const char *path, unsigned char *buf, size_t max_len,
		      size_t *out_len)
{
	FILE *fp;
	size_t total = 0;
	int use_stdin = !strcmp(path, "-");

	if (use_stdin) {
		fp = stdin;
	} else {
		fp = fopen(path, "rb");
		if (!fp) {
			perror("fopen");
			return -1;
		}
	}

	while (total < max_len) {
		size_t n = fread(buf + total, 1, max_len - total, fp);

		if (n == 0)
			break;
		total += n;
	}

	if (total == max_len) {
		char probe[1];
		size_t extra = fread(probe, 1, 1, fp);

		if (extra != 0) {
			fprintf(stderr, "nonce must be at most %zu bytes\n", max_len);
			if (!use_stdin)
				fclose(fp);
			return -1;
		}
	}

	if (!use_stdin)
		fclose(fp);

	*out_len = total;
	return 0;
}

static int write_output(const char *path, const unsigned char *buf, size_t len)
{
	FILE *fp;
	size_t n;
	int use_stdout = !strcmp(path, "-");

	if (use_stdout) {
		fp = stdout;
	} else {
		fp = fopen(path, "wb");
		if (!fp) {
			perror("fopen");
			return -1;
		}
	}

	n = fwrite(buf, 1, len, fp);

	if (n != len) {
		if (!use_stdout)
			fclose(fp);
		fprintf(stderr, "failed to write %zu bytes (wrote %zu)\n", len, n);
		return -1;
	}

	if (!use_stdout)
		fclose(fp);
	else if (fflush(stdout)) {
		perror("fflush");
		return -1;
	}

	return 0;
}

static int nla_put(struct nlmsghdr *nlh, size_t maxlen, int type,
		   const void *data, size_t len)
{
	size_t attr_len = NLA_HDRLEN + len;
	size_t attr_len_aligned = NLA_ALIGN(attr_len);
	struct nlattr *nla;

	if (nlh->nlmsg_len + attr_len_aligned > maxlen)
		return -1;

	nla = (struct nlattr *)((char *)nlh + nlh->nlmsg_len);
	nla->nla_type = type;
	nla->nla_len = attr_len;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
	memset((char *)nla + attr_len, 0, attr_len_aligned - attr_len);
	nlh->nlmsg_len += attr_len_aligned;
	return 0;
}

static int nla_parse_attr(struct nlattr *nla, int *remaining)
{
	if (*remaining < (int)sizeof(*nla))
		return 0;
	if (nla->nla_len < sizeof(*nla) || nla->nla_len > *remaining)
		return 0;
	return 1;
}

static struct nlattr *nla_next(struct nlattr *nla, int *remaining)
{
	int len = NLA_ALIGN(nla->nla_len);

	*remaining -= len;
	return (struct nlattr *)((char *)nla + len);
}

static int get_family_id(int sock_fd)
{
	int family_id = -1;
	int ret, remaining;
	struct nlattr *attr;
	char buf[MAX_MSG_SIZE];
	struct genlmsghdr *genlh;
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	size_t name_len = sizeof(DEVICE_EVIDENCE_FAMILY_NAME);
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 1;
	nlh->nlmsg_pid = getpid();

	genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	genlh->cmd = CTRL_CMD_GETFAMILY;
	genlh->version = 1;

	if (nla_put(nlh, sizeof(buf),
		    CTRL_ATTR_FAMILY_NAME, DEVICE_EVIDENCE_FAMILY_NAME, name_len)) {
		fprintf(stderr, "failed to build CTRL request\n");
		return -1;
	}

	ret = sendto(sock_fd, nlh, nlh->nlmsg_len, 0,
		     (struct sockaddr *)&nladdr, sizeof(nladdr));
	if (ret < 0) {
		perror("sendto");
		return -1;
	}

	ret = recv(sock_fd, buf, sizeof(buf), 0);
	if (ret < 0) {
		perror("recv");
		return -1;
	}

	for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, ret);
	     nlh = NLMSG_NEXT(nlh, ret)) {
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = NLMSG_DATA(nlh);

			fprintf(stderr, "netlink error when fetching family: %s\n",
				strerror(-err->error));
			return -1;
		}

		genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
		attr = (struct nlattr *)((char *)genlh + GENL_HDRLEN);
		remaining = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

		while (nla_parse_attr(attr, &remaining)) {
			if (attr->nla_type == CTRL_ATTR_FAMILY_ID) {
				uint16_t id;

				memcpy(&id, (char *)attr + NLA_HDRLEN, sizeof(id));
				family_id = id;
				return family_id;
			}
			attr = nla_next(attr, &remaining);
		}
	}

	fprintf(stderr, "family id not found\n");
	return -1;
}

static void hexdump(const unsigned char *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (i && i % 16 == 0)
			fprintf(stderr, "\n");
		fprintf(stderr, "%02x ", buf[i]);
	}
	fprintf(stderr, "\n");
}

/*
 * Emit one fully reassembled evidence object. The kernel fragments large
 * objects across multiple dump skbs: TYPE, GENERATION and LENGTH start an
 * object; follow-on skbs carry VAL only (see device_evidence_nl_read in
 * drivers/base/evidence.c).
 */
static int flush_evidence_object(int type, uint32_t generation,
				 const unsigned char *buf, size_t len,
				 size_t expected_len, const char *output_path,
				 int refreshed, int *objects_seen, int *output_used)
{
	(*objects_seen)++;

	if (expected_len && len != expected_len) {
		fprintf(stderr,
			"%s (%u): received %zu bytes, expected %zu\n",
			evidence_type_name(type), type, len, expected_len);
		return -1;
	}

	if (!len) {
		fprintf(stderr,
			"%s (%u): empty (generation %u",
			evidence_type_name(type), type, generation);
		if (!refreshed)
			fprintf(stderr, "; no --nonce refresh");
		fprintf(stderr, ")\n");
		empty_type_hint(type, refreshed);
		return output_path ? -1 : 0;
	}

	if (output_path && !strcmp(output_path, "-")) {
		fprintf(stderr, "%s (%u), generation %u, length %zu bytes\n",
			evidence_type_name(type), type, generation, len);
	} else {
		fprintf(stderr,
			"%s (%u), generation %u, length %zu bytes (first 128 bytes):\n",
			evidence_type_name(type), type, generation, len);
		hexdump(buf, len < 128 ? len : 128);
	}

	if (!output_path)
		return 0;

	if (*output_used) {
		fprintf(stderr,
			"multiple objects with data; use a single-bit type-mask for --output\n");
		return -1;
	}

	if (write_output(output_path, buf, len))
		return -1;

	*output_used = 1;
	return 0;
}

int main(int argc, char **argv)
{
	int opt;
	int sock_fd;
	struct nlattr *attr;
	struct nlmsghdr *nlh;
	char *req_buf, *resp_buf;
	struct genlmsghdr *genlh;
	int family_id;
	int ret, done = 0, remaining;
	int current_type = -1;
	uint32_t current_generation;
	size_t expected_len;
	const char *output_path = NULL;
	const char *dev_name = NULL;
	const char *subsys = "pci";
	unsigned int type_mask = 0;
	unsigned int flags = 0;
	int have_nonce = 0, have_type_mask = 0;
	int have_type = 0;
	size_t nonce_len = 0;
	int have_reply_type = 0;
	int reply_type = -1;
	uint32_t reply_generation;
	size_t reply_length;
	int have_reply_length = 0;
	int objects_seen = 0;
	int output_used = 0;
	int exit_status = 1;
	size_t acc_len = 0;
	unsigned char *nonce, *reply_buf;
	size_t resp_buf_len = DEVICE_EVIDENCE_MAX_OBJECT_SIZE + 1024;
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };

	static const struct option long_options[] = {
		{ "dev-name", required_argument, NULL, 'd' },
		{ "type", required_argument, NULL, 'T' },
		{ "type-mask", required_argument, NULL, 't' },
		{ "subsys", required_argument, NULL, 's' },
		{ "flags", required_argument, NULL, 'f' },
		{ "nonce", required_argument, NULL, 'n' },
		{ "output", required_argument, NULL, 'o' },
		{ NULL, 0, NULL, 0 }
	};

	req_buf = calloc(1, MAX_MSG_SIZE);
	resp_buf = calloc(1, resp_buf_len);
	nonce = malloc(DEVICE_EVIDENCE_MAX_NONCE_SIZE);
	if (!req_buf || !resp_buf || !nonce) {
		fprintf(stderr, "allocation failed\n");
		goto out_free;
	}

	reply_buf = calloc(1, DEVICE_EVIDENCE_MAX_OBJECT_SIZE);
	if (!reply_buf) {
		fprintf(stderr, "allocation failed\n");
		goto out_free;
	}

	while ((opt = getopt_long(argc, argv, "d:T:t:s:f:n:o:", long_options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			dev_name = optarg;
			break;
		case 'T':
			if (parse_type(optarg, &type_mask)) {
				fprintf(stderr, "unknown evidence type '%s'\n", optarg);
				goto out_free;
			}
			have_type = 1;
			break;
		case 't':
			type_mask = strtoul(optarg, NULL, 0);
			have_type_mask = 1;
			break;
		case 's':
			subsys = optarg;
			break;
		case 'f':
			flags = strtoul(optarg, NULL, 0);
			break;
		case 'n':
			if (read_nonce(optarg, nonce, DEVICE_EVIDENCE_MAX_NONCE_SIZE,
				       &nonce_len))
				goto out_free;
			have_nonce = 1;
			break;
		case 'o':
			output_path = optarg;
			break;
		default:
			usage(argv[0]);
			goto out_free;
		}
	}

	if (!dev_name) {
		usage(argv[0]);
		goto out_free;
	}
	if (have_type && have_type_mask) {
		fprintf(stderr, "use either --type or --type-mask, not both\n");
		goto out_free;
	}
	if (!have_type && !have_type_mask) {
		usage(argv[0]);
		goto out_free;
	}
	if (optind < argc) {
		usage(argv[0]);
		goto out_free;
	}
	if (type_mask > DEVICE_EVIDENCE_TYPE_FLAG_MASK) {
		fprintf(stderr, "type-mask exceeds 0x%x\n",
			DEVICE_EVIDENCE_TYPE_FLAG_MASK);
		goto out_free;
	}

	sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock_fd < 0) {
		perror("socket");
		goto out_free;
	}

	if (bind(sock_fd, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
		perror("bind");
		goto out_close;
	}

	family_id = get_family_id(sock_fd);
	if (family_id < 0) {
		goto out_close;
	}

	nlh = (struct nlmsghdr *)req_buf;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = 2;
	nlh->nlmsg_pid = getpid();

	genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	genlh->cmd = DEVICE_EVIDENCE_CMD_READ;
	genlh->version = DEVICE_EVIDENCE_FAMILY_VERSION;

	if (nla_put(nlh, MAX_MSG_SIZE, DEVICE_EVIDENCE_A_OBJECT_TYPE_MASK,
		    &type_mask, sizeof(type_mask))) {
		fprintf(stderr, "failed to add type-mask attribute\n");
		goto out_close;
	}

	if (nla_put(nlh, MAX_MSG_SIZE, DEVICE_EVIDENCE_A_OBJECT_FLAGS,
		    &flags, sizeof(flags))) {
		fprintf(stderr, "failed to add flags attribute\n");
		goto out_close;
	}

	if (nla_put(nlh, MAX_MSG_SIZE, DEVICE_EVIDENCE_A_OBJECT_SUBSYS,
		    subsys, strlen(subsys) + 1)) {
		fprintf(stderr, "failed to add subsys attribute\n");
		goto out_close;
	}

	if (nla_put(nlh, MAX_MSG_SIZE, DEVICE_EVIDENCE_A_OBJECT_DEV_NAME,
		    dev_name, strlen(dev_name) + 1)) {
		fprintf(stderr, "failed to add device name attribute\n");
		goto out_close;
	}

	if (have_nonce) {
		if (nla_put(nlh, MAX_MSG_SIZE, DEVICE_EVIDENCE_A_OBJECT_NONCE,
			    nonce, nonce_len)) {
			fprintf(stderr, "failed to add nonce attribute\n");
			goto out_close;
		}
	}

	ret = sendto(sock_fd, nlh, nlh->nlmsg_len, 0,
		     (struct sockaddr *)&nladdr, sizeof(nladdr));
	if (ret < 0) {
		perror("sendto");
		goto out_close;
	}

	while (!done) {
		ret = recv(sock_fd, resp_buf, resp_buf_len, 0);
		if (ret < 0) {
			perror("recv");
			goto out_close;
		}

		for (nlh = (struct nlmsghdr *)resp_buf; NLMSG_OK(nlh, ret);
		     nlh = NLMSG_NEXT(nlh, ret)) {
			const unsigned char *val_data = NULL;
			size_t val_len = 0;

			if (nlh->nlmsg_type == NLMSG_DONE) {
				done = 1;
				break;
			}
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = NLMSG_DATA(nlh);

				if (err->error == 0)
					continue;

				fprintf(stderr, "netlink error: %s\n",
					strerror(-err->error));
				goto out_close;
			}

			if (nlh->nlmsg_type != (unsigned int)family_id)
				continue;

			genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
			attr = (struct nlattr *)((char *)genlh + GENL_HDRLEN);
			remaining = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
			have_reply_type = 0;
			have_reply_length = 0;

			while (nla_parse_attr(attr, &remaining)) {
				int atype = (int)(attr->nla_type & NLA_TYPE_MASK);

				switch (atype) {
				case DEVICE_EVIDENCE_A_OBJECT_TYPE:
				{
					uint32_t attr_type;

					if (attr->nla_len != NLA_HDRLEN + sizeof(attr_type))
						break;
					memcpy(&attr_type, (char *)attr + NLA_HDRLEN,
					       sizeof(attr_type));
					reply_type = attr_type;
					have_reply_type = 1;
					break;
				}
				case DEVICE_EVIDENCE_A_OBJECT_GENERATION:
				{
					uint32_t gen;

					if (attr->nla_len != NLA_HDRLEN + sizeof(gen))
						break;
					memcpy(&gen, (char *)attr + NLA_HDRLEN, sizeof(gen));
					reply_generation = gen;
					break;
				}
				case DEVICE_EVIDENCE_A_OBJECT_LENGTH:
				{
					uint32_t len;

					if (attr->nla_len != NLA_HDRLEN + sizeof(len))
						break;
					memcpy(&len, (char *)attr + NLA_HDRLEN, sizeof(len));
					reply_length = len;
					have_reply_length = 1;
					break;
				}
				case DEVICE_EVIDENCE_A_OBJECT_VAL:
				{
					int len = attr->nla_len - NLA_HDRLEN;

					if (len < 0) {
						fprintf(stderr, "invalid VAL attribute\n");
						goto out_close;
					}
					val_data = (const unsigned char *)attr + NLA_HDRLEN;
					val_len = len;
					break;
				}
				default:
					break;
				}
				attr = nla_next(attr, &remaining);
			}

			if (have_reply_type) {
				if (current_type >= 0) {
					ret = flush_evidence_object(current_type,
								    current_generation,
								    reply_buf, acc_len,
								    expected_len,
								    output_path,
								    have_nonce,
								    &objects_seen,
								    &output_used);
					if (ret)
						goto out_close;
					acc_len = 0;
				}
				current_type = reply_type;
				current_generation = reply_generation;
				expected_len = have_reply_length ? reply_length : 0;
			} else if (current_type < 0) {
				fprintf(stderr, "missing type in response\n");
				goto out_close;
			}

			if (val_len) {
				if (acc_len + val_len > DEVICE_EVIDENCE_MAX_OBJECT_SIZE) {
					fprintf(stderr, "response too large\n");
					goto out_close;
				}
				memcpy(reply_buf + acc_len, val_data, val_len);
				acc_len += val_len;
			}

			if (expected_len && acc_len > expected_len) {
				fprintf(stderr,
					"type %d: received more than length %zu\n",
					current_type, expected_len);
				goto out_close;
			}
		}
	}

	if (current_type >= 0) {
		ret = flush_evidence_object(current_type, current_generation,
					    reply_buf, acc_len, expected_len,
					    output_path, have_nonce,
					    &objects_seen, &output_used);
		if (ret)
			goto out_close;
	}

	if (!objects_seen) {
		fprintf(stderr, "empty response\n");
		goto out_close;
	}

	exit_status = 0;

out_close:
	close(sock_fd);
out_free:
	free(req_buf);
	free(resp_buf);
	free(nonce);
	free(reply_buf);
	return exit_status;
}
