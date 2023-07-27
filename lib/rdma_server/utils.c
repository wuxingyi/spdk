#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/env.h"
#include "spdk/rdma_client.h"

int spdk_client_transport_id_populate_trstring(struct spdk_client_transport_id *trid, const char *trstring)
{
	int len, i, rc;

	if (trstring == NULL)
	{
		return -EINVAL;
	}

	len = strnlen(trstring, SPDK_SRV_TRSTRING_MAX_LEN);
	if (len == SPDK_SRV_TRSTRING_MAX_LEN)
	{
		return -EINVAL;
	}

	rc = snprintf(trid->trstring, SPDK_SRV_TRSTRING_MAX_LEN, "%s", trstring);
	if (rc < 0)
	{
		return rc;
	}

	/* cast official trstring to uppercase version of input. */
	for (i = 0; i < len; i++)
	{
		trid->trstring[i] = toupper(trid->trstring[i]);
	}
	return 0;
}

int spdk_client_transport_id_parse_trtype(enum spdk_client_transport_type *trtype, const char *str)
{
	if (trtype == NULL || str == NULL)
	{
		return -EINVAL;
	}
	else if (strcasecmp(str, "RDMA") == 0)
	{
		*trtype = SPDK_CLIENT_TRANSPORT_RDMA;
	}

	return 0;
}

const char *
spdk_client_transport_id_trtype_str(enum spdk_client_transport_type trtype)
{
	switch (trtype)
	{
	case SPDK_CLIENT_TRANSPORT_RDMA:
		return "RDMA";
	default:
		return NULL;
	}
}

int spdk_client_transport_id_parse_adrfam(enum spdk_srv_adrfam *adrfam, const char *str)
{
	if (adrfam == NULL || str == NULL)
	{
		return -EINVAL;
	}

	if (strcasecmp(str, "IPv4") == 0)
	{
		*adrfam = SPDK_SRV_ADRFAM_IPV4;
	}
	else if (strcasecmp(str, "IPv6") == 0)
	{
		*adrfam = SPDK_SRV_ADRFAM_IPV6;
	}
	else if (strcasecmp(str, "IB") == 0)
	{
		*adrfam = SPDK_SRV_ADRFAM_IB;
	}
	else if (strcasecmp(str, "FC") == 0)
	{
		*adrfam = SPDK_SRV_ADRFAM_FC;
	}
	else
	{
		return -ENOENT;
	}
	return 0;
}

const char *
spdk_client_transport_id_adrfam_str(enum spdk_srv_adrfam adrfam)
{
	switch (adrfam)
	{
	case SPDK_SRV_ADRFAM_IPV4:
		return "IPv4";
	case SPDK_SRV_ADRFAM_IPV6:
		return "IPv6";
	case SPDK_SRV_ADRFAM_IB:
		return "IB";
	case SPDK_SRV_ADRFAM_FC:
		return "FC";
	default:
		return NULL;
	}
}

static size_t
parse_next_key(const char **str, char *key, char *val, size_t key_buf_size, size_t val_buf_size)
{

	const char *sep, *sep1;
	const char *whitespace = " \t\n";
	size_t key_len, val_len;

	*str += strspn(*str, whitespace);

	sep = strchr(*str, ':');
	if (!sep)
	{
		sep = strchr(*str, '=');
		if (!sep)
		{
			SPDK_ERRLOG("Key without ':' or '=' separator\n");
			return 0;
		}
	}
	else
	{
		sep1 = strchr(*str, '=');
		if ((sep1 != NULL) && (sep1 < sep))
		{
			sep = sep1;
		}
	}

	key_len = sep - *str;
	if (key_len >= key_buf_size)
	{
		SPDK_ERRLOG("Key length %zu greater than maximum allowed %zu\n",
					key_len, key_buf_size - 1);
		return 0;
	}

	memcpy(key, *str, key_len);
	key[key_len] = '\0';

	*str += key_len + 1; /* Skip key: */
	val_len = strcspn(*str, whitespace);
	if (val_len == 0)
	{
		SPDK_ERRLOG("Key without value\n");
		return 0;
	}

	if (val_len >= val_buf_size)
	{
		SPDK_ERRLOG("Value length %zu greater than maximum allowed %zu\n",
					val_len, val_buf_size - 1);
		return 0;
	}

	memcpy(val, *str, val_len);
	val[val_len] = '\0';

	*str += val_len;

	return val_len;
}

int spdk_client_transport_id_parse(struct spdk_client_transport_id *trid, const char *str)
{
	size_t val_len;
	char key[32];
	char val[1024];

	if (trid == NULL || str == NULL)
	{
		return -EINVAL;
	}

	while (*str != '\0')
	{

		val_len = parse_next_key(&str, key, val, sizeof(key), sizeof(val));

		if (val_len == 0)
		{
			SPDK_ERRLOG("Failed to parse transport ID\n");
			return -EINVAL;
		}

		if (strcasecmp(key, "trtype") == 0)
		{
			if (spdk_client_transport_id_populate_trstring(trid, val) != 0)
			{
				SPDK_ERRLOG("invalid transport '%s'\n", val);
				return -EINVAL;
			}
			if (spdk_client_transport_id_parse_trtype(&trid->trtype, val) != 0)
			{
				SPDK_ERRLOG("Unknown trtype '%s'\n", val);
				return -EINVAL;
			}
		}
		else if (strcasecmp(key, "adrfam") == 0)
		{
			if (spdk_client_transport_id_parse_adrfam(&trid->adrfam, val) != 0)
			{
				SPDK_ERRLOG("Unknown adrfam '%s'\n", val);
				return -EINVAL;
			}
		}
		else if (strcasecmp(key, "traddr") == 0)
		{
			if (val_len > SPDK_SRV_TRADDR_MAX_LEN)
			{
				SPDK_ERRLOG("traddr length %zu greater than maximum allowed %u\n",
							val_len, SPDK_SRV_TRADDR_MAX_LEN);
				return -EINVAL;
			}
			memcpy(trid->traddr, val, val_len + 1);
		}
		else if (strcasecmp(key, "trsvcid") == 0)
		{
			if (val_len > SPDK_SRV_TRSVCID_MAX_LEN)
			{
				SPDK_ERRLOG("trsvcid length %zu greater than maximum allowed %u\n",
							val_len, SPDK_SRV_TRSVCID_MAX_LEN);
				return -EINVAL;
			}
			memcpy(trid->trsvcid, val, val_len + 1);
		}
		else if (strcasecmp(key, "priority") == 0)
		{
			if (val_len > SPDK_SRV_PRIORITY_MAX_LEN)
			{
				SPDK_ERRLOG("priority length %zu greater than maximum allowed %u\n",
							val_len, SPDK_SRV_PRIORITY_MAX_LEN);
				return -EINVAL;
			}
			trid->priority = spdk_strtol(val, 10);
		}
		else if (strcasecmp(key, "hostaddr") == 0)
		{
			continue;
		}
		else if (strcasecmp(key, "hostsvcid") == 0)
		{
			continue;
		}
		else if (strcasecmp(key, "hostnqn") == 0)
		{
			continue;
		}
		else if (strcasecmp(key, "ns") == 0)
		{
			/*
			 * Special case.  The namespace id parameter may
			 * optionally be passed in the transport id string
			 * for an SPDK application (e.g. client/perf)
			 * and additionally parsed therein to limit
			 * targeting a specific namespace.  For this
			 * scenario, just silently ignore this key
			 * rather than letting it default to logging
			 * it as an invalid key.
			 */
			continue;
		}
		else if (strcasecmp(key, "alt_traddr") == 0)
		{
			/*
			 * Used by applications for enabling transport ID failover.
			 * Please see the case above for more information on custom parameters.
			 */
			continue;
		}
		else
		{
			SPDK_ERRLOG("Unknown transport ID key '%s'\n", key);
		}
	}

	return 0;
}

int spdk_client_host_id_parse(struct spdk_client_host_id *hostid, const char *str)
{

	size_t key_size = 32;
	size_t val_size = 1024;
	size_t val_len;
	char key[key_size];
	char val[val_size];

	if (hostid == NULL || str == NULL)
	{
		return -EINVAL;
	}

	while (*str != '\0')
	{

		val_len = parse_next_key(&str, key, val, key_size, val_size);

		if (val_len == 0)
		{
			SPDK_ERRLOG("Failed to parse host ID\n");
			return val_len;
		}

		/* Ignore the rest of the options from the transport ID. */
		if (strcasecmp(key, "trtype") == 0)
		{
			continue;
		}
		else if (strcasecmp(key, "adrfam") == 0)
		{
			continue;
		}
		else if (strcasecmp(key, "traddr") == 0)
		{
			continue;
		}
		else if (strcasecmp(key, "trsvcid") == 0)
		{
			continue;
		}
		else if (strcasecmp(key, "subnqn") == 0)
		{
			continue;
		}
		else if (strcasecmp(key, "priority") == 0)
		{
			continue;
		}
		else if (strcasecmp(key, "ns") == 0)
		{
			continue;
		}
		else if (strcasecmp(key, "hostaddr") == 0)
		{
			if (val_len > SPDK_SRV_TRADDR_MAX_LEN)
			{
				SPDK_ERRLOG("hostaddr length %zu greater than maximum allowed %u\n",
							val_len, SPDK_SRV_TRADDR_MAX_LEN);
				return -EINVAL;
			}
			memcpy(hostid->hostaddr, val, val_len + 1);
		}
		else if (strcasecmp(key, "hostsvcid") == 0)
		{
			if (val_len > SPDK_SRV_TRSVCID_MAX_LEN)
			{
				SPDK_ERRLOG("trsvcid length %zu greater than maximum allowed %u\n",
							val_len, SPDK_SRV_TRSVCID_MAX_LEN);
				return -EINVAL;
			}
			memcpy(hostid->hostsvcid, val, val_len + 1);
		}
		else
		{
			SPDK_ERRLOG("Unknown transport ID key '%s'\n", key);
		}
	}

	return 0;
}