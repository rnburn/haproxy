
#include <haproxy/filters.h>

const char *http_rescap_flt_id = "response capture filter";

struct flt_ops rescap_ops;

/***********************************************************************/
struct flt_ops rescap_ops = {
	/* .init              = comp_flt_init, */
	/* .init_per_thread   = comp_flt_init_per_thread, */
	/* .deinit_per_thread = comp_flt_deinit_per_thread, */

	/* .attach = comp_strm_init, */
	/* .detach = comp_strm_deinit, */

	/* .channel_post_analyze  = comp_http_post_analyze, */

	/* .http_headers          = comp_http_headers, */
	/* .http_payload          = comp_http_payload, */
	/* .http_end              = comp_http_end, */
};

static int
parse_http_rescap_flt(char **args, int *cur_arg, struct proxy *px,
                    struct flt_conf *fconf, char **err, void *private)
{
	/* struct flt_conf *fc, *back; */

	/* list_for_each_entry_safe(fc, back, &px->filter_configs, list) { */
	/* 	if (fc->id == http_comp_flt_id) { */
	/* 		memprintf(err, "%s: Proxy supports only one compression filter\n", px->id); */
	/* 		return -1; */
	/* 	} */
	/* } */

	fconf->id   = http_rescap_flt_id;
	fconf->conf = NULL;
	fconf->ops  = &rescap_ops;
	(*cur_arg)++;

	return 0;
}

/* Declare the filter parser for "compression" keyword */
static struct flt_kw_list filter_kws = { "RESCAP", { }, {
		{ "rescap", parse_http_rescap_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, flt_register_keywords, &filter_kws);
