
#include <haproxy/filters.h>
#include <haproxy/http_htx.h>
#include <haproxy/h1.h>

const char *http_rescap_flt_id = "response capture filter";

struct flt_ops rescap_ops;

struct rescap_state {
  char* response_data;
  int response_len;
};

DECLARE_STATIC_POOL(pool_head_rescap_state, "rescap_state", sizeof(struct rescap_state));

/***********************************************************************/
static int
rescap_strm_init(struct stream *s, struct filter *filter)
{
	struct rescap_state *st;

	st = pool_alloc(pool_head_rescap_state);
	if (st == NULL)
		return -1;

  st->response_data = NULL;
  st->response_len = 0;
#if 0
	st->comp_algo = NULL;
	st->comp_ctx  = NULL;
	st->flags     = 0;
	filter->ctx   = st;

	/* Register post-analyzer on AN_RES_WAIT_HTTP because we need to
	 * analyze response headers before http-response rules execution
	 * to be sure we can use res.comp and res.comp_algo sample
	 * fetches */
	filter->post_analyzers |= AN_RES_WAIT_HTTP;
#endif
	return 1;
}

static void
rescap_strm_deinit(struct stream *s, struct filter *filter)
{
	struct rescap_state *st = filter->ctx;

	if (!st)
		return;
  
  if (st->response_data)
    free(st->response_data);
	pool_free(pool_head_rescap_state, st);
	filter->ctx = NULL;
}

static int
rescap_http_headers(struct stream *s, struct filter *filter, struct http_msg *msg)
{
	struct rescap_state *st = filter->ctx;
  (void)st;

  if (msg->chn->flags & CF_ISRESP)
    return 1;

  struct htx* htx;
  struct ist hdr;
  struct http_hdr_ctx ctx;

  hdr = ist("Content-Length");
  if (!http_find_header(htx, hdr, &ctx, 0))
    return 1;

	struct h1m h1m;
  int ret;
	ret = h1_parse_cont_len_header(&h1m, &ctx.value);
  if (ret < 0)
    return 1;

  st->response_data = calloc(1, h1m.curr_len);
  st->response_len = h1m.curr_len;

	return 1;
}

static int
rescap_http_payload(struct stream *s, struct filter *filter, struct http_msg *msg,
		  unsigned int offset, unsigned int len)
{
	struct rescap_state *st = filter->ctx;
  (void)st;
  return 1;
}

static int
rescap_http_end(struct stream *s, struct filter *filter,
	      struct http_msg *msg)
{
	struct comp_state *st = filter->ctx;
  (void)st;
  return 1;
}

/***********************************************************************/
struct flt_ops rescap_ops = {
	/* .init              = comp_flt_init, */
	/* .init_per_thread   = comp_flt_init_per_thread, */
	/* .deinit_per_thread = comp_flt_deinit_per_thread, */

	.attach = rescap_strm_init,
	.detach = rescap_strm_deinit,

	/* .channel_post_analyze  = comp_http_post_analyze, */

	.http_headers          = rescap_http_headers,
	.http_payload          = rescap_http_payload,
	.http_end              = rescap_http_end,
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
