#include <stdio.h>

#include <haproxy/filters.h>
#include <haproxy/http_htx.h>
#include <haproxy/h1.h>

const char *http_rescap_flt_id = "response capture filter";

struct flt_ops rescap_ops;

struct rescap_state {
  char* response_data;
  int offset;
  int response_len;
};

DECLARE_STATIC_POOL(pool_head_rescap_state, "rescap_state", sizeof(struct rescap_state));

/***********************************************************************/
static void copy_data(struct rescap_state* st, void* data, int len) {
  int n = st->response_len - st->offset;
  if (len < n) {
    n = len;
  }
  char* out = st->response_data + st->offset;
  memcpy(out, data, n);
  st->offset += n;
}

static int
rescap_flt_init(struct proxy *px, struct flt_conf *fconf)
{
	fconf->flags |= FLT_CFG_FL_HTX;
	return 0;
}

static int
rescap_strm_init(struct stream *s, struct filter *filter)
{
  printf("nuf\n");
	struct rescap_state *st;

	st = pool_alloc(pool_head_rescap_state);
	if (st == NULL)
		return -1;

  st->response_data = NULL;
  st->offset = 0;
  st->response_len = 0;

  filter->ctx = st;
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
  printf("arf\n");
	struct rescap_state *st = filter->ctx;
  (void)st;

  if (!(msg->chn->flags & CF_ISRESP))
    return 1;

	struct htx *htx = htxbuf(&msg->chn->buf);
  struct ist hdr;
  struct http_hdr_ctx ctx;
  
  printf("finding header\n");
  hdr = ist("Content-Length");
  ctx.blk = NULL;
  if (!http_find_header(htx, hdr, &ctx, 0))
    return 1;

  printf("content-length found\n");
	struct h1m h1m;
	h1m_init_res(&h1m);
  int ret;
	ret = h1_parse_cont_len_header(&h1m, &ctx.value);
  printf("parse cont_len rcode=%d\n", ret);
  if (ret < 0)
    return 1;

  printf("content-length: %llu\n", h1m.curr_len);
  st->response_data = calloc(1, h1m.curr_len);
  st->response_len = h1m.curr_len;
  printf("nuf\n");

  register_data_filter(s, msg->chn, filter);

	return 1;
}

static int
rescap_http_payload(struct stream *s, struct filter *filter, struct http_msg *msg,
		  unsigned int offset, unsigned int len)
{
	struct rescap_state *st = filter->ctx;
  if (!(msg->chn->flags & CF_ISRESP))
    return 1;
  struct htx *htx = htxbuf(&msg->chn->buf);
  struct htx_ret htxret = htx_find_offset(htx, offset);

  struct htx_blk *blk;
  blk = htxret.blk;
	offset = htxret.ret;
  for (; blk; blk = htx_get_next_blk(htx, blk)) {
    enum htx_blk_type type = htx_get_blk_type(blk);
    if (type == HTX_BLK_UNUSED)
      continue;
    else if (type == HTX_BLK_DATA) {
		    struct ist v;
				v = htx_get_blk_value(htx, blk);
				v = istadv(v, offset);
				if (v.len > len) {
					v.len = len;
				}
        copy_data(st, v.ptr, (int)v.len);
    }
    else
      break;
  }
  (void)st;
  printf("woof: %u %u\n", offset, len);
  return len;
}

static int
rescap_http_end(struct stream *s, struct filter *filter,
	      struct http_msg *msg)
{
	struct rescap_state *st = filter->ctx;
  (void)st;
  printf("http-end\n");
  printf("data: %.*s\n", st->offset, st->response_data);
  return 1;
}

/***********************************************************************/
struct flt_ops rescap_ops = {
	.init              = rescap_flt_init,
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
  printf("hrrrr\n");
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
