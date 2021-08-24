#include <haproxy/filters.h>
#include <haproxy/h1.h>
#include <haproxy/http_htx.h>
#include <haproxy/sample.h>
#include <haproxy/vars.h>
#include <stdio.h>

const char *http_rescap_flt_id = "response capture filter";

struct flt_ops rescap_ops;

struct rescap_state {
  char* response_data;
  int size;
  int content_length;
};

DECLARE_STATIC_POOL(pool_head_rescap_state, "rescap_state", sizeof(struct rescap_state));

/***********************************************************************/
static void copy_data(struct rescap_state* st, void* data, int len) {
  int n = st->content_length - st->size;
  if (len < n) {
    n = len;
  }
  char* out = st->response_data + st->size;
  memcpy(out, data, n);
  st->size += n;
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
  st->size = 0;
  st->content_length = 0;

  filter->ctx = st;

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

  if (!(msg->chn->flags & CF_ISRESP))
    return 1;

	struct htx *htx = htxbuf(&msg->chn->buf);
  struct ist hdr;
  struct http_hdr_ctx ctx;
  
  hdr = ist("Content-Length");
  ctx.blk = NULL;
  if (!http_find_header(htx, hdr, &ctx, 0))
    return 1;

	struct h1m h1m;
	h1m_init_res(&h1m);
  int ret;
	ret = h1_parse_cont_len_header(&h1m, &ctx.value);
  if (ret < 0)
    return 1;

  // Allocate a buffer to hold the captured response and
  // configure the filter to intercept the response data
  printf("rescap content-length: %llu\n", h1m.curr_len);
  st->response_data = calloc(1, h1m.curr_len);
  st->content_length = h1m.curr_len;

  register_data_filter(s, msg->chn, filter);

	return 1;
}

static int
rescap_http_payload(struct stream *s, struct filter *filter, struct http_msg *msg,
		  unsigned int offset, unsigned int len)
{
	struct rescap_state *st = filter->ctx;
  if (!(msg->chn->flags & CF_ISRESP))
    return len;
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
  return len;
}

static int
rescap_http_end(struct stream *s, struct filter *filter,
	      struct http_msg *msg)
{
  // At this point, we will have buffered the full response.
  // Now, we need to forward it to our agent. Ideally, we would do 
  // this by reusing haproxy's internal APIs similar to what
  // https://github.com/haproxytech/haproxy-lua-http
  // does. 
  //
  // For now, we'll just print out the buffer to verify that it's 
  // captured.
	struct rescap_state *st = filter->ctx;
  printf("rescap data: %.*s\n", st->size, st->response_data);

  return 1;
}

/***********************************************************************/
struct flt_ops rescap_ops = {
	.init              = rescap_flt_init,
	/* .init_per_thread   = comp_flt_init_per_thread, */
	/* .deinit_per_thread = comp_flt_deinit_per_thread, */

	.attach = rescap_strm_init,
	.detach = rescap_strm_deinit,


	.http_headers          = rescap_http_headers,
	.http_payload          = rescap_http_payload,
	.http_end              = rescap_http_end,
};

static int
parse_http_rescap_flt(char **args, int *cur_arg, struct proxy *px,
                    struct flt_conf *fconf, char **err, void *private)
{
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
