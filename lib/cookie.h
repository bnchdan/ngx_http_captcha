
#define CAPTCHA_COOKIE_NAME "captcha_code"
#define COOKIE_LEN 128


typedef struct _ngx_captcha_cookie{
    ngx_str_t path;
    ngx_str_t domain;
    ngx_str_t expire;
    ngx_str_t name;
    ngx_str_t value;
} ngx_captcha_cookie;

static ngx_captcha_cookie * generate_captcha_cookie(ngx_http_request_t *req, u_char* captcha_code)
{
    u_char * value;
    size_t value_len;
    u_char * expire, *p;
    size_t expire_len;
    size_t exp_len;
 
    ngx_captcha_cookie * captcha_cookie;

    captcha_cookie = (ngx_captcha_cookie *)ngx_pcalloc(req->pool, sizeof(ngx_captcha_cookie));//alloc 1

    value = captcha_code;
    value_len = COOKIE_LEN; //to do modify size
    
    exp_len = ngx_strlen("; expires=");
    expire = (u_char *)ngx_pcalloc(req->pool, exp_len+40);//alloc 2
    p = expire;
    p = ngx_copy(p, "; expires=", exp_len);
    p = ngx_http_cookie_time(p, ngx_time()+ 8*3600 );
    expire_len = ngx_strlen((const char *)expire);

    captcha_cookie->name.data = (u_char *)CAPTCHA_COOKIE_NAME;
    captcha_cookie->name.len = strlen(CAPTCHA_COOKIE_NAME);
    captcha_cookie->value.data = value;
    captcha_cookie->value.len = value_len;
    captcha_cookie->expire.data = expire;
    captcha_cookie->expire.len = expire_len;
    captcha_cookie->path.data = (u_char *)"; path=/;";
    captcha_cookie->path.len = ngx_strlen("; path=/;");

    return captcha_cookie;
}



/**
* set cookie to header
*/
static ngx_int_t set_captcha_cookie(ngx_http_request_t *req, u_char* captcha_code)
{
    u_char           *cookie, *p;
    size_t           len;
    ngx_table_elt_t  *set_cookie;

    ngx_captcha_cookie * captcha_cookie = generate_captcha_cookie(req, captcha_code);

    len = captcha_cookie->name.len+1+captcha_cookie->value.len;

    if (captcha_cookie->expire.len) {
        len += captcha_cookie->expire.len;
    }

    if (captcha_cookie->path.len) {
        len += captcha_cookie->path.len;
    }

    cookie = ngx_pnalloc(req->pool, len);                   //alloc 3

    if (cookie == NULL) {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,"cookie ngx_pnalloc error length[%d]",len);
        return NGX_ERROR;
    }

    p = ngx_copy(cookie, captcha_cookie->name.data, captcha_cookie->name.len);
    *p++ = '=';
    p = ngx_copy(p, captcha_cookie->value.data, captcha_cookie->value.len);
    
    if (captcha_cookie->expire.len) {
        p = ngx_copy(p, captcha_cookie->expire.data, captcha_cookie->expire.len);
    }

    if (captcha_cookie->path.len) {
        p = ngx_copy(p, captcha_cookie->path.data, captcha_cookie->path.len);
    }

    
    ngx_pfree(req->pool, captcha_cookie->expire.data);      //free 2
    ngx_pfree(req->pool, captcha_cookie);                   //free 1

    set_cookie = ngx_list_push(&req->headers_out.headers);
    if (set_cookie == NULL) {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,"set_cookie ngx_list_push error cookie[%s]", cookie);
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;


    ngx_pfree(req->pool, cookie);                             //free 3

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,"captcha cookie: \"%V\"", &set_cookie->value);


    return NGX_OK;
}



/**
* get cookie from header
*/
int get_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value) {
#if defined(nginx_version) && nginx_version >= 1023000
    ngx_table_elt_t *h;
    for (h = r->headers_in.cookie; h; h = h->next) {
        u_char *start = h->value.data;
        u_char *end = h->value.data + h->value.len;
        // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ HEADERS ] > %s < ",h->value.data );
#else
    ngx_table_elt_t **h;
    h = r->headers_in.cookies.elts;
    ngx_uint_t i = 0;
    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        u_char *start = h[i]->value.data;
        u_char *end = h[i]->value.data + h[i]->value.len;
        // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ HEADERS ] > %s < ",h[i]->value.data );
#endif
        while (start < end) {
            while (start < end && *start == ' ') { start++; }
            //get cookie
            if (ngx_strncmp(start, name->data, name->len) == 0) {
                u_char *last;
                for (last = start; last < end && *last != ';'; last++) {   
                    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ %c ]  ",*last );
                   }
                while (*start++ != '=' && start < last) {}

                value->data = start;
                value->len = (last - start);

                // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ %d - %d]  ",last, start );
                return 0;
            }
            while (*start++ != ';' && start < end) {}
        }
    }

    return -1;
}

