#include <ngx_http.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "lib/captcha.h"
#include "lib/hash.h"
#include "lib/cookie.h"


#define DEFAULT_SECRET  "changeme"
//define chars
#define CAPTCHA_CHARSET "abcdefghijmnpqrtvwxyzABCDEFGHIJLMNPQRTVWXYZ123456789#@%" 
//define font
#define CAPTCHA_FONT "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
//define number of chars
#define CAPTCHA_CHAR_LENGTH 6
//define number of line
#define CAPTCHA_NUMBER_OF_LINES 7


int get_cookie(ngx_http_request_t *, ngx_str_t *, ngx_str_t *);
static ngx_int_t set_captcha_cookie(ngx_http_request_t *, u_char* );
static ngx_int_t ngx_http_captcha(ngx_conf_t *);
static ngx_int_t ngx_http_captcha_handler(ngx_http_request_t *);
static void *ngx_http_captcha_create_loc_conf(ngx_conf_t *);
static char *ngx_http_captcha_merge_loc_conf(ngx_conf_t *, void *, void *);

#define SHA_LEN 128


typedef struct {
    ngx_flag_t enabled;
    ngx_uint_t bucket_duration;
    ngx_uint_t captcha_length;
    ngx_str_t  secret;
    ngx_str_t  captcha_font;
    ngx_str_t  captcha_charset;
} ngx_http_captcha_loc_conf_t;


static ngx_command_t ngx_http_captcha_commands[] = {
        {
                ngx_string("captcha"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_SIF_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_captcha_loc_conf_t, enabled),
                NULL
        },
        {
                ngx_string("captcha_bucket_duration"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_num_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_captcha_loc_conf_t, bucket_duration),
                NULL
        },
        {
                ngx_string("captcha_length"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_num_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_captcha_loc_conf_t, captcha_length),
                NULL
        },
        {
                ngx_string("captcha_secret"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_captcha_loc_conf_t, secret),
                NULL
        },
        {
                ngx_string("captcha_font"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_captcha_loc_conf_t, captcha_font),
                NULL
        },
        {
                ngx_string("captcha_charset"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_captcha_loc_conf_t, captcha_charset),
                NULL
        },
        ngx_null_command
};


static ngx_http_module_t ngx_http_captcha_module_ctx = {
        NULL,
        ngx_http_captcha,
        NULL,
        NULL,
        NULL,
        NULL,
        ngx_http_captcha_create_loc_conf,
        ngx_http_captcha_merge_loc_conf
};

ngx_module_t ngx_http_captcha_module = {
        NGX_MODULE_V1,
        &ngx_http_captcha_module_ctx,
        ngx_http_captcha_commands,
        NGX_HTTP_MODULE,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NGX_MODULE_V1_PADDING
};


static void *ngx_http_captcha_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_captcha_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_captcha_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->secret = (ngx_str_t) {0, NULL};
    conf->bucket_duration = NGX_CONF_UNSET_UINT;
    conf->captcha_length = NGX_CONF_UNSET_UINT;
    conf->enabled = NGX_CONF_UNSET;

    return conf;
}


static char *ngx_http_captcha_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_captcha_loc_conf_t *prev = parent;
    ngx_http_captcha_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->bucket_duration, prev->bucket_duration, 3600)
    ngx_conf_merge_uint_value(conf->captcha_length, prev->captcha_length, CAPTCHA_CHAR_LENGTH)
    ngx_conf_merge_value(conf->enabled, prev->enabled, 0)
    ngx_conf_merge_str_value(conf->secret, prev->secret, DEFAULT_SECRET)
    ngx_conf_merge_str_value(conf->captcha_font, prev->captcha_font, CAPTCHA_FONT)
    ngx_conf_merge_str_value(conf->captcha_charset, prev->captcha_charset, CAPTCHA_CHARSET)

    if (conf->bucket_duration < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bucket_duration must be equal or more than 1");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


//<!DOCTYPE html><meta name='viewport' content="initial-scale=1.0, width=device-width" /><html><head><style>	.center-screen { 		display: flex; justify-content: center; 		align-items: center;		text-align: center;		min-height: 100vh;	}	.button {  background-color: #4CAF50; /* Green */  border: none;  color: white;  padding: 4px 16px;  text-align: center;  text-decoration: none;  display: inline-block;  font-size: 16px;  margin: 4px 2px;  transition-duration: 0.4s;  cursor: pointer;}.button2 {  background-color: #008CBA;   color: black;   border: 2px solid #008CBA;}.button2:hover {  background-color: white;  color: black;}.loader {  border: 16px solid #f3f3f3;  border-radius: 50%;  border-top: 16px solid #3498db;  width: 120px;  height: 120px;  -webkit-animation: spin 2s linear infinite; /* Safari */  animation: spin 2s linear infinite;}/* Safari */@-webkit-keyframes spin {  0% { -webkit-transform: rotate(0deg); }  100% { -webkit-transform: rotate(360deg); }}@keyframes spin {  0% { transform: rotate(0deg); }  100% { transform: rotate(360deg); }}</style>  </head><body>	<div class="center-screen">			<div id="captcha_content"  style="mine-height: 50px"><img src="\captcha123" id="captchaimg" style="margin: 0px;"> <br>		<div style="margin: 0px;"><h2>Enter the code above here :</h2></div><br>		<input id="resp"><span onclick="updateImage()" style="cursor: pointer; margin-left: 10px;">&#x21bb;</span><br><button class="button button2" id="myBtn" onclick="updateResponse()" style="margin: 10px;"> Submit </button></div> 	<div class="center-screen" ><div class="loader" id="loader_content"  style="display: none"></div></div>	<script>			 	function updateResponse(){		document.cookie = 'resp='+document.getElementById('resp').value+'; path=/'; 				document.getElementById("captcha_content").style.display="none";		document.getElementById('loader_content').style.display='block'; 		setTimeout(function(){ 			window.location.reload(); 		}, 1000); 	} document.addEventListener('keypress', (event) => {	  if (event.code === 'Enter'){  	updateResponse();  }}, false);   function updateImage(){window.location.reload();}    </script>	</div></body></html>
//https://www.javascriptobfuscator.com/Javascript-Obfuscator.aspx -> javascript
//http://snapbuilder.com/code_snippet_generator/obfuscate_html_source_code/ ->html
int  serve_HTML(ngx_http_request_t *r) {
    unsigned char buf[] = {"<script language='javascript'>document.write(unescape('%3C%21%44%4F%43%54%59%50%45%20%68%74%6D%6C%3E%3C%6D%65%74%61%20%6E%61%6D%65%3D%27%76%69%65%77%70%6F%72%74%27%20%63%6F%6E%74%65%6E%74%3D%22%69%6E%69%74%69%61%6C%2D%73%63%61%6C%65%3D%31%2E%30%2C%20%77%69%64%74%68%3D%64%65%76%69%63%65%2D%77%69%64%74%68%22%20%2F%3E%3C%68%74%6D%6C%3E%3C%68%65%61%64%3E%3C%73%74%79%6C%65%3E%09%2E%63%65%6E%74%65%72%2D%73%63%72%65%65%6E%20%7B%20%09%09%64%69%73%70%6C%61%79%3A%20%66%6C%65%78%3B%20%6A%75%73%74%69%66%79%2D%63%6F%6E%74%65%6E%74%3A%20%63%65%6E%74%65%72%3B%20%09%09%61%6C%69%67%6E%2D%69%74%65%6D%73%3A%20%63%65%6E%74%65%72%3B%09%09%74%65%78%74%2D%61%6C%69%67%6E%3A%20%63%65%6E%74%65%72%3B%09%09%6D%69%6E%2D%68%65%69%67%68%74%3A%20%31%30%30%76%68%3B%09%7D%09%2E%62%75%74%74%6F%6E%20%7B%20%20%62%61%63%6B%67%72%6F%75%6E%64%2D%63%6F%6C%6F%72%3A%20%23%34%43%41%46%35%30%3B%20%2F%2A%20%47%72%65%65%6E%20%2A%2F%20%20%62%6F%72%64%65%72%3A%20%6E%6F%6E%65%3B%20%20%63%6F%6C%6F%72%3A%20%77%68%69%74%65%3B%20%20%70%61%64%64%69%6E%67%3A%20%34%70%78%20%31%36%70%78%3B%20%20%74%65%78%74%2D%61%6C%69%67%6E%3A%20%63%65%6E%74%65%72%3B%20%20%74%65%78%74%2D%64%65%63%6F%72%61%74%69%6F%6E%3A%20%6E%6F%6E%65%3B%20%20%64%69%73%70%6C%61%79%3A%20%69%6E%6C%69%6E%65%2D%62%6C%6F%63%6B%3B%20%20%66%6F%6E%74%2D%73%69%7A%65%3A%20%31%36%70%78%3B%20%20%6D%61%72%67%69%6E%3A%20%34%70%78%20%32%70%78%3B%20%20%74%72%61%6E%73%69%74%69%6F%6E%2D%64%75%72%61%74%69%6F%6E%3A%20%30%2E%34%73%3B%20%20%63%75%72%73%6F%72%3A%20%70%6F%69%6E%74%65%72%3B%7D%2E%62%75%74%74%6F%6E%32%20%7B%20%20%62%61%63%6B%67%72%6F%75%6E%64%2D%63%6F%6C%6F%72%3A%20%23%30%30%38%43%42%41%3B%20%20%20%63%6F%6C%6F%72%3A%20%62%6C%61%63%6B%3B%20%20%20%62%6F%72%64%65%72%3A%20%32%70%78%20%73%6F%6C%69%64%20%23%30%30%38%43%42%41%3B%7D%2E%62%75%74%74%6F%6E%32%3A%68%6F%76%65%72%20%7B%20%20%62%61%63%6B%67%72%6F%75%6E%64%2D%63%6F%6C%6F%72%3A%20%77%68%69%74%65%3B%20%20%63%6F%6C%6F%72%3A%20%62%6C%61%63%6B%3B%7D%2E%6C%6F%61%64%65%72%20%7B%20%20%62%6F%72%64%65%72%3A%20%31%36%70%78%20%73%6F%6C%69%64%20%23%66%33%66%33%66%33%3B%20%20%62%6F%72%64%65%72%2D%72%61%64%69%75%73%3A%20%35%30%25%3B%20%20%62%6F%72%64%65%72%2D%74%6F%70%3A%20%31%36%70%78%20%73%6F%6C%69%64%20%23%33%34%39%38%64%62%3B%20%20%77%69%64%74%68%3A%20%31%32%30%70%78%3B%20%20%68%65%69%67%68%74%3A%20%31%32%30%70%78%3B%20%20%2D%77%65%62%6B%69%74%2D%61%6E%69%6D%61%74%69%6F%6E%3A%20%73%70%69%6E%20%32%73%20%6C%69%6E%65%61%72%20%69%6E%66%69%6E%69%74%65%3B%20%2F%2A%20%53%61%66%61%72%69%20%2A%2F%20%20%61%6E%69%6D%61%74%69%6F%6E%3A%20%73%70%69%6E%20%32%73%20%6C%69%6E%65%61%72%20%69%6E%66%69%6E%69%74%65%3B%7D%2F%2A%20%53%61%66%61%72%69%20%2A%2F%40%2D%77%65%62%6B%69%74%2D%6B%65%79%66%72%61%6D%65%73%20%73%70%69%6E%20%7B%20%20%30%25%20%7B%20%2D%77%65%62%6B%69%74%2D%74%72%61%6E%73%66%6F%72%6D%3A%20%72%6F%74%61%74%65%28%30%64%65%67%29%3B%20%7D%20%20%31%30%30%25%20%7B%20%2D%77%65%62%6B%69%74%2D%74%72%61%6E%73%66%6F%72%6D%3A%20%72%6F%74%61%74%65%28%33%36%30%64%65%67%29%3B%20%7D%7D%40%6B%65%79%66%72%61%6D%65%73%20%73%70%69%6E%20%7B%20%20%30%25%20%7B%20%74%72%61%6E%73%66%6F%72%6D%3A%20%72%6F%74%61%74%65%28%30%64%65%67%29%3B%20%7D%20%20%31%30%30%25%20%7B%20%74%72%61%6E%73%66%6F%72%6D%3A%20%72%6F%74%61%74%65%28%33%36%30%64%65%67%29%3B%20%7D%7D%3C%2F%73%74%79%6C%65%3E%20%20%3C%2F%68%65%61%64%3E%3C%62%6F%64%79%3E%09%3C%64%69%76%20%63%6C%61%73%73%3D%22%63%65%6E%74%65%72%2D%73%63%72%65%65%6E%22%3E%09%09%09%3C%64%69%76%20%69%64%3D%22%63%61%70%74%63%68%61%5F%63%6F%6E%74%65%6E%74%22%20%20%73%74%79%6C%65%3D%22%6D%69%6E%65%2D%68%65%69%67%68%74%3A%20%35%30%70%78%22%3E%3C%69%6D%67%20%73%72%63%3D%22%5C%63%61%70%74%63%68%61%31%32%33%22%20%69%64%3D%22%63%61%70%74%63%68%61%69%6D%67%22%20%73%74%79%6C%65%3D%22%6D%61%72%67%69%6E%3A%20%30%70%78%3B%22%3E%20%3C%62%72%3E%09%09%3C%64%69%76%20%73%74%79%6C%65%3D%22%6D%61%72%67%69%6E%3A%20%30%70%78%3B%22%3E%3C%68%32%3E%45%6E%74%65%72%20%74%68%65%20%63%6F%64%65%20%61%62%6F%76%65%20%68%65%72%65%20%3A%3C%2F%68%32%3E%3C%2F%64%69%76%3E%3C%62%72%3E%09%09%3C%69%6E%70%75%74%20%69%64%3D%22%72%65%73%70%22%3E%3C%73%70%61%6E%20%6F%6E%63%6C%69%63%6B%3D%22%75%70%64%61%74%65%49%6D%61%67%65%28%29%22%20%73%74%79%6C%65%3D%22%63%75%72%73%6F%72%3A%20%70%6F%69%6E%74%65%72%3B%20%6D%61%72%67%69%6E%2D%6C%65%66%74%3A%20%31%30%70%78%3B%22%3E%26%23%78%32%31%62%62%3B%3C%2F%73%70%61%6E%3E%3C%62%72%3E%3C%62%75%74%74%6F%6E%20%63%6C%61%73%73%3D%22%62%75%74%74%6F%6E%20%62%75%74%74%6F%6E%32%22%20%69%64%3D%22%6D%79%42%74%6E%22%20%6F%6E%63%6C%69%63%6B%3D%22%75%70%64%61%74%65%52%65%73%70%6F%6E%73%65%28%29%22%20%73%74%79%6C%65%3D%22%6D%61%72%67%69%6E%3A%20%31%30%70%78%3B%22%3E%20%53%75%62%6D%69%74%20%3C%2F%62%75%74%74%6F%6E%3E%3C%2F%64%69%76%3E%20%09%3C%64%69%76%20%63%6C%61%73%73%3D%22%63%65%6E%74%65%72%2D%73%63%72%65%65%6E%22%20%3E%3C%64%69%76%20%63%6C%61%73%73%3D%22%6C%6F%61%64%65%72%22%20%69%64%3D%22%6C%6F%61%64%65%72%5F%63%6F%6E%74%65%6E%74%22%20%20%73%74%79%6C%65%3D%22%64%69%73%70%6C%61%79%3A%20%6E%6F%6E%65%22%3E%3C%2F%64%69%76%3E%3C%2F%64%69%76%3E%09%3C%73%63%72%69%70%74%3E%09%09%76%61%72%20%5F%30%78%32%39%65%64%30%34%3D%5F%30%78%32%32%30%38%3B%28%66%75%6E%63%74%69%6F%6E%28%5F%30%78%33%62%36%32%62%30%2C%5F%30%78%34%61%37%36%66%62%29%7B%76%61%72%20%5F%30%78%33%66%63%31%65%31%3D%5F%30%78%32%32%30%38%2C%5F%30%78%35%63%32%33%39%31%3D%5F%30%78%33%62%36%32%62%30%28%29%3B%77%68%69%6C%65%28%21%21%5B%5D%29%7B%74%72%79%7B%76%61%72%20%5F%30%78%37%61%37%66%37%64%3D%2D%70%61%72%73%65%49%6E%74%28%5F%30%78%33%66%63%31%65%31%28%30%78%38%62%29%29%2F%30%78%31%2A%28%70%61%72%73%65%49%6E%74%28%5F%30%78%33%66%63%31%65%31%28%30%78%39%61%29%29%2F%30%78%32%29%2B%2D%70%61%72%73%65%49%6E%74%28%5F%30%78%33%66%63%31%65%31%28%30%78%38%38%29%29%2F%30%78%33%2B%70%61%72%73%65%49%6E%74%28%5F%30%78%33%66%63%31%65%31%28%30%78%39%62%29%29%2F%30%78%34%2B%2D%70%61%72%73%65%49%6E%74%28%5F%30%78%33%66%63%31%65%31%28%30%78%39%35%29%29%2F%30%78%35%2A%28%2D%70%61%72%73%65%49%6E%74%28%5F%30%78%33%66%63%31%65%31%28%30%78%39%66%29%29%2F%30%78%36%29%2B%2D%70%61%72%73%65%49%6E%74%28%5F%30%78%33%66%63%31%65%31%28%30%78%39%33%29%29%2F%30%78%37%2B%2D%70%61%72%73%65%49%6E%74%28%5F%30%78%33%66%63%31%65%31%28%30%78%38%61%29%29%2F%30%78%38%2B%70%61%72%73%65%49%6E%74%28%5F%30%78%33%66%63%31%65%31%28%30%78%38%39%29%29%2F%30%78%39%3B%69%66%28%5F%30%78%37%61%37%66%37%64%3D%3D%3D%5F%30%78%34%61%37%36%66%62%29%62%72%65%61%6B%3B%65%6C%73%65%20%5F%30%78%35%63%32%33%39%31%5B%27%70%75%73%68%27%5D%28%5F%30%78%35%63%32%33%39%31%5B%27%73%68%69%66%74%27%5D%28%29%29%3B%7D%63%61%74%63%68%28%5F%30%78%31%33%62%32%39%35%29%7B%5F%30%78%35%63%32%33%39%31%5B%27%70%75%73%68%27%5D%28%5F%30%78%35%63%32%33%39%31%5B%27%73%68%69%66%74%27%5D%28%29%29%3B%7D%7D%7D%28%5F%30%78%31%35%64%66%2C%30%78%65%36%30%66%63%29%29%3B%66%75%6E%63%74%69%6F%6E%20%5F%30%78%32%32%30%38%28%5F%30%78%31%39%34%62%30%37%2C%5F%30%78%31%65%62%35%35%38%29%7B%76%61%72%20%5F%30%78%31%35%64%66%65%36%3D%5F%30%78%31%35%64%66%28%29%3B%72%65%74%75%72%6E%20%5F%30%78%32%32%30%38%3D%66%75%6E%63%74%69%6F%6E%28%5F%30%78%32%32%30%38%31%32%2C%5F%30%78%31%37%66%61%38%36%29%7B%5F%30%78%32%32%30%38%31%32%3D%5F%30%78%32%32%30%38%31%32%2D%30%78%38%38%3B%76%61%72%20%5F%30%78%31%66%64%36%35%37%3D%5F%30%78%31%35%64%66%65%36%5B%5F%30%78%32%32%30%38%31%32%5D%3B%72%65%74%75%72%6E%20%5F%30%78%31%66%64%36%35%37%3B%7D%2C%5F%30%78%32%32%30%38%28%5F%30%78%31%39%34%62%30%37%2C%5F%30%78%31%65%62%35%35%38%29%3B%7D%66%75%6E%63%74%69%6F%6E%20%5F%30%78%31%35%64%66%28%29%7B%76%61%72%20%5F%30%78%33%63%39%65%30%35%3D%5B%27%6C%6F%63%61%74%69%6F%6E%27%2C%27%32%32%35%39%32%30%38%64%73%63%50%77%59%27%2C%27%76%61%6C%75%65%27%2C%27%31%30%69%44%6F%56%62%53%27%2C%27%3B%5C%78%32%30%70%61%74%68%3D%2F%27%2C%27%63%61%70%74%63%68%61%5F%63%6F%6E%74%65%6E%74%27%2C%27%6B%65%79%70%72%65%73%73%27%2C%27%61%64%64%45%76%65%6E%74%4C%69%73%74%65%6E%65%72%27%2C%27%31%31%32%38%37%34%6C%61%47%61%6A%77%27%2C%27%31%35%37%39%32%34%34%72%76%71%62%58%52%27%2C%27%72%65%73%70%3D%27%2C%27%64%69%73%70%6C%61%79%27%2C%27%45%6E%74%65%72%27%2C%27%32%31%36%33%37%32%30%61%74%64%66%5A%6F%27%2C%27%31%34%39%38%36%30%38%63%53%42%5A%53%69%27%2C%27%32%35%37%33%31%39%31%38%53%79%78%74%57%6A%27%2C%27%31%33%36%32%30%38%36%34%43%62%62%43%6E%6B%27%2C%27%39%69%74%57%6E%48%69%27%2C%27%62%6C%6F%63%6B%27%2C%27%73%74%79%6C%65%27%2C%27%67%65%74%45%6C%65%6D%65%6E%74%42%79%49%64%27%2C%27%72%65%6C%6F%61%64%27%2C%27%63%6F%6F%6B%69%65%27%2C%27%63%6F%64%65%27%5D%3B%5F%30%78%31%35%64%66%3D%66%75%6E%63%74%69%6F%6E%28%29%7B%72%65%74%75%72%6E%20%5F%30%78%33%63%39%65%30%35%3B%7D%3B%72%65%74%75%72%6E%20%5F%30%78%31%35%64%66%28%29%3B%7D%66%75%6E%63%74%69%6F%6E%20%75%70%64%61%74%65%52%65%73%70%6F%6E%73%65%28%29%7B%76%61%72%20%5F%30%78%33%63%61%39%64%65%3D%5F%30%78%32%32%30%38%3B%64%6F%63%75%6D%65%6E%74%5B%5F%30%78%33%63%61%39%64%65%28%30%78%39%30%29%5D%3D%5F%30%78%33%63%61%39%64%65%28%30%78%39%63%29%2B%64%6F%63%75%6D%65%6E%74%5B%5F%30%78%33%63%61%39%64%65%28%30%78%38%65%29%5D%28%27%72%65%73%70%27%29%5B%5F%30%78%33%63%61%39%64%65%28%30%78%39%34%29%5D%2B%5F%30%78%33%63%61%39%64%65%28%30%78%39%36%29%2C%64%6F%63%75%6D%65%6E%74%5B%5F%30%78%33%63%61%39%64%65%28%30%78%38%65%29%5D%28%5F%30%78%33%63%61%39%64%65%28%30%78%39%37%29%29%5B%27%73%74%79%6C%65%27%5D%5B%5F%30%78%33%63%61%39%64%65%28%30%78%39%64%29%5D%3D%27%6E%6F%6E%65%27%2C%64%6F%63%75%6D%65%6E%74%5B%27%67%65%74%45%6C%65%6D%65%6E%74%42%79%49%64%27%5D%28%27%6C%6F%61%64%65%72%5F%63%6F%6E%74%65%6E%74%27%29%5B%5F%30%78%33%63%61%39%64%65%28%30%78%38%64%29%5D%5B%5F%30%78%33%63%61%39%64%65%28%30%78%39%64%29%5D%3D%5F%30%78%33%63%61%39%64%65%28%30%78%38%63%29%2C%73%65%74%54%69%6D%65%6F%75%74%28%66%75%6E%63%74%69%6F%6E%28%29%7B%77%69%6E%64%6F%77%5B%27%6C%6F%63%61%74%69%6F%6E%27%5D%5B%27%72%65%6C%6F%61%64%27%5D%28%29%3B%7D%2C%30%78%33%65%38%29%3B%7D%64%6F%63%75%6D%65%6E%74%5B%5F%30%78%32%39%65%64%30%34%28%30%78%39%39%29%5D%28%5F%30%78%32%39%65%64%30%34%28%30%78%39%38%29%2C%5F%30%78%33%36%30%36%30%31%3D%3E%7B%76%61%72%20%5F%30%78%32%34%30%34%64%62%3D%5F%30%78%32%39%65%64%30%34%3B%5F%30%78%33%36%30%36%30%31%5B%5F%30%78%32%34%30%34%64%62%28%30%78%39%31%29%5D%3D%3D%3D%5F%30%78%32%34%30%34%64%62%28%30%78%39%65%29%26%26%75%70%64%61%74%65%52%65%73%70%6F%6E%73%65%28%29%3B%7D%2C%21%5B%5D%29%3B%66%75%6E%63%74%69%6F%6E%20%75%70%64%61%74%65%49%6D%61%67%65%28%29%7B%76%61%72%20%5F%30%78%35%33%33%65%35%37%3D%5F%30%78%32%39%65%64%30%34%3B%77%69%6E%64%6F%77%5B%5F%30%78%35%33%33%65%35%37%28%30%78%39%32%29%5D%5B%5F%30%78%35%33%33%65%35%37%28%30%78%38%66%29%5D%28%29%3B%7D%20%3C%2F%73%63%72%69%70%74%3E%09%3C%2F%64%69%76%3E%3C%2F%62%6F%64%79%3E%3C%2F%68%74%6D%6C%3E%0A'));</script>"};
    
    size_t sz = strlen((char *)buf);
    static const ngx_str_t content_type = ngx_string("text/html;charset=utf-8;");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = sz;
   
    r->headers_out.content_type = content_type;
    ngx_http_send_header(r);

    ngx_buf_t    *b;
    ngx_chain_t   out;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    out.buf = b;
    out.next = NULL;

    b->pos = buf;
    b->last = buf + sz;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, 0);
    
    return NGX_DONE;
}




/**
* serve captcha image
ex:
HTTP/1.1 200 OK\r\n
Content-Type: image/png\r\n
Content-Length: [length in bytes of the image]\r\n
Set-Cookie: [hash(captcha)]\r\n
\r\n
[binary data of your image]
*/
int serve_captcha(ngx_http_request_t *r, ngx_http_captcha_loc_conf_t *conf){
    //create captcha
    struct Captcha *captcha=create(
            conf->captcha_length, CAPTCHA_NUMBER_OF_LINES, CHAR_PIXEL_LENGTH, 
            (char *)conf->captcha_charset.data, (char *)conf->captcha_font.data
    );
    generate_captcha(captcha);
    get_binary(captcha);
    
    static const ngx_str_t content_type = ngx_string("image/png;");

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = captcha->size;
    r->headers_out.content_type = content_type;
    
    unsigned long bucket = r->start_sec - (r->start_sec % conf->bucket_duration);
    int bucket_size = 0;
    for (unsigned long i=1; i<bucket; i*=10){
        bucket_size++;
    }
	unsigned* input=malloc( sizeof(char) * (conf->secret.len +r->connection->addr_text.len+conf->captcha_length + bucket_size +2  )  );
    snprintf( 
            (char *)input, 
            ( conf->secret.len +r->connection->addr_text.len+conf->captcha_length + bucket_size +1  ),
            "%s%s%lu%s",
             conf->secret.data, r->connection->addr_text.data, bucket,  captcha->message 
            );
    unsigned char output_sha512[64];
    mySHA512((unsigned char *)input,output_sha512 );
	
    
	unsigned char output_sha512_hex[129];
    buf2hex(output_sha512, 64, output_sha512_hex);
	output_sha512_hex[128]='\0';

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ CAPTCHA code] , OUTPUT2 =%s ff\n", (char *)input);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ CAPTCHA code] , HASH2 =%s ff\n", (char *)output_sha512_hex);
    free(input);
    set_captcha_cookie(r,(u_char*)output_sha512_hex);
    ngx_http_send_header(r);

    ngx_buf_t    *b;
    ngx_chain_t   out;
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    out.buf = b;
    out.next = NULL;

    b->pos = captcha->buf;
    b->last = captcha->buf + captcha->size;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, 0);
    destroy_captcha(captcha);   //destroy captcha
    return NGX_DONE;
}



static ngx_int_t ngx_http_captcha_handler(ngx_http_request_t *r) {

    ngx_http_captcha_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);

    if (!conf->enabled) {
        return NGX_DECLINED;
    }

    //captcha image
    //to do: generate dynamic link for image
    if ( strncmp((char *)r->uri.data,"/captcha123",11) == 0){
        return serve_captcha(r, conf);
    }

    //get cookies
    ngx_str_t captcha_code;
    ngx_str_t cookie_name = ngx_string("captcha_code");
    int ret = get_cookie(r, &cookie_name, &captcha_code);

    ngx_str_t resp;
    ngx_str_t cookie_name2 = ngx_string("resp");
    int ret2 = get_cookie(r, &cookie_name2, &resp);

    if (ret < 0 || ret2 <0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ CAPTCHA code] , captcha_code/resp is not set");
        return  serve_HTML(r);
    }

    if (captcha_code.len != 128 || resp.len != conf->captcha_length ){
        return serve_HTML(r);
    }
    
	/**
    create input string ( secret + IP + time +resp cookie )
    */
    unsigned long bucket = r->start_sec - (r->start_sec % conf->bucket_duration);
    int bucket_size = 0;
    for (unsigned long i=1; i<bucket; i*=10){
        bucket_size++;
    }
	unsigned* input=malloc( sizeof(char) * (conf->secret.len +r->connection->addr_text.len+resp.len + bucket_size +2  )  );
    snprintf( 
            (char *)input, 
            ( conf->secret.len +r->connection->addr_text.len+resp.len + bucket_size +1  ),
            "%s%s%lu%s",
             conf->secret.data, r->connection->addr_text.data, bucket,  resp.data 
            );

    unsigned char output_sha512[64];
    mySHA512((unsigned char *)input,output_sha512 );
	
	unsigned char output_sha512_hex[129];
    buf2hex(output_sha512, 64, output_sha512_hex);
	output_sha512_hex[128]='\0';

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ CAPTCHA code] , input=%s ff\n", input);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ CAPTCHA code] , response_len=%d ff\n", resp.len);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ CAPTCHA code] , capctcha_code=%d ff\n", captcha_code.len);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ CAPTCHA code] , sha512=%s ff\n", output_sha512_hex);

    free(input);
    
    if (strncmp( (char *)captcha_code.data, (char *)output_sha512_hex , SHA_LEN ) != 0){
        return  serve_HTML(r);
    }

    return NGX_DECLINED;
}




static ngx_int_t ngx_http_captcha(ngx_conf_t *cf) {

    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&main_conf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "null");
        return NGX_ERROR;
    }
    *h = ngx_http_captcha_handler;
    return NGX_OK;
}

