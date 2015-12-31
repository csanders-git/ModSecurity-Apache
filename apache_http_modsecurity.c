/* Include the required headers from httpd */
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"

#include <modsecurity/modsecurity.h>
#include <modsecurity/assay.h>
#include <modsecurity/rules.h>
#include <modsecurity/intervention.h>

/* Define prototypes of our functions in this module */
static void register_hooks(apr_pool_t *pool);
static int example_handler(request_rec *r);

module AP_MODULE_DECLARE_DATA   security3_module =
{ 
    STANDARD20_MODULE_STUFF,
    NULL, /* Per-directory configuration handler */
    NULL,  /* Merge handler for per-directory configurations */
    NULL, /* Per-server configuration handler */
    NULL,  /* Merge handler for per-server configurations */
    NULL,      /* Any directives we may have for httpd */
    register_hooks   /* Our hook registering function */
};

static int addRequestHeader(void* rec, const char* key, const char* value) {
    Assay* assay = rec;
    msc_add_request_header(assay,(unsigned char*)key,(unsigned char *)value);
    return 1;
}

static int addResponseHeader(void* rec, const char* key, const char* value) {
    Assay* assay = rec;
    msc_add_response_header(assay,(unsigned char*)key,(unsigned char *)value);
    return 1;
}

static void register_hooks(apr_pool_t *pool)
{
    /* Create a hook in the request handler, so we get called when a request arrives */
    ap_hook_handler(example_handler, NULL, NULL, APR_HOOK_LAST);
}

static int example_handler(request_rec *r)
{
    const char *error = NULL;
    ModSecurity *modsec = msc_init();
    msc_set_connector_info(modsec, "ModSecurity-apache v0.0.1-alpha");
    Rules *rules_set = msc_create_rules_set();
    if(msc_rules_add_file(rules_set, "/opt/newer/ModSecurityNew/examples/simple_example_using_c/basic_rules.conf", &error) < 0){
        printf("Error: Issues loading the rules: %s", error);
    }

    msc_rules_dump(rules_set);
    Assay * assay = msc_new_assay(modsec,rules_set, NULL);
    char *local_addr = r->connection->local_ip;
    int local_port = r->connection->local_addr->port; 
    char *remote_addr = r->connection->client_ip;
    int remote_port = r->connection->client_addr->port; 
    msc_process_connection(assay,local_addr,local_port,remote_addr,remote_port);
    msc_process_uri(assay, r->uri,r->method,"1.1");

    if (!r->handler || strcmp(r->handler, "example-handler")) return (DECLINED);
    

    ap_set_content_type(r, "text/html");
    apr_table_do(addRequestHeader, assay, r->headers_in,NULL);
    apr_table_do(addResponseHeader, assay, r->headers_out,NULL);

    ap_rprintf(r, "Hello, world! %s", r->connection->client_ip);
    ap_rprintf(r, "Hello, world! %s", r->method);
    

    return OK;
}
