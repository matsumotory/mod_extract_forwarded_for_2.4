/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

/*
 * Apache 2 compatible mod_extract_forwarded
 *
 * Introduction
 * ------------
 * This module is based on version 1.4 of mod_extract_forwarded.c published
 * for use with Apache 1.3 by Adrian Hosey <alh@warhound.org>  and obtained
 * from http://web.warhound.org/mod_extract_forwarded/
 * The source has been substantially rewritten for this Apache 2 version but
 * the primary capability provided is the same. Main differences are:
 *
 * 1. Changes to accommodate use of IPv4-mapped IPv6 addresses per RFC2373
 *    and RFC 2553 as well a IPv4 addresses.
 * 2. Accommodate the difference between Apache 1.3 and Apache 2 APIs
 * 3. Added handler to reverse the changes to the conn_rec if mod_proxy is
 *    going to add/extend the X-Forwarded-For request header because it
 *    judges the request is to be treated as a reverse proxying activity
 * 4. Removed functionality provided by the AllowForwarderCaching directive
 *    because that is really a content handler issue
 * 5. Changed from AddAcceptForwarder and RemoveAcceptForwarder directives
 *    to MEForder, MEFaccept and MEFrefuse directives, which operate a little
 *    like mod_access' allow/deny/order directives. MEF directives are
 *    for use only in the default server config and VirtualHost containers;
 *    which makes sense as no directory context is available at post read
 *    request/pre URI translation time
 * 6. Added MEFaddenv directive to control addition and name of an envrionment
 *    variable if spoofing is done
 * 7. Added MEFdebug directive to log to the Apache 2 error_log the fine detail
 *    of what is done by the module as an aid to understanding fixing problems
 *    with this code; this is NOT for production use because of the volume of
 *    output it will generate and the way it flushes stderr
 *
 * History of Apache 2 compatible mod_extract_forwarded
 * ----------------------------------------------------
 *
 * Version      Date            Notes
 * -------      ----            -----
 * 2.0          9 Feb 2004      Initial conversion to Apache 2 by
 *                              Richard Barrett <R.Barrett@openinfo.co.uk>
 * 2.0.1        2 Mar 2004      Minor cosmetic changes to comments and such
 * 2.0.2        4 Mar 2004      Changed working but sub-optimal pool use in
 *                              command handling
 *                              Cleaned up interpretation of per_der_config
 *                              for internal redirect and subrequests and
 *                              other logic tidying
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"
#include "mod_proxy.h"
#include "apr_strings.h"

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/*
 * #define USING_proxy_http_module if proxy_http.c module is either
 * compiled into Apache 2 or it is being loaded as a DSO. If proxy_http.c
 * module is not loaded then this module will generate an error when and
 * if it is loaded as a DSO. In that case comment out the #define, recompile
 * and reinstall this module. BUT do not forget to change things back if
 * proxy_http.c module is reinstated
 */
#define USING_proxy_http_module 1

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Data declarations.                                                       */
/*                                                                          */
/*--------------------------------------------------------------------------*/

/*
 * Declare ourselves so the configuration routines can find and know us.
 * We'll fill it in at the end of the module.
 */
module AP_MODULE_DECLARE_DATA extract_forwarded_module;

/*
 * Per directory configuration record.
 */
typedef struct {
    int order;  /* order in which the accept and refuse specs are applied */
    int debug;                      /* debug output to error log flag */
    const char *envar;              /* name of env var to add */
    apr_table_t *accept_proxies;    /* proxies to trust */
    apr_table_t *refuse_proxies;    /* proxies to distrust */
} mef_config;

/*
 * Two possible orders in which the accept and refuse specs are applied
 */
#define REFUSE_THEN_ACCEPT 0
#define ACCEPT_THEN_REFUSE 1
/*
 * To output debug info to error log or not
 */
#define MEF_DEBUG_OFF 0
#define MEF_DEBUG_ON 1
/*
 * Maximum number of IPs in an X-Forwarded-For header of a request before
 * it is treated a excessive and hence absurd
 */
#define MEF_ABSURD_PROXY_LIMIT 32
/*
 * Default environment variable name
 */
#define MEF_PROXY_ADDR "MEF_PROXY_ADDR"
static const char* MEF_proxy_addr = MEF_PROXY_ADDR;

/*
 * This function gets called to create a per-directory configuration
 *
 * Specification of the modules associated directives should ensure that
 * we should only end up creating configs in the server and VirtualHost
 * containers but not in Directory, Location or Files containers
 *
 * The return value is a pointer to the created module-specific
 * structure.
 *
 * Config default is:
 *      MEForder refuse,accept
 *      MEFrefuse all
 *      MEFaccept - not 'all'
 *      MEFaddenv yes
 *      MEFdebug off
 */
static void *mef_create_dir_config(apr_pool_t *p, char *dirspec)
{
    mef_config *conf;
    conf = (mef_config *) apr_pcalloc(p, sizeof(mef_config));
    conf->order = REFUSE_THEN_ACCEPT;
    conf->debug = MEF_DEBUG_OFF;
    conf->envar = MEF_proxy_addr;
    conf->accept_proxies = apr_table_make(p, 0);
    conf->refuse_proxies = apr_table_make(p, 0);
    apr_table_set(conf->refuse_proxies, "all", "t");
    return (void *)conf;
}

/*
 * Record order in which accept and refuse specs are to be applied
 */
static const char *mef_order_proxy(cmd_parms *cparms, void *mconfig,
                                   const char *arg)
{
    mef_config *conf = (mef_config *)mconfig;
    if (!strcasecmp(arg, "refuse,accept"))
    {
        conf->order = REFUSE_THEN_ACCEPT;
    }
    else
    {
        if (!strcasecmp(arg, "accept,refuse"))
        {
            conf->order = ACCEPT_THEN_REFUSE;
        }
        else
        {
            return "Unknown MEForder specified";
        }
    }
    return NULL;
}

/*
 * Record whether MEF should insert an environment variable for the request
 * handler giving the IP of the machine actually making the connection if it
 * does spoof the conn_rec
 */
static const char *mef_add_env(cmd_parms *cparms, void *mconfig,
                                     const char *arg)
{
    mef_config *conf = (mef_config *)mconfig;
    if (!strcmp(arg, "no"))
    {
        conf->envar = NULL;
    }
    else
    {
        if (!strcmp(arg, "yes"))
        {
            conf->envar = MEF_proxy_addr;
        }
        else
        {
            conf->envar = apr_pstrdup(cparms->pool, arg);
        }
    }
    return NULL;
}

/*
 * Record whether MEF debug output to the error log should be generated
 */
static const char *mef_debug_control(cmd_parms *cparms, void *mconfig,
                                     const char *arg)
{
    mef_config *conf = (mef_config *)mconfig;
    if (!strcmp(arg, "on"))
    {
        conf->debug = MEF_DEBUG_ON;
    }
    else
    {
        if (!strcmp(arg, "off"))
        {
            conf->debug = MEF_DEBUG_OFF;
        }
        else
        {
            return "Unknown MEFdebug value specified";
        }
    }
    return NULL;
}

/*
 * Given an IP or 'all' as "arg", add it to the accept_proxies table
 */
static const char *mef_accept_proxy(cmd_parms *cparms, void *mconfig,
                                    const char *arg)
{
    mef_config *conf = (mef_config *)mconfig;
    struct hostent *hptr = NULL;
    char** haddr;
    if (strcasecmp(arg, "all") == 0)
    /* "all" keyword replaces everything with just itself */
    {
        apr_table_clear(conf->accept_proxies);
        apr_table_set(conf->accept_proxies, arg, "t");
    }
    else
    /* Add IP to list of accepted proxies */
    {
        hptr = gethostbyname(arg);
        if (hptr)
        {
            apr_table_unset(conf->accept_proxies, "all");
            for (haddr=hptr->h_addr_list; *haddr; haddr++)
            {
                apr_table_set(conf->accept_proxies,
                              inet_ntoa(*((struct in_addr*)(*haddr))), "t");
            }
        }
        else
        {
            return "No 'all' or valid IP identified by MEFaccept";
        }
    }
    return NULL;
}

/*
 * Given an IP or 'all' as "arg", add it to the refused_proxies table
 */
static const char *mef_refuse_proxy(cmd_parms *cparms, void *mconfig,
                                    const char *arg)
{
    mef_config *conf = (mef_config *) mconfig;
    struct hostent *hptr = NULL;
    char** haddr;
    if (strcasecmp(arg, "all") == 0)
    /* "all" keyword replaces everything with just itself */
    {
        apr_table_clear(conf->refuse_proxies);
        apr_table_set(conf->refuse_proxies, arg, "t");
    }
    else
    /* Add IP to list of refused proxies */
    {
        hptr = gethostbyname(arg);
        if (hptr)
        {
            apr_table_unset(conf->refuse_proxies, "all");
            for (haddr=hptr->h_addr_list; *haddr; haddr++)
            {
                apr_table_set(conf->refuse_proxies,
                              inet_ntoa(*((struct in_addr*)(*haddr))), "t");
            }
        }
        else
        {
            return "No 'all' or valid IP identified by MEFrefuse";
        }
    }
    return NULL;
}

/*
 * Make sure the given proxy IP is allowed with the server config we are given
 */
static int acceptable_proxy(mef_config *conf, char *proxy_ip)
{
    int accept_it = 0;
    int refuse_it = 0;
    /* is the proxy potentially acceptable */
    if (apr_table_get(conf->accept_proxies, "all") ||
        apr_table_get(conf->accept_proxies, proxy_ip))
    {
        accept_it = 1;
    }
    /* is the proxy potentially refuseable */
    if (apr_table_get(conf->refuse_proxies, "all") ||
        apr_table_get(conf->refuse_proxies, proxy_ip))
    {
        refuse_it = 1;
    }
    if (conf->order == ACCEPT_THEN_REFUSE)
    {
        /* Its OK if acceptable and not refused */
        return accept_it && !refuse_it;
    }
    else /* REFUSE_THEN_ACCEPT */
    {
        /*
         * Its OK if it was not refused or it was
         * but acceptance overrode the refusal
         */
        return !refuse_it || accept_it;
    }
    return 0;
}

/*
 * The MEFsave_rec data structure is used to preserve information that
 * this module has modified in the conn_rec associated with a request
 * so that the conn_rec can be restored to its original state as needed.
 * It also carries information between transaction phases and internal
 * redirects and subrequests
 */
typedef struct MEFsave_rec MEFsave_rec;

struct MEFsave_rec {
    conn_rec *connection;           /* connection record being used */
    in_addr_t orig_in_addr;         /* original remote in_addr_t */
    in_addr_t new_in_addr;          /* modified remote in_addr_t */
    char *orig_client_ip;           /* original client_ip */
    char *new_client_ip;            /* modified client_ip */
    int conn_rec_mod_state;         /* conn_rec modification state */
    int debug;                      /* are we printing MEF debug */
    const char *envar;              /* name of env var to add */
    void *per_dir_config;           /* per_dir_config applicable */
    MEFsave_rec *other_saved;       /* any preceding req's save_rec */
    request_rec *other_r;           /* any preceding req's request_rec */
};

#define CONN_REC_MODIFIED 1
#define CONN_REC_RESTORED 0

/*
 * remote_in_addr returns a pointer to the in_addr_t which specifes
 * the IP of the remote end of the connection supporting the specified
 * request. NULL is returned if this cannot be determined.
 */
static in_addr_t *get_remote_in_addr(conn_rec *conn)
{
    in_addr_t *result = NULL;
    if (conn->client_addr->family == AF_INET)
    {
        result = &(conn->client_addr->sa.sin.sin_addr.s_addr);
    }
#if defined(AF_INET6) && defined(IN6_IS_ADDR_V4MAPPED)
    if (conn->client_addr->family == AF_INET6 &&
        IN6_IS_ADDR_V4MAPPED(&conn->client_addr->sa.sin6.sin6_addr))
    {
        result = &(((uint32_t *)conn->client_addr->ipaddr_ptr)[3]);
    }
#endif
    return result;
}

/* Forward declared for convenience */
static apr_status_t cleanup_initial(void *data);
static apr_status_t cleanup_not_initial(void *data);

/*
 * The spoof_initial() function modifies the conn_rec for the connection over
 * which a request was made to make it appear that it came from a specifed
 * IP number rather than of the machine making the actual connection to the
 * Apache 2 server machine. We save the stuff we change and some other things
 * so that the changes can be reversed and re-applied if that is required.
 */
static int spoof_initial(request_rec *r, char *spoof_ip, char *phase)
{
    in_addr_t *remote_in_addr;
    MEFsave_rec *saved;
    mef_config *conf = ap_get_module_config(r->per_dir_config,
                                            &extract_forwarded_module);
    /* Validate and acquire pointer to the remote in_addr_t */
    if ((remote_in_addr = get_remote_in_addr(r->connection)) == NULL)
    {
        /* Could not get a valid value so give up */
        if (conf->debug == MEF_DEBUG_ON)
        {
            fprintf(stderr,"MEF: phase:%s, si problem acquiring remote_in_addr\n",
                    phase);
            fflush(stderr);
        }
        return DECLINED;
    }
    /*
     * We can proceed to do the spoof
     *
     * First, somewhere to save what we are changing
     */
    saved = apr_pcalloc(r->pool, sizeof(MEFsave_rec));
    /* Then the saving */
    saved->connection = r->connection;
    saved->orig_in_addr = *remote_in_addr;
    saved->orig_client_ip = r->connection->client_ip;
    saved->new_in_addr = inet_addr(spoof_ip);
    saved->new_client_ip = spoof_ip;
    saved->per_dir_config = r->per_dir_config;
    saved->debug = conf->debug;
    saved->envar = conf->envar;
    saved->other_saved = NULL;
    saved->other_r = NULL;
    /* Then the modifying of the conn_rec */
    *remote_in_addr = saved->new_in_addr;
    saved->connection->client_ip = saved->new_client_ip;
    saved->conn_rec_mod_state = CONN_REC_MODIFIED;
    /* Force re-evaluation of the remote_host value */
    saved->connection->remote_host = NULL;
    ap_get_remote_host(saved->connection, saved->per_dir_config,
                       REMOTE_HOST, NULL);
    /* Make the saved info available to later request processing phases */
    ap_set_module_config(r->request_config, &extract_forwarded_module,
                         saved);
    /*
     * Make this saved info available to the cleanup handler for the request
     * pool
     */
    apr_pool_cleanup_register(r->pool, (void *)saved, cleanup_initial,
                              apr_pool_cleanup_null);
    /* If wanted, put the last proxy's IP in an environment variable */
    if (saved->envar != NULL)
    {
        apr_table_set(r->subprocess_env, saved->envar, saved->orig_client_ip);
    }
    if (saved->debug == MEF_DEBUG_ON)
    {
        fprintf(stderr,"MEF: phase:%s, initial substituted %s for %s, %s\n",
                phase, saved->new_client_ip, saved->orig_client_ip,
                r->unparsed_uri);
        fflush(stderr);
    }
    return DECLINED;
}

/*
 * The spoof_not_initial() function continues the IP spoofing initiated by
 * spoof_initial() in the event that internal redirects or subrequests are
 * being used to service the initial request. These just piggy back on the
 * mechanism used by the initial request.
 */
static int spoof_not_initial(request_rec *this_r, request_rec *other_r,
                             char *phase)
{
    in_addr_t *remote_in_addr;
    MEFsave_rec *saved;
    MEFsave_rec *other_saved;
    /*
     * If the other (main or previous) request did nothing then
     * there is nothing for this request to do
     */
    if ((other_saved = ap_get_module_config(other_r->request_config,
                                         &extract_forwarded_module)) == NULL)
    {
        return DECLINED;
    }
    /*
     * We do the spoof by copying the other request's spoof
     *
     * First, somewhere to save what we are changing
     */
    saved = apr_pcalloc(this_r->pool, sizeof(MEFsave_rec));
    /* Then the copying */
    saved->connection = other_saved->connection;
    remote_in_addr = get_remote_in_addr(saved->connection);
    saved->orig_in_addr = other_saved->orig_in_addr;
    saved->orig_client_ip = other_saved->orig_client_ip;
    saved->new_in_addr = other_saved->new_in_addr;
    saved->new_client_ip = other_saved->new_client_ip;
    saved->per_dir_config = other_saved->per_dir_config;
    saved->debug = other_saved->debug;
    saved->envar = other_saved->envar;
    /* Followed by the local differences */
    saved->other_saved = other_saved;
    saved->other_r = other_r;
    /* Ensure the conn_rec is spoofed */
    *remote_in_addr = saved->new_in_addr;
    this_r->connection->client_ip = saved->new_client_ip;
    this_r->useragent_ip = saved->new_client_ip;
    saved->conn_rec_mod_state = CONN_REC_MODIFIED;
    /* Force re-evaluation of the remote_host value */
    saved->connection->remote_host = NULL;
    ap_get_remote_host(saved->connection, saved->per_dir_config,
                       REMOTE_HOST, NULL);
    /* Make the saved info available to later request processing phases */
    ap_set_module_config(this_r->request_config, &extract_forwarded_module,
                         saved);
    /*
     * Make this saved info available to the cleanup handler for the request
     * pool
     */
    apr_pool_cleanup_register(this_r->pool, (void *)saved,
                              cleanup_not_initial, apr_pool_cleanup_null);
    /*  If wanted, put the last proxy's IP in an environment variable */
    if (saved->envar != NULL)
    {
        apr_table_set(this_r->subprocess_env, saved->envar,
                      saved->orig_client_ip);
    }
    if (saved->debug == MEF_DEBUG_ON)
    {
        fprintf(stderr,
                "MEF: phase:%s, not initial substituted %s for %s, %s\n",
                phase, saved->new_client_ip, saved->orig_client_ip,
                this_r->unparsed_uri);
        fflush(stderr);
    }
    return DECLINED;
}

/*
 * The undo_spoof() function undoes the changes made to a conn_rec
 * by spoof_initial() or spoof_not_initial()
 */
static int undo_spoof(MEFsave_rec *saved, request_rec *r, char *phase)
{
    in_addr_t *remote_in_addr;
    if ((remote_in_addr = get_remote_in_addr(saved->connection)) == NULL)
    {
        /* Could not get a valid value so give up */
        return DECLINED;
    }
    /* Do the restoring */
    *remote_in_addr = saved->orig_in_addr;
    saved->connection->client_ip = saved->orig_client_ip;
    r->useragent_ip = saved->orig_client_ip;
    saved->connection->remote_host = NULL;
    ap_get_remote_host(saved->connection, saved->per_dir_config,
                       REMOTE_HOST, NULL);
    saved->conn_rec_mod_state = CONN_REC_RESTORED;
    if (r != NULL)
    {
        if (saved->envar != NULL)
        {
            apr_table_unset(r->subprocess_env, saved->envar);
        }
        if (saved->debug == MEF_DEBUG_ON)
        {
            fprintf(stderr,
                    "MEF: phase:%s, undo spoof substituted %s for %s, %s\n",
                    phase, saved->orig_client_ip, saved->new_client_ip,
                    r->unparsed_uri);
            fflush(stderr);
        }
    }
    else
    {
        if (saved->debug == MEF_DEBUG_ON)
        {
            fprintf(stderr,"MEF: phase:%s, undo spoof substituted %s for %s\n",
                    phase, saved->orig_client_ip, saved->new_client_ip);
            fflush(stderr);
        }
    }
    return DECLINED;
}

/*
 * The redo_spoof() function reapplies the changes made to a
 * conn_rec by spoof_initial() or spoof_not_initial():
 *
 * 1. after a prior call to undo_spoof has removed them, typically
 *    because of proxy_http reverse-proxy X-Forwarded-For issue
 * 2. when an internal redirect or subrequest has generated a new
 *    subordinate, request_rec which is (should be) using the same
 *    conn_rec as the primary request
 */
static int redo_spoof(MEFsave_rec *saved, request_rec *r, char *phase)
{
    in_addr_t *remote_in_addr;
    if ((remote_in_addr = get_remote_in_addr(saved->connection)) == NULL)
    {
        /* Could not get a valid value so give up */
        return DECLINED;
    }
    /* Modify it all again */
    *remote_in_addr = saved->new_in_addr;
    saved->connection->client_ip = saved->new_client_ip;
    r->useragent_ip = saved->new_client_ip;
    saved->connection->remote_host = NULL;
    ap_get_remote_host(saved->connection, saved->per_dir_config,
                       REMOTE_HOST, NULL);
    saved->conn_rec_mod_state = CONN_REC_MODIFIED;
    if (r != NULL)
    {
        if (saved->envar != NULL)
        {
            apr_table_set(r->subprocess_env, saved->envar,
                          saved->orig_client_ip);
        }
        if (saved->debug == MEF_DEBUG_ON)
        {
            fprintf(stderr,
                    "MEF: phase:%s, redo spoof substituted %s for %s, %s\n",
                    phase, saved->new_client_ip, saved->orig_client_ip,
                    r->unparsed_uri);
            fflush(stderr);
        }
    }
    else
    {
        if (saved->debug == MEF_DEBUG_ON)
        {
            fprintf(stderr,"MEF: phase:%s, redo spoof substituted %s for %s\n",
                    phase, saved->new_client_ip, saved->orig_client_ip);
            fflush(stderr);
        }
    }
    return DECLINED;
}

/*
 * The cleanup_initial() and cleanup_not_initial() function get the conn_rec
 * back to what it should be with the demise of the initial request or
 * any subsequent internal redirect of subrequests respectively.
 *
 * The actions of cleanup_initial() are particularly necessary if the
 * connection is from a proxy server which is makes multiple requests,
 * potentially for different clients, down a persistent connection.
 *
 * If we do not restore the proxy server's IP in the conn_rec then all
 * subsequent requests down the connection may be misattributed to
 * the same IP as the first request.
 *
 * The actions of cleanup_not_initial() are aimed at getting the conn_rec back
 * to the state it was in before the internal redirect request or subrequest
 * was started.
 */
static int cleanup_initial(void *data)
{
    MEFsave_rec *saved = (MEFsave_rec *)data;
    return undo_spoof(saved, NULL, "cleanup initial");
}

static int cleanup_not_initial(void *data)
{
    MEFsave_rec *saved = (MEFsave_rec *)data;
    if (saved->other_saved->conn_rec_mod_state == CONN_REC_MODIFIED)
    {
        return redo_spoof(saved->other_saved, saved->other_r,
                          "cleanup not initial");
    }
    else
    {
        return undo_spoof(saved->other_saved, saved->other_r,
                          "cleanup not initial");
    }
}

/*
 * primary_request() handles an initial request and is the primary
 * determinant of whether spoofing will done for the inital request
 * and any internal redirects or subrquests that flow from it
 */
static int primary_request(request_rec *r, char *phase)
{
    const char *fwded_for;
    const char *copy_fwded_for;
    char *val;
    char *client_ip;
    char *was_client_ip;
    apr_array_header_t *ary;
    int ctr;
    int start_ptr;
    conn_rec *conn = r->connection;
    mef_config *conf = ap_get_module_config(r->per_dir_config,
                                            &extract_forwarded_module);
    /* If there are no headers indicating proxying there is nothing  to do */
    if ((fwded_for = apr_table_get(r->headers_in, "X-Forwarded-For")) == NULL &&
        (fwded_for = apr_table_get(r->headers_in, "Forwarded-For")) == NULL)
    {
        if (conf->debug == MEF_DEBUG_ON)
        {
            fprintf(stderr,"MEF: phase:%s, no FORWARDED-FOR header, %s\n",
                    phase, r->unparsed_uri);
            fflush(stderr);
        }
        return DECLINED;
    }
    copy_fwded_for = fwded_for;
    /* If request was not from an acceptable proxy there is nothing to do */
    if (!acceptable_proxy(conf, conn->client_ip))
    {
        if (conf->debug == MEF_DEBUG_ON)
        {
            fprintf(stderr,"MEF: phase:%s, $s not acceptabler proxy, %s\n",
                    phase, conn->client_ip);
            fflush(stderr);
        }
        return DECLINED;
    }
    /* Build an array of proxies that say they forwarded this request */
    ary = apr_array_make(r->pool, 1, sizeof(char*));
    ctr = 0;
    while (*fwded_for && (val = ap_get_token(r->pool, &fwded_for, 0)))
    {
        *(char**)apr_array_push(ary) = apr_pstrdup(r->pool, val);
        if (*fwded_for == ',' || *fwded_for == ';')
        {
            ++fwded_for;
        }
        /* We protect ourselves against being fed absurd headers */
        if (++ctr > MEF_ABSURD_PROXY_LIMIT)
        {
            ctr = 0;
            break;
        }
    }
    /* If headers were empty or absurd there is nothing to do */
    if (!ctr)
    {
        if (conf->debug == MEF_DEBUG_ON)
        {
            fprintf(stderr,"MEF: phase:%s, duff header:%s\n",
                    phase, copy_fwded_for);
            fflush(stderr);
        }
        return DECLINED;
    }
    /*
     * Scan back from the end of the list of proxies until we
     * find one that isn't trusted, typically one that isn't one of our
     * proxy servers. This allows us to back out any sequence of trusted
     * proxy servers and find the first IP that isn't, which is the IP
     * we're interested in. What we want is the IP number of the machine
     * that made the connection to the first of, potentially a sequence
     * of, our trusted proxies. We don't care about any external
     * proxies that may precede our trusted proxies because we cannot
     * trust what they say.
     *
     * Do not search back beyond the 2nd forwarded-for IP number. Even
     * if the first is from a trusted proxy's IP number it must have
     * been acting as a client not a proxy if it appears in that
     * position.
     */
    for (ctr = ary->nelts - 1; ctr >= 1; ctr--)
    {
        if (!acceptable_proxy(conf, ((char**)ary->elts)[ctr]))
        {
            break;
        }
    }
    client_ip = ((char**)ary->elts)[ctr];
    /*
     * Here's the spoof
     */
    return spoof_initial(r, client_ip, phase);
}

/*
 * secondary_request() handles a secondary request. In MEF config terms
 * internal redirects and subrequests always do the same as the primary
 * request that triggers them
 */
static int secondary_request(request_rec *r, request_rec *other_r,
                             char *phase)
{
    MEFsave_rec *other_saved;
    other_saved = ap_get_module_config(other_r->request_config,
                                       &extract_forwarded_module);
    if (other_saved != NULL)
    {
        /*  Prior request did something so this request follows suit */
        return spoof_not_initial(r, other_r, phase);
    }
    /* Prior request did nothing so this one will do the same */
    return DECLINED;
}

/*
 * mef_composite() is called at post read request, URI translate, and
 * access checker request processing phases (also  header parser if you
 * enable that handler).
 *
 * If a proxy has provided us with an X-Forwarded-For: header we may want
 * to manipulate the remote IP associated with the request. We want to do
 * that as early as possible in the request processing cycle.  The first
 * handler to gain access to the request depends on whether the request
 * is an initial request, internal redirect or subrequest.
 */
static int mef_composite(request_rec *r, char *phase)
{
    /*
     * If we have already been at work in an earlier phase then do
     * nothing now
     */
    MEFsave_rec *saved;
    if ((saved = ap_get_module_config(r->request_config,
                                      &extract_forwarded_module)) != NULL)
    {
        if (saved->debug == MEF_DEBUG_ON)
        {
            fprintf(stderr,"MEF: phase:%s, already done, NFA required, %s\n",
                    phase,  r->unparsed_uri);
            fflush(stderr);
        }
        return DECLINED;
    }
    /*
     * What we now do depends on what type of request we are dealing with
     */
    if (ap_is_initial_req(r))
    {
        /* It the initial request */
        return primary_request(r, phase);
    }
    if (r->prev != NULL)
    {
        /* It is an internal redirect */
        return secondary_request(r, r->prev, phase);
    }
    if (r->main != NULL)
    {
        /* It is a subrequest */
        return secondary_request(r, r->main, phase);
    }
    return DECLINED; /* What are  we doing here captain! */
}

/*
 * We access mef_composite() via the following request phase specific
 * functions to pick up which phase it is for debug/trace logging
 * purposes
 */
static int mef_post_read_request(request_rec *r)
{
    return mef_composite(r, "post read request");
}

static int mef_uri_translate(request_rec *r)
{
    return mef_composite(r, "URI translate");
}

static int mef_header_parser(request_rec *r)
{
    return mef_composite(r, "header parser");
}

static int mef_access_check(request_rec *r)
{
    return mef_composite(r, "access check");
}

/*
 * mef_before_proxy_http() is called if Apache 2's HTTP proxy_http handler
 * is about to act and undoes the spoofing of the conn_rec associated with
 * the incoming request if the proxy is about to add information to the
 * request's X-Forwarded-For header. Without this the wrong IP (the
 * spoof one) is added to the X-Forwarded-For header.
 */
static int mef_before_proxy_http(request_rec *r,
#if AP_SERVER_MINORVERSION_NUMBER >= 2
                                 proxy_worker *worker,
#endif
                                 proxy_server_conf *pconf,
                                 char *url, const char *proxyname,
                                 apr_port_t proxyport)
{
    MEFsave_rec *saved;
    /*
     * If our post-read-request handler did something we may have to too
     */
    if ((saved = (MEFsave_rec *)ap_get_module_config(r->request_config,
                                         &extract_forwarded_module)) != NULL)
    {
        /*
         * If proxy_http is going to add X-Forwarded-For info then we have
         * have to undo the changes we made earlier so proxy_http can get
         * it right
         */
        if (PROXYREQ_REVERSE == r->proxyreq)
        {
            undo_spoof(saved,  r, "before proxy http");
        }
    }
    return DECLINED;
}

/*
 * mef_logging() is used to redo the spoofing of the conn_rec associated
 * with the incoming request if was undone.
 * Redoing the spoof is to ensure that the spoof IP is used for logging
 * information about the request
 */
static int mef_logging(request_rec *r)
{
    MEFsave_rec *saved;
    /*
     * If our post-read-request handler did something we may have to too
     */
    if ((saved = (MEFsave_rec *)ap_get_module_config(r->request_config,
                                         &extract_forwarded_module)) != NULL)
    {
        /*
         * If we undid the spoof, probably because proxy_http was adding
         * X-Forwarded-For info, then we want to redo the changes we
         * undid so the spook IP is logged
         */
        if (saved->conn_rec_mod_state == CONN_REC_RESTORED)
        {
            redo_spoof(saved, r, "logging");
        }
    }
    return DECLINED;
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Data structures pulling all the mef module's bits together               */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/*
 * mef module's functions attached to request processing hooks.
 */
static void mef_register_hooks(apr_pool_t *p)
{
    ap_hook_post_read_request(mef_post_read_request, NULL, NULL,
                              APR_HOOK_FIRST);
    ap_hook_translate_name(mef_uri_translate, NULL, NULL, APR_HOOK_FIRST);
/*
 * This hook shouldn't be needed as as subrequest should enter at URI translate
 * or access control/check but uncomment it if you think you need it
 *    ap_hook_header_parser(mef_header_parser, NULL, NULL, APR_HOOK_FIRST);
 */
    ap_hook_access_checker(mef_access_check, NULL, NULL, APR_HOOK_FIRST);
#ifdef USING_proxy_http_module
    /*
     * Only need to register the following handlers if proxy_http_module
     * is going to be loaded
     */
    static const char *const mef_proxy_b4[] = { "proxy_http.c", NULL };
    proxy_hook_scheme_handler(mef_before_proxy_http, NULL, mef_proxy_b4,
                              APR_HOOK_FIRST);
    ap_hook_log_transaction(mef_logging, NULL, NULL, APR_HOOK_FIRST);
#endif /* USING_proxy_http_module */
}

/*
 * List of directives specific to the mef module. The should only be used for
 * the default host or inside VirtualHost containers because we are running
 * a post read request handler which operates before we have done URI
 * translation and hence directory information is unavailable for the
 * request.
 */
static const command_rec mef_cmds[] =
{
    AP_INIT_TAKE1(
        "MEForder",             /* directive name */
        mef_order_proxy,        /* config action routine */
        NULL,                   /* argument to include in call */
        RSRC_CONF,              /* where available */
                                /* description  */
        "Order to apply checks - 'accept,refuse', 'refuse,accept'"
    ),
    AP_INIT_TAKE1(
        "MEFaddenv",            /* directive name */
        mef_add_env,            /* config action routine */
        NULL,                   /* argument to include in call */
        RSRC_CONF,              /* where available */
                                /* description  */
        "Add MEF_PROXY_ADDR env var - 'yes', 'no' or varname"
    ),
    AP_INIT_TAKE1(
        "MEFdebug",             /* directive name */
        mef_debug_control,      /* config action routine */
        NULL,                   /* argument to include in call */
        RSRC_CONF,              /* where available */
                                /* description  */
        "Generate debug output to error log - 'on', 'off'"
    ),
    AP_INIT_ITERATE(
        "MEFaccept",            /* directive name */
        mef_accept_proxy,       /* config action routine */
        NULL,                   /* argument to include in call */
        RSRC_CONF,              /* where available */
                                /* description  */
        "One or more proxy names or IPs to accept, or 'all'"
    ),
    AP_INIT_ITERATE(
        "MEFrefuse",            /* directive name */
        mef_refuse_proxy,       /* config action routine */
        NULL,                   /* argument to include in call */
        RSRC_CONF,              /* where available */
                                /* description  */
        "One or more proxy names or IPs to refuse, or 'all'"
    ),
    { NULL }
};

/*
 * mef module's definition for configuration.
 */
module AP_MODULE_DECLARE_DATA extract_forwarded_module =
{
    STANDARD20_MODULE_STUFF,
    mef_create_dir_config,      /* per-directory config creator */
    NULL,                       /* dir config merger */
    NULL,                       /* server config creator */
    NULL,                       /* server config merger */
    mef_cmds,                   /* command table */
    mef_register_hooks,         /* set up other request processing hooks */
};
