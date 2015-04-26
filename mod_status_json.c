/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Status Module to export Apache HTTP server status as JSON object.
 * To enable this, add the following lines into any config file:
 *
 * <Location /server-status-json>
 * SetHandler server-status-json
 * </Location>
 *
 * You may want to protect this location by password or domain so no one
 * else can look at it.  Then you can access the statistics with a URL like:
 *
 * http://your_server_name/server-status
 *
 * /server-status-json - Returns page using tables
 *
 *
 * TODO: Find out if the following query parameters still work:
 *
 * /server-status?notable - Returns page for browsers without table support
 * /server-status?refresh - Returns page with 1 second refresh
 * /server-status?refresh=6 - Returns page with refresh every 6 seconds
 * /server-status?auto - Returns page with data for automatic parsing
 *
 * Mikko Karjalainen 2015
 *
 * Derived from original Apache mod_status.c module:
 * Mark Cox, mark@ukweb.com, November 1995
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "ap_mpm.h"
#include "util_script.h"
#include <time.h>
#include "scoreboard.h"
#include "http_log.h"
#include "mod_status.h"
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"

#include "json.h"

#define STATUS_MAXLINE 64

#define KBYTE 1024
#define MBYTE 1048576L
#define GBYTE 1073741824L

#ifndef DEFAULT_TIME_FORMAT
#define DEFAULT_TIME_FORMAT "%A, %d-%b-%Y %H:%M:%S %Z"
#endif

#define STATUS_MAGIC_TYPE "application/x-httpd-status"
#define TEMP_STR_LENGTH 512

module AP_MODULE_DECLARE_DATA status_json_module;

static int server_limit, thread_limit, threads_per_child, max_servers,
           is_async;

static const char *to_textual_state(char chr);

/* Implement 'ap_run_status_hook'. */
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ap, STATUS, int, status_hook,
                                    (request_rec *r, int flags),
                                    (r, flags),
                                    OK, DECLINED)

#ifdef HAVE_TIMES
/* ugh... need to know if we're running with a pthread implementation
 * such as linuxthreads that treats individual threads as distinct
 * processes; that affects how we add up CPU time in a process
 */
static pid_t child_pid;
#endif

/* Format the number of bytes nicely */
static void format_byte_out(request_rec *r, apr_off_t bytes)
{
    if (bytes < (5 * KBYTE))
        ap_rprintf(r, "%d B", (int) bytes);
    else if (bytes < (MBYTE / 2))
        ap_rprintf(r, "%.1f kB", (float) bytes / KBYTE);
    else if (bytes < (GBYTE / 2))
        ap_rprintf(r, "%.1f MB", (float) bytes / MBYTE);
    else
        ap_rprintf(r, "%.1f GB", (float) bytes / GBYTE);
}

static void format_byte_out_str(char *buffer, int buflen, apr_off_t bytes)
{
    if (bytes < (5 * KBYTE))
        snprintf(buffer, buflen, "%d B", (int) bytes);
    else if (bytes < (MBYTE / 2))
        snprintf(buffer, buflen, "%.1f kB", (float) bytes / KBYTE);
    else if (bytes < (GBYTE / 2))
        snprintf(buffer, buflen, "%.1f MB", (float) bytes / MBYTE);
    else
        snprintf(buffer, buflen, "%.1f GB", (float) bytes / GBYTE);
}

static void format_kbyte_out(request_rec *r, apr_off_t kbytes)
{
    if (kbytes < KBYTE)
        ap_rprintf(r, "%d kB", (int) kbytes);
    else if (kbytes < MBYTE)
        ap_rprintf(r, "%.1f MB", (float) kbytes / KBYTE);
    else
        ap_rprintf(r, "%.1f GB", (float) kbytes / MBYTE);
}

static void show_time(request_rec *r, apr_uint32_t tsecs)
{
    int days, hrs, mins, secs;

    secs = (int)(tsecs % 60);
    tsecs /= 60;
    mins = (int)(tsecs % 60);
    tsecs /= 60;
    hrs = (int)(tsecs % 24);
    days = (int)(tsecs / 24);

    if (days)
        ap_rprintf(r, " %d day%s", days, days == 1 ? "" : "s");

    if (hrs)
        ap_rprintf(r, " %d hour%s", hrs, hrs == 1 ? "" : "s");

    if (mins)
        ap_rprintf(r, " %d minute%s", mins, mins == 1 ? "" : "s");

    if (secs)
        ap_rprintf(r, " %d second%s", secs, secs == 1 ? "" : "s");
}

static void write_server_info(js_serialiser_t *s, request_rec *r)
{
    apr_uint32_t up_time;
    apr_time_t nowtime;
    ap_loadavg_t t;
    ap_generation_t mpm_generation;
    unsigned long count;
    
    nowtime = apr_time_now();

    /* up_time in seconds */
    up_time = (apr_uint32_t) apr_time_sec(nowtime -
                               ap_scoreboard_image->global->restart_time);
    ap_get_loadavg(&t);


    js_object(s, "server");
    js_string(s, "name", ap_escape_html(r->pool, ap_get_server_name(r)));
    js_string(s, "via", r->connection->local_ip);
    js_string(s, "version", ap_get_server_description());
    js_string(s, "serverMPM", ap_show_mpm());
    js_string(s, "serverBuilt", ap_get_server_built());
    js_string(s, "currentTime: ",
              ap_ht_time(r->pool, nowtime, DEFAULT_TIME_FORMAT, 0));
    js_string(s, "restartTime: ",
              ap_ht_time(r->pool, 
                         ap_scoreboard_image->global->restart_time,
                         DEFAULT_TIME_FORMAT, 0));
    js_int_number(s, "parent-config-generation",
                  ap_state_query(AP_SQ_CONFIG_GEN));
    js_int_number(s, "parent-server-MPM-Generation", (int)mpm_generation);

    /* TODO: Mikko, fix uptime:
    js_int_number(&s, "serverUptime", uptime);
        ap_rputs("  ServerUptime: " DQUOTE, r);
        show_time(r, up_time);
    */

    js_object(s, "load");
    js_number(s, "avg", t.loadavg);
    js_number(s, "avg5:", t.loadavg5);
    js_number(s, "avg15:", t.loadavg15);
    js_object_end(s);
    js_object_end(s);


    js_int_number(s, "totalAccesses", count);
}

static void write_cpu_usage(js_serialiser_t *s,
                            clock_t tu, clock_t ts, clock_t tcu, clock_t tcs,
                            apr_uint32_t up_time, float tick)
{
    js_object(s, "cpuUsage");
    js_number(s, "u", tu/tick); 
    js_number(s, "s", ts/tick);
    js_number(s, "cu", tcu/tick);
    js_number(s, "cs", tcs/tick);
    if (ts || tu || tcu || tcs)
       js_number(s, "load:", (tu + ts + tcu + tcs) / tick / up_time * 100.);
    js_object_end(s);
}

static void write_process_record(js_serialiser_t *s, process_score *ps_record,
                                 int busy_workers, int idle_workers)
{
    js_object(s, "");

    /* TODO: Mikko: Potentially platform specific code. 
     *              Apache mod_status used APR_PID_T_FMT as 
     *              a format string.
     */
    js_int_number(s, "pid", ps_record->pid);
    js_object(s, "connections");
      js_int_number(s, "total", ps_record->connections);
      js_boolean(s, "accepting", !ps_record->not_accepting);
      js_object(s, "async");
        js_int_number(s, "writing", ps_record->write_completion);
        js_int_number(s, "keepAlive", ps_record->keep_alive);
        js_int_number(s, "closing", ps_record->lingering_close);
      js_object_end(s);
      js_object_end(s);
    js_object(s, "threads");
      js_int_number(s, "busy", busy_workers);
      js_int_number(s, "idle", idle_workers);
    js_object_end(s);
   js_object_end(s);
}

/* Main handler for x-httpd-status requests */

/* ID values for command table */

#define STAT_OPT_END     -1
#define STAT_OPT_REFRESH  0
#define STAT_OPT_NOTABLE  1
#define STAT_OPT_AUTO     2

struct stat_opt {
    int id;
    const char *form_data_str;
    const char *hdr_out_str;
};

static const struct stat_opt status_options[] = /* see #defines above */
{
    {STAT_OPT_REFRESH, "refresh", "Refresh"},
    {STAT_OPT_NOTABLE, "notable", NULL},
    {STAT_OPT_AUTO, "auto", NULL},
    {STAT_OPT_END, NULL, NULL}
};

/* add another state for slots above the MaxRequestWorkers setting */
#define SERVER_DISABLED SERVER_NUM_STATUS
#define MOD_STATUS_NUM_STATUS (SERVER_NUM_STATUS+1)

static char status_flags[MOD_STATUS_NUM_STATUS];

static void print_to_response(void *call_arg, const char *output)
{
    request_rec *r = call_arg;
    ap_rprintf(r, "%s", output);
}

static int all_threads_dead(int i, int thread_limit, char *stat_buffer)
{
    int j = 0;

    for (j = 0; j < thread_limit; ++j) {
        int indx = (i * thread_limit) + j;
        if (stat_buffer[indx] != '.' && stat_buffer[indx] != ' ') {
            return 0;
        }
    }
    return 1;
}


static void write_threads_summary(js_serialiser_t *s,
                                  int server_limit,
                                  int thread_limit,
                                  char *stat_buffer,
                                  char status_flags[])
{
    int i = 0;
    int j = 0;

    for (i = 0; i < server_limit; ++i) {
        if (all_threads_dead(i, thread_limit, stat_buffer)) {
            continue;
        }

        js_object(s, "");
        js_int_number(s, "server-id", i);
        js_array(s, "states");

        for (j = 0; j < thread_limit; ++j) {
            int indx = (i * thread_limit) + j;
            if (stat_buffer[indx] != status_flags[SERVER_DISABLED]) {
                js_string(s, "", to_textual_state(stat_buffer[indx]));
            }
        }
        js_array_end(s);
        js_object_end(s);
    }
}

static void write_server_activity(js_serialiser_t *s,
                                  int server_limit,
                                  int thread_limit,
                                  worker_score *ws_record,
                                  request_rec *r,
                                  apr_time_t nowtime)
{
    int i;
    int j;
    process_score *ps_record;
    long req_time;
    unsigned long lres, my_lres, conn_lres;
    apr_off_t bytes, my_bytes, conn_bytes;
    ap_generation_t mpm_generation, worker_generation;
    pid_t *pid_buffer, worker_pid;
    float tick;

    js_array(s, "serverActivity");

    for (i = 0; i < server_limit; ++i) {
        for (j = 0; j < thread_limit; ++j) {
            ap_copy_scoreboard_worker(ws_record, i, j);

            if (ws_record->access_count == 0 &&
               (ws_record->status == SERVER_READY ||
                ws_record->status == SERVER_DEAD)) {
                continue;
            }

            ps_record = ap_get_scoreboard_process(i);

            if (ws_record->start_time == 0L)
                req_time = 0L;
            else
                req_time = (long)
                    ((ws_record->stop_time -
                      ws_record->start_time) / 1000);
            if (req_time < 0L)
                req_time = 0L;

            lres       = ws_record->access_count;
            my_lres    = ws_record->my_access_count;
            conn_lres  = ws_record->conn_count;
            bytes      = ws_record->bytes_served;
            my_bytes   = ws_record->my_bytes_served;
            conn_bytes = ws_record->conn_bytes;

    
            if (ws_record->pid) { // MPM sets per-worker pid and generation
                worker_pid = ws_record->pid;
                worker_generation = ws_record->generation;
            }
            else {
                worker_pid = ps_record->pid;
                worker_generation = ps_record->generation;
            }

            js_object(s, "");
            /*
             * TODO, Mikko: prints Srv, PID, and Acc columns:
             */
            js_int_number(s, "serverChildNumber", i);
            js_int_number(s, "workerGeneration", worker_generation);
            if (ws_record->status == SERVER_DEAD) {
                js_int_number(s, "pid", -1);
            }
            else {
                js_int_number(s, "pid", worker_pid);
            }
            js_object(s, "accesses");
            js_int_number(s, "connection", conn_lres);
            js_int_number(s, "child", my_lres);
            js_int_number(s, "slot", lres);
            js_object_end(s);

            /* TODO,  Mikko: prints M column: */
            switch (ws_record->status) {
            case SERVER_READY:
                js_string(s, "mode", "_");
                break;
            case SERVER_STARTING:
                js_string(s, "mode", "S");
                break;
            case SERVER_BUSY_READ:
                js_string(s, "mode", "R");
                break;
            case SERVER_BUSY_WRITE:
                js_string(s, "mode", "W");
                break;
            case SERVER_BUSY_KEEPALIVE:
                js_string(s, "mode", "K");
                break;
            case SERVER_BUSY_LOG:
                js_string(s, "mode", "L");
                break;
            case SERVER_BUSY_DNS:
                js_string(s, "mode", "D");
                break;
            case SERVER_CLOSING:
                js_string(s, "mode", "C");
                break;
            case SERVER_DEAD:
                js_string(s, "mode", ".");
                break;
            case SERVER_GRACEFUL:
                js_string(s, "mode", "G");
                break;
            case SERVER_IDLE_KILL:
                js_string(s, "mode", "I");
                break;
            default:
                js_string(s, "mode", "?");
                break;
            }

#ifdef HAVE_TIMES
            js_number(s, "cpu", (ws_record->times.tms_utime +
                                ws_record->times.tms_stime +
                                ws_record->times.tms_cutime +
                                ws_record->times.tms_cstime) / tick);
#endif
            js_int_number(s, "sinceMostRecentSec", (long)apr_time_sec(nowtime -
                                                    ws_record->last_used));
            js_int_number(s, "processingTimeMs", req_time);

            js_number(s, "kbytesOnThisConnection", (double)conn_bytes/KBYTE);
            js_number(s, "mbytesOnThisConnection", (double)my_bytes/MBYTE);
            js_number(s, "totalMBytesOnThisSlot", (double)bytes/MBYTE);

            /* TODO, Mikko: Should be escape_json in following: */
            js_string(s, "client", ap_escape_html(r->pool,
                                              ws_record->client));
            js_string(s, "vHost", ap_escape_html(r->pool,
                                              ws_record->vhost));
            js_string(s, "request", ap_escape_html(r->pool,
                                              ap_escape_logitem(r->pool,
                                                      ws_record->request)));
            js_object_end(s);
        } // for (j...) 
    } // for (i...) 

    js_array_end(s);
}



static int status_handler(request_rec *r)
{
    const char *loc;
    apr_time_t nowtime;
    apr_uint32_t up_time;
    ap_loadavg_t t;
    int j, i, res, written;
    int ready;
    int busy;
    unsigned long count;
    unsigned long lres, my_lres, conn_lres;
    apr_off_t bytes, my_bytes, conn_bytes;
    apr_off_t bcount, kbcount;
    long req_time;
    int short_report;
    int no_table_report;
    worker_score *ws_record = apr_palloc(r->pool, sizeof *ws_record);
    process_score *ps_record;
    char *stat_buffer;
    pid_t *pid_buffer, worker_pid;
    int *thread_idle_buffer = NULL;
    int *thread_busy_buffer = NULL;
    clock_t tu, ts, tcu, tcs;
    ap_generation_t mpm_generation, worker_generation;
#ifdef HAVE_TIMES
    float tick;
    int times_per_thread;
#endif
    js_serialiser_t s;


    char temp_str[TEMP_STR_LENGTH];
  

    if (strcmp(r->handler, STATUS_MAGIC_TYPE) && strcmp(r->handler,
            "server-status-json")) {
        return DECLINED;
    }

#ifdef HAVE_TIMES
    times_per_thread = getpid() != child_pid;
#endif

    ap_mpm_query(AP_MPMQ_GENERATION, &mpm_generation);

#ifdef HAVE_TIMES
#ifdef _SC_CLK_TCK
    tick = sysconf(_SC_CLK_TCK);
#else
    tick = HZ;
#endif
#endif

    ready = 0;
    busy = 0;
    count = 0;
    bcount = 0;
    kbcount = 0;
    short_report = 0;
    no_table_report = 0;

    pid_buffer = apr_palloc(r->pool, server_limit * sizeof(pid_t));
    stat_buffer = apr_palloc(r->pool, server_limit * thread_limit * sizeof(char));
    if (is_async) {
        thread_idle_buffer = apr_palloc(r->pool, server_limit * sizeof(int));
        thread_busy_buffer = apr_palloc(r->pool, server_limit * sizeof(int));
    }

    nowtime = apr_time_now();
    tu = ts = tcu = tcs = 0;

    if (!ap_exists_scoreboard_image()) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01237)
                      "Server status unavailable in inetd mode");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    r->allowed = (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET)
        return DECLINED;

    ap_set_content_type(r, "application/json; charset=UTF-8");

    /*
     * Simple table-driven form data set parser that lets you alter the header
     */

    if (r->args) {
        i = 0;
        while (status_options[i].id != STAT_OPT_END) {
            if ((loc = ap_strstr_c(r->args,
                                   status_options[i].form_data_str)) != NULL) {
                switch (status_options[i].id) {
                case STAT_OPT_REFRESH: {
                    apr_size_t len = strlen(status_options[i].form_data_str);
                    long t = 0;

                    if (*(loc + len ) == '=') {
                        t = atol(loc + len + 1);
                    }
                    apr_table_setn(r->headers_out,
                                   status_options[i].hdr_out_str,
                                   apr_ltoa(r->pool, t < 1 ? 10 : t));
                    break;
                }
                case STAT_OPT_NOTABLE:
                    no_table_report = 1;
                    break;
                case STAT_OPT_AUTO:
                    ap_set_content_type(r, "text/plain; charset=ISO-8859-1");
                    short_report = 1;
                    break;
                }
            }

            i++;
        }
    }

    for (i = 0; i < server_limit; ++i) {
#ifdef HAVE_TIMES
        clock_t proc_tu = 0, proc_ts = 0, proc_tcu = 0, proc_tcs = 0;
        clock_t tmp_tu, tmp_ts, tmp_tcu, tmp_tcs;
#endif

        ps_record = ap_get_scoreboard_process(i);
        if (is_async) {
            thread_idle_buffer[i] = 0;
            thread_busy_buffer[i] = 0;
        }
        for (j = 0; j < thread_limit; ++j) {
            int indx = (i * thread_limit) + j;

            ap_copy_scoreboard_worker(ws_record, i, j);
            res = ws_record->status;

            if ((i >= max_servers || j >= threads_per_child)
                && (res == SERVER_DEAD))
                stat_buffer[indx] = status_flags[SERVER_DISABLED];
            else
                stat_buffer[indx] = status_flags[res];

            if (!ps_record->quiescing
                && ps_record->pid) {
                if (res == SERVER_READY) {
                    if (ps_record->generation == mpm_generation)
                        ready++;
                    if (is_async)
                        thread_idle_buffer[i]++;
                }
                else if (res != SERVER_DEAD &&
                         res != SERVER_STARTING &&
                         res != SERVER_IDLE_KILL) {
                    busy++;
                    if (is_async) {
                        if (res == SERVER_GRACEFUL)
                            thread_idle_buffer[i]++;
                        else
                            thread_busy_buffer[i]++;
                    }
                }
            }

            /* XXX what about the counters for quiescing/seg faulted
             * processes?  should they be counted or not?  GLA
             */
            if (ap_extended_status) {
                lres = ws_record->access_count;
                bytes = ws_record->bytes_served;

                if (lres != 0 || (res != SERVER_READY && res != SERVER_DEAD)) {
#ifdef HAVE_TIMES
                    tmp_tu = ws_record->times.tms_utime;
                    tmp_ts = ws_record->times.tms_stime;
                    tmp_tcu = ws_record->times.tms_cutime;
                    tmp_tcs = ws_record->times.tms_cstime;

                    if (times_per_thread) {
                        proc_tu += tmp_tu;
                        proc_ts += tmp_ts;
                        proc_tcu += tmp_tcu;
                        proc_tcs += tmp_tcs;
                    }
                    else {
                        if (tmp_tu > proc_tu ||
                            tmp_ts > proc_ts ||
                            tmp_tcu > proc_tcu ||
                            tmp_tcs > proc_tcs) {
                            proc_tu = tmp_tu;
                            proc_ts = tmp_ts;
                            proc_tcu = tmp_tcu;
                            proc_tcs = tmp_tcs;
                        }
                    }
#endif /* HAVE_TIMES */

                    count += lres;
                    bcount += bytes;

                    if (bcount >= KBYTE) {
                        kbcount += (bcount >> 10);
                        bcount = bcount & 0x3ff;
                    }
                }
            }
        }
#ifdef HAVE_TIMES
        tu += proc_tu;
        ts += proc_ts;
        tcu += proc_tcu;
        tcs += proc_tcs;
#endif
        pid_buffer[i] = ps_record->pid;
    }

    js_document4(&s, print_to_response, r, 1);

    up_time = (apr_uint32_t) apr_time_sec(nowtime -
                               ap_scoreboard_image->global->restart_time);
    ap_get_loadavg(&t);

    write_server_info(&s, r);

    js_int_number(&s, "totalAccesses", count);
    
    /* TODO, Mikko, Fix this:
    js_int_number(&s, "  totalTraffic: " DQUOTE);
            format_kbyte_out(r, kbcount);
    */
#ifdef HAVE_TIMES
    /* Allow for OS/2 not having CPU stats */
    write_cpu_usage(&s, tu, ts, tcu, tcs, up_time, tick);
#endif

    js_number(&s, "requestsPersec", (float)count/(float)up_time);

    /* TODO: numeric values passed as js_string */

    format_byte_out_str(temp_str, TEMP_STR_LENGTH,
                    (unsigned long)(KBYTE*(float)kbcount/(float)up_time));
    
    js_string(&s, "bytesPerSecondPerUptime", temp_str);


    if (count > 0) {
        format_byte_out_str(temp_str, TEMP_STR_LENGTH,
                        (unsigned long)(KBYTE*(float)kbcount/(float)count));
    
        js_string(&s, "bytesPerSecondPerCount", temp_str);
    }

    js_int_number(&s, "busyWorkers", busy);
    js_int_number(&s, "idleWorkers", ready);

    if (is_async) {
        int write_completion = 0, lingering_close = 0, keep_alive = 0,
            connections = 0;
        /*
         * These differ from 'busy' and 'ready' in how gracefully finishing
         * threads are counted. XXX: How to make this clear in the html?
         */
        int busy_workers = 0, idle_workers = 0;

        js_array(&s, "psRecords");
        for (i = 0; i < server_limit; ++i) {
            ps_record = ap_get_scoreboard_process(i);
            if (ps_record->pid) {
                write_process_record(&s, ps_record,
                                     thread_busy_buffer[i],
                                     thread_idle_buffer[i]);
           }
        }
        js_array_end(&s);
    }

    written = 0;

    js_array(&s, "threads");
    write_threads_summary(&s, server_limit, thread_limit,
                          stat_buffer, status_flags);
    js_array_end(&s);

    write_server_activity(&s, server_limit, thread_limit, ws_record, r, nowtime);
    {
        // Run extension hooks to insert extra content.
        int flags =
            (short_report ? AP_STATUS_SHORT : 0) |
            (no_table_report ? AP_STATUS_NOTABLE : 0) |
            (ap_extended_status ? AP_STATUS_EXTENDED : 0);

        ap_run_status_hook(r, flags);
    }

    /* TODO: Mikko: Is ap_psignature() necessary?
        ap_rputs(ap_psignature("<hr />\n",r), r);
    */

    js_document_end(&s);

    return 0;
}

static int status_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    /* When mod_status_json is loaded, default our ExtendedStatus to 'on'
     * other modules which prefer verbose scoreboards may play a similar game.
     * If left to their own requirements, mpm modules can make do with simple
     * scoreboard entries.
     */
    ap_extended_status = 1;
    return OK;
}

static const char *to_textual_state(char chr)
{
    switch (chr) {
    case '.':
        return "dead";
    case '_':
        return "ready";
    case 'S':
        return "starting";
    case 'R':
        return "busy-read";
    case 'W':
        return "busy-write";
    case 'K':
        return "busy-keep-alive";
    case 'L':
        return "busy-log";
    case 'D':
        return "busy-dns";
    case 'C':
        return "closing";
    case 'G':
        return "graceful";
    case 'I':
        return "idle-kill";
    case ' ':
        return "disabled";
    default:
        return "";
    }
}


static int status_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                       server_rec *s)
{ /*
    status_str[SERVER_DEAD] = "dead";  
    status_str[SERVER_READY] = "ready";
    status_str[SERVER_STARTING] = "starting";
    status_str[SERVER_BUSY_READ] = "read";
    status_str[SERVER_BUSY_WRITE] = "write";
    status_str[SERVER_BUSY_KEEPALIVE] = "keep-alive";
    status_str[SERVER_BUSY_LOG] = "busy-log";
    status_str[SERVER_BUSY_DNS] = "dns";
    status_str[SERVER_CLOSING] = "closing";
    status_str[SERVER_GRACEFUL] = "graceful";
    status_str[SERVER_IDLE_KILL] = "idle-kill";
    status_str[SERVER_DISABLED] = "disabled";
  */

    status_flags[SERVER_DEAD] = '.';  /* We don't want to assume these are in */
    status_flags[SERVER_READY] = '_'; /* any particular order in scoreboard.h */
    status_flags[SERVER_STARTING] = 'S';
    status_flags[SERVER_BUSY_READ] = 'R';
    status_flags[SERVER_BUSY_WRITE] = 'W';
    status_flags[SERVER_BUSY_KEEPALIVE] = 'K';
    status_flags[SERVER_BUSY_LOG] = 'L';
    status_flags[SERVER_BUSY_DNS] = 'D';
    status_flags[SERVER_CLOSING] = 'C';
    status_flags[SERVER_GRACEFUL] = 'G';
    status_flags[SERVER_IDLE_KILL] = 'I';
    status_flags[SERVER_DISABLED] = ' ';
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);
    ap_mpm_query(AP_MPMQ_MAX_THREADS, &threads_per_child);
    /* work around buggy MPMs */
    if (threads_per_child == 0)
        threads_per_child = 1;
    ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_servers);
    ap_mpm_query(AP_MPMQ_IS_ASYNC, &is_async);
    return OK;
}

#ifdef HAVE_TIMES
static void status_child_init(apr_pool_t *p, server_rec *s)
{
    child_pid = getpid();
}
#endif

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(status_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(status_pre_config, NULL, NULL, APR_HOOK_LAST);
    ap_hook_post_config(status_init, NULL, NULL, APR_HOOK_MIDDLE);
#ifdef HAVE_TIMES
    ap_hook_child_init(status_child_init, NULL, NULL, APR_HOOK_MIDDLE);
#endif
}

AP_DECLARE_MODULE(status_json) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    NULL,                       /* command table */
    register_hooks              /* register_hooks */
};
