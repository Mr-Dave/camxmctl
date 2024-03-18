/*
 *    This file is part of camxmctl.
 *
 *    camxmctl is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    camxmctl is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with camxmctl.  If not, see <https://www.gnu.org/licenses/>.
 *
*/

#include "camxmctl.hpp"
#include "conf.hpp"
#include "logger.hpp"
#include "util.hpp"
#include "webu.hpp"
#include "webu_json.hpp"

/* Get the command, device_id and camera index from the post data */
void webu_post_cmdindx(ctx_webui *webui)
{
    int indx;
    std::string keyval;

    webui->post_cmd = "";

    for (indx = 0; indx < webui->post_sz; indx++) {
        keyval = std::string(webui->post_info[indx].key_val);
        if (mystreq(webui->post_info[indx].key_nm, "command")) {
            webui->post_cmd = keyval;
        }
        if (mystreq(webui->post_info[indx].key_nm, "ip")) {
            webui->app->caminfo.ip =keyval;
        }
        if (mystreq(webui->post_info[indx].key_nm, "port")) {
            webui->app->caminfo.port =keyval;
        }
        if (mystreq(webui->post_info[indx].key_nm, "user")) {
            webui->app->caminfo.user = keyval;
        }
        if (mystreq(webui->post_info[indx].key_nm, "password")) {
            webui->app->caminfo.pwd = keyval;
        }
        if (mystreq(webui->post_info[indx].key_nm, "key_nm")) {
            webui->app->caminfo.cfg_nm =keyval;
        }
        if (mystreq(webui->post_info[indx].key_nm, "key_val")) {
            webui->app->caminfo.cfg_val =keyval;
        }
        if (mystreq(webui->post_info[indx].key_nm, "ptz_action")) {
            webui->app->caminfo.ptz_action =keyval;
        }
        if (mystreq(webui->post_info[indx].key_nm, "ptz_duration")) {
            webui->app->caminfo.ptz_duration = keyval;
        }

        LOG_MSG(DBG, NO_ERRNO ,"key: %s  value: %s "
            , webui->post_info[indx].key_nm
            , webui->post_info[indx].key_val
        );

        //fprintf(stderr, "\n\n%s\n\n",webui->app->caminfo.cfg_val.c_str());
    }

    if (webui->post_cmd == "") {
        LOG_MSG(ERR, NO_ERRNO
            , "Invalid post request.  No command");
        return;
    }
}

/* Process the actions from the webcontrol that the user requested */
void webu_post_main(ctx_webui *webui)
{

    webu_post_cmdindx(webui);

    if (webui->post_cmd == "")  {
        return;
    }

    webui->app->status_msg = "";

    if (webui->post_cmd == "login") {
        camctl_login(webui->app);
    } else if (webui->post_cmd == "logout") {
        camctl_logout(webui->app);
    } else if (webui->post_cmd == "configset") {
        camctl_login(webui->app);
        camctl_config_set(webui->app);
        camctl_logout(webui->app);
    } else if (webui->post_cmd == "ptz") {
        camctl_login(webui->app);
        camctl_cmd_ptz(webui->app);
        camctl_logout(webui->app);
    } else if ((webui->post_cmd == "reboot") ||
        (webui->post_cmd == "settime1") ||
        (webui->post_cmd == "settime2")) {
        camctl_login(webui->app);
        camctl_cmd_send(webui->app, webui->post_cmd.c_str(), "");
        camctl_logout(webui->app);
    } else {
        LOG_MSG(INF, NO_ERRNO
            , "Invalid action requested: command: >%s< "
            , webui->post_cmd.c_str());
    }

}

void webu_html_badreq(ctx_webui *webui)
{
    webui->resp_page =
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<body>\n"
        "<p>Bad Request</p>\n"
        "<p>The server did not understand your request.</p>\n"
        "</body>\n"
        "</html>\n";
}

void webu_html_page(ctx_webui *webui)
{
    webui->resp_page =
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<body>\n"
        "<p>No page</p>\n"
        "<p>The server does not have a default page.  Provide user page via configuration file.</p>\n"
        "</body>\n"
        "</html>\n";
}

void webu_html_user(ctx_webui *webui)
{
    char response[PATH_MAX];
    FILE *fp = NULL;

    fp = myfopen(webui->app->conf->webcontrol_html.c_str(), "re");

    if (fp == NULL) {
        LOG_MSG(ERR, NO_ERRNO
            , "Invalid user html file: %s"
            , webui->app->conf->webcontrol_html.c_str());
        webu_html_badreq(webui);
        return;
    }

    webui->resp_page = "";
    while (fgets(response, PATH_MAX-1, fp)) {
        webui->resp_page += response;
    }

    myfclose(fp);
}

/* Set defaults for the webui context */
static void webu_context_init(ctx_app *app, ctx_webui *webui)
{
    webui->url           = "";
    webui->uri_cmd0     = "";
    webui->uri_cmd1      = "";
    webui->uri_cmd2      = "";
    webui->uri_cmd3      = "";
    webui->clientip      = "";

    webui->auth_opaque   = (char*)mymalloc(WEBUI_LEN_PARM);
    webui->auth_realm    = (char*)mymalloc(WEBUI_LEN_PARM);
    webui->auth_user     = NULL;                        /* Buffer to hold the user name*/
    webui->auth_pass     = NULL;                        /* Buffer to hold the password */
    webui->authenticated = false;                       /* boolean for whether we are authenticated*/
    webui->resp_size     = WEBUI_LEN_RESP * 10;         /* The size of the resp_page buffer.  May get adjusted */
    webui->resp_used     = 0;                           /* How many bytes used so far in resp_page*/
    webui->resp_image    = NULL;                        /* Buffer for sending the images */
    webui->stream_pos    = 0;                           /* Stream position of image being sent */
    webui->stream_fps    = 300;                         /* Stream rate */
    webui->resp_page     = "";                          /* The response being constructed */
    webui->app           = app;                         /* The application context */
    webui->cnct_type     = WEBUI_CNCT_UNKNOWN;
    webui->resp_type     = WEBUI_RESP_HTML;             /* Default to html response */
    webui->cnct_method   = WEBUI_METHOD_GET;
    webui->post_sz       = 0;
    webui->post_info     = NULL;

    return;
}

/* Free the variables in the webui context */
static void webu_context_free(ctx_webui *webui)
{
    int indx;
    myfree(&webui->auth_user);
    myfree(&webui->auth_pass);
    myfree(&webui->auth_opaque);
    myfree(&webui->auth_realm);
    myfree(&webui->resp_image);
    for (indx = 0; indx<webui->post_sz; indx++) {
        myfree(&webui->post_info[indx].key_nm);
        myfree(&webui->post_info[indx].key_val);
    }
    myfree(&webui->post_info);

    delete webui;
}

/* Edit the parameters specified in the url sent */
static void webu_parms_edit(ctx_webui *webui)
{
    LOG_MSG(DBG, NO_ERRNO
        , "cmd0: >%s< cmd1: >%s< cmd2: >%s< cmd3: >%s<"
        , webui->uri_cmd0.c_str(), webui->uri_cmd1.c_str()
        , webui->uri_cmd2.c_str(), webui->uri_cmd3.c_str());

}


/* Extract the cmds from the url */
static int webu_parseurl(ctx_webui *webui)
{
    char *tmpurl;
    size_t  pos_slash1, pos_slash2, baselen;

    /* Example:  /chid/cmd1/cmd2/cmd3   */
    webui->uri_cmd0 = "";
    webui->uri_cmd1 = "";
    webui->uri_cmd2 = "";
    webui->uri_cmd3 = "";

    LOG_MSG(DBG, NO_ERRNO, "Sent url: %s"
        ,webui->url.c_str());

    tmpurl = (char*)mymalloc(webui->url.length()+1);
    memcpy(tmpurl, webui->url.c_str(), webui->url.length());

    MHD_http_unescape(tmpurl);

    webui->url.assign(tmpurl);
    free(tmpurl);

    LOG_MSG(DBG, NO_ERRNO, "Decoded url: %s",webui->url.c_str());

    baselen = webui->app->conf->webcontrol_base_path.length();

    if (webui->url.length() < baselen) {
        return -1;
    }

    if (webui->url.substr(baselen) ==  "/favicon.ico") {
        return -1;
    }

    if (webui->url.substr(0, baselen) !=
        webui->app->conf->webcontrol_base_path) {
        return -1;
    }

    if (webui->url == "/") {
        return 0;
    }

    /* Remove any trailing slash to keep parms clean */
    if (webui->url.substr(webui->url.length()-1,1) == "/") {
        webui->url = webui->url.substr(0, webui->url.length()-1);
    }

    if (webui->url.length() == baselen) {
        return 0;
    }

    pos_slash1 = webui->url.find("/", baselen+1);
    if (pos_slash1 != std::string::npos) {
        webui->uri_cmd0 = webui->url.substr(baselen+1, pos_slash1-baselen- 1);
    } else {
        webui->uri_cmd0 = webui->url.substr(baselen+1);
        return 0;
    }

    pos_slash1++;
    if (pos_slash1 >= webui->url.length()) {
        return 0;
    }

    pos_slash2 = webui->url.find("/", pos_slash1);
    if (pos_slash2 != std::string::npos) {
        webui->uri_cmd1 = webui->url.substr(pos_slash1, pos_slash2 - pos_slash1);
    } else {
        webui->uri_cmd1 = webui->url.substr(pos_slash1);
        return 0;
    }

    pos_slash1 = ++pos_slash2;
    if (pos_slash1 >= webui->url.length()) {
        return 0;
    }

    pos_slash2 = webui->url.find("/", pos_slash1);
    if (pos_slash2 != std::string::npos) {
        webui->uri_cmd2 = webui->url.substr(pos_slash1, pos_slash2 - pos_slash1);
    } else {
        webui->uri_cmd2 = webui->url.substr(pos_slash1);
        return 0;
    }

    pos_slash1 = ++pos_slash2;
    if (pos_slash1 >= webui->url.length()) {
        return 0;
    }
    webui->uri_cmd3 = webui->url.substr(pos_slash1);

    return 0;

}

/* Log the ip of the client connecting*/
static void webu_clientip(ctx_webui *webui)
{
    const union MHD_ConnectionInfo *con_info;
    char client[WEBUI_LEN_URLI];
    const char *ip_dst;
    struct sockaddr_in6 *con_socket6;
    struct sockaddr_in *con_socket4;
    int is_ipv6;

    is_ipv6 = false;
    if (webui->app->conf->webcontrol_ipv6) {
        is_ipv6 = true;
    }

    con_info = MHD_get_connection_info(webui->connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (is_ipv6) {
        con_socket6 = (struct sockaddr_in6 *)con_info->client_addr;
        ip_dst = inet_ntop(AF_INET6, &con_socket6->sin6_addr, client, WEBUI_LEN_URLI);
        if (ip_dst == NULL) {
            webui->clientip = "Unknown";
        } else {
            webui->clientip.assign(client);
            if (webui->clientip.substr(0, 7) == "::ffff:") {
                webui->clientip = webui->clientip.substr(7);
            }
        }
    } else {
        con_socket4 = (struct sockaddr_in *)con_info->client_addr;
        ip_dst = inet_ntop(AF_INET, &con_socket4->sin_addr, client, WEBUI_LEN_URLI);
        if (ip_dst == NULL) {
            webui->clientip = "Unknown";
        } else {
            webui->clientip.assign(client);
        }
    }

}

/* Get the hostname */
static void webu_hostname(ctx_webui *webui)
{
    const char *hdr;

    hdr = MHD_lookup_connection_value(webui->connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_HOST);
    if (hdr == NULL) {
        webui->hostfull = "//localhost:" +
            std::to_string(webui->app->conf->webcontrol_port) +
            webui->app->conf->webcontrol_base_path;
    } else {
        webui->hostfull = "//" +  std::string(hdr) +
            webui->app->conf->webcontrol_base_path;
    }

    LOG_MSG(DBG, NO_ERRNO, "Full Host:  %s", webui->hostfull.c_str());

    return;
}

/* Log the failed authentication check */
static void webu_failauth_log(ctx_webui *webui, bool userid_fail)
{
    timespec            tm_cnct;
    ctx_webu_clients    clients;
    std::list<ctx_webu_clients>::iterator   it;

    LOG_MSG(ALR, NO_ERRNO
            ,"Failed authentication from %s", webui->clientip.c_str());

    clock_gettime(CLOCK_MONOTONIC, &tm_cnct);

    it = webui->app->webcontrol_clients.begin();
    while (it != webui->app->webcontrol_clients.end()) {
        if (it->clientip == webui->clientip) {
            it->conn_nbr++;
            it->conn_time.tv_sec =tm_cnct.tv_sec;
            it->authenticated = false;
            if (userid_fail) {
                it->userid_fail_nbr++;
            }
            return;
        }
        it++;

    }

    clients.clientip = webui->clientip;
    clients.conn_nbr = 1;
    clients.conn_time = tm_cnct;
    clients.authenticated = false;
    if (userid_fail) {
        clients.userid_fail_nbr = 1;
    } else {
        clients.userid_fail_nbr = 0;
    }

    webui->app->webcontrol_clients.push_back(clients);

    return;

}

static void webu_client_connect(ctx_webui *webui)
{
    timespec  tm_cnct;
    ctx_webu_clients  clients;
    std::list<ctx_webu_clients>::iterator   it;

    clock_gettime(CLOCK_MONOTONIC, &tm_cnct);

    /* First we need to clean out any old IPs from the list*/
    it = webui->app->webcontrol_clients.begin();
    while (it != webui->app->webcontrol_clients.end()) {
        if ((tm_cnct.tv_sec - it->conn_time.tv_sec) >=
            (webui->app->conf->webcontrol_lock_minutes*60)) {
            it = webui->app->webcontrol_clients.erase(it);
        }
        it++;
    }

    /* When this function is called, we know that we are authenticated
     * so we reset the info and as needed print a message that the
     * ip is connected.
     */
    it = webui->app->webcontrol_clients.begin();
    while (it != webui->app->webcontrol_clients.end()) {
        if (it->clientip == webui->clientip) {
            if (it->authenticated == false) {
                LOG_MSG(INF, NO_ERRNO, "Connection from: %s",webui->clientip.c_str());
            }
            it->authenticated = true;
            it->conn_nbr = 1;
            it->userid_fail_nbr = 0;
            it->conn_time.tv_sec = tm_cnct.tv_sec;
            return;
        }
        it++;
    }

    /* The ip was not already in our list. */
    clients.clientip = webui->clientip;
    clients.conn_nbr = 1;
    clients.userid_fail_nbr = 0;
    clients.conn_time = tm_cnct;
    clients.authenticated = true;
    webui->app->webcontrol_clients.push_back(clients);

    LOG_MSG(INF, NO_ERRNO, "Connection from: %s",webui->clientip.c_str());

    return;

}

/* Check for ips with excessive failed authentication attempts */
static mhdrslt webu_failauth_check(ctx_webui *webui)
{
    timespec                                tm_cnct;
    std::list<ctx_webu_clients>::iterator   it;
    std::string                             tmp;

    if (webui->app->webcontrol_clients.size() == 0) {
        return MHD_YES;
    }

    clock_gettime(CLOCK_MONOTONIC, &tm_cnct);
    it = webui->app->webcontrol_clients.begin();
    while (it != webui->app->webcontrol_clients.end()) {
        if ((it->clientip == webui->clientip) &&
            ((tm_cnct.tv_sec - it->conn_time.tv_sec) <
             (webui->app->conf->webcontrol_lock_minutes*60)) &&
            (it->authenticated == false) &&
            (it->conn_nbr > webui->app->conf->webcontrol_lock_attempts)) {
            LOG_MSG(EMG, NO_ERRNO
                , "Ignoring connection from: %s"
                , webui->clientip.c_str());
            it->conn_time = tm_cnct;
            return MHD_NO;
        } else if ((tm_cnct.tv_sec - it->conn_time.tv_sec) >=
            (webui->app->conf->webcontrol_lock_minutes*60)) {
            it = webui->app->webcontrol_clients.erase(it);
        } else {
            it++;
        }
    }

    return MHD_YES;

}

/* Create a authorization denied response to user*/
static mhdrslt webu_mhd_digest_fail(ctx_webui *webui,int signal_stale)
{
    struct MHD_Response *response;
    mhdrslt retcd;

    webui->authenticated = false;

    webui->resp_page = "<html><head><title>Access denied</title>"
        "</head><body>Access denied</body></html>";

    response = MHD_create_response_from_buffer(webui->resp_page.length()
        ,(void *)webui->resp_page.c_str(), MHD_RESPMEM_PERSISTENT);

    if (response == NULL) {
        return MHD_NO;
    }

    retcd = MHD_queue_auth_fail_response(webui->connection, webui->auth_realm
        ,webui->auth_opaque, response
        ,(signal_stale == MHD_INVALID_NONCE) ? MHD_YES : MHD_NO);

    MHD_destroy_response(response);

    return retcd;
}

/* Perform digest authentication */
static mhdrslt webu_mhd_digest(ctx_webui *webui)
{
    /* This function gets called a couple of
     * times by MHD during the authentication process.
     */
    int retcd;
    char *user;

    /*Get username or prompt for a user/pass */
    user = MHD_digest_auth_get_username(webui->connection);
    if (user == NULL) {
        return webu_mhd_digest_fail(webui, MHD_NO);
    }

    /* Check for valid user name */
    if (mystrne(user, webui->auth_user)) {
        webu_failauth_log(webui, true);
        myfree(&user);
        return webu_mhd_digest_fail(webui, MHD_NO);
    }
    myfree(&user);

    /* Check the password as well*/
    retcd = MHD_digest_auth_check(webui->connection, webui->auth_realm
        , webui->auth_user, webui->auth_pass, 300);

    if (retcd == MHD_NO) {
        webu_failauth_log(webui, false);
    }

    if ( (retcd == MHD_INVALID_NONCE) || (retcd == MHD_NO) )  {
        return webu_mhd_digest_fail(webui, retcd);
    }

    webui->authenticated = true;
    return MHD_YES;

}

/* Create a authorization denied response to user*/
static mhdrslt webu_mhd_basic_fail(ctx_webui *webui)
{
    struct MHD_Response *response;
    int retcd;

    webui->authenticated = false;

    webui->resp_page = "<html><head><title>Access denied</title>"
        "</head><body>Access denied</body></html>";

    response = MHD_create_response_from_buffer(webui->resp_page.length()
        ,(void *)webui->resp_page.c_str(), MHD_RESPMEM_PERSISTENT);

    if (response == NULL) {
        return MHD_NO;
    }

    retcd = MHD_queue_basic_auth_fail_response (webui->connection, webui->auth_realm, response);

    MHD_destroy_response(response);

    if (retcd == MHD_YES) {
        return MHD_YES;
    } else {
        return MHD_NO;
    }

}

/* Perform Basic Authentication.  */
static mhdrslt webu_mhd_basic(ctx_webui *webui)
{
    char *user, *pass;

    pass = NULL;
    user = NULL;

    user = MHD_basic_auth_get_username_password (webui->connection, &pass);
    if ((user == NULL) || (pass == NULL)) {
        myfree(&user);
        myfree(&pass);
        return webu_mhd_basic_fail(webui);
    }

    if ((mystrne(user, webui->auth_user)) || (mystrne(pass, webui->auth_pass))) {
        webu_failauth_log(webui, mystrne(user, webui->auth_user));
        myfree(&user);
        myfree(&pass);
        return webu_mhd_basic_fail(webui);
    }

    myfree(&user);
    myfree(&pass);

    webui->authenticated = true;

    return MHD_YES;

}

/* Parse apart the user:pass provided*/
static void webu_mhd_auth_parse(ctx_webui *webui)
{
    int auth_len;
    char *col_pos;

    myfree(&webui->auth_user);
    myfree(&webui->auth_pass);

    auth_len = (int)webui->app->conf->webcontrol_authentication.length();
    col_pos =(char*) strstr(webui->app->conf->webcontrol_authentication.c_str() ,":");
    if (col_pos == NULL) {
        webui->auth_user = (char*)mymalloc(auth_len+1);
        webui->auth_pass = (char*)mymalloc(2);
        snprintf(webui->auth_user, auth_len + 1, "%s"
            ,webui->app->conf->webcontrol_authentication.c_str());
        snprintf(webui->auth_pass, 2, "%s","");
    } else {
        webui->auth_user = (char*)mymalloc(auth_len - strlen(col_pos) + 1);
        webui->auth_pass =(char*)mymalloc(strlen(col_pos));
        snprintf(webui->auth_user, auth_len - strlen(col_pos) + 1, "%s"
            ,webui->app->conf->webcontrol_authentication.c_str());
        snprintf(webui->auth_pass, strlen(col_pos), "%s", col_pos + 1);
    }

}

/* Initialize for authorization */
static mhdrslt webu_mhd_auth(ctx_webui *webui)
{
    unsigned int rand1,rand2;

    srand((unsigned int)time(NULL));
    rand1 = (unsigned int)(42000000.0 * rand() / (RAND_MAX + 1.0));
    rand2 = (unsigned int)(42000000.0 * rand() / (RAND_MAX + 1.0));
    snprintf(webui->auth_opaque, WEBUI_LEN_PARM, "%08x%08x", rand1, rand2);

    snprintf(webui->auth_realm, WEBUI_LEN_PARM, "%s","Restream");

    if (webui->app->conf->webcontrol_authentication == "") {
        webui->authenticated = true;
        if (webui->app->conf->webcontrol_auth_method != "none") {
            LOG_MSG(NTC, NO_ERRNO ,"No webcontrol user:pass provided");
        }
        return MHD_YES;
    }

    if (webui->auth_user == NULL) {
        webu_mhd_auth_parse(webui);
    }

    if (webui->app->conf->webcontrol_auth_method == "basic") {
        return webu_mhd_basic(webui);
    } else if (webui->app->conf->webcontrol_auth_method == "digest") {
        return webu_mhd_digest(webui);
    }


    webui->authenticated = true;
    return MHD_YES;

}

/* Send the response that we created back to the user.  */
static mhdrslt webu_mhd_send(ctx_webui *webui)
{
    mhdrslt retcd;
    struct MHD_Response *response;
    std::list<ctx_params_item>::iterator    it;

    response = MHD_create_response_from_buffer(webui->resp_page.length()
        ,(void *)webui->resp_page.c_str(), MHD_RESPMEM_PERSISTENT);
    if (!response) {
        LOG_MSG(ERR, NO_ERRNO, "Invalid response");
        return MHD_NO;
    }

    for (it  = webui->app->webcontrol_headers.params_array.begin();
         it != webui->app->webcontrol_headers.params_array.end(); it++) {
        MHD_add_response_header (response
            , it->param_name.c_str(), it->param_value.c_str());
    }

    if (webui->resp_type == WEBUI_RESP_TEXT) {
        MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain;");
    } else if (webui->resp_type == WEBUI_RESP_JSON) {
        MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json;");
    } else {
        MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html");
    }

    retcd = MHD_queue_response (webui->connection, MHD_HTTP_OK, response);
    MHD_destroy_response (response);

    return retcd;
}

/* Process the post data command */
static mhdrslt webu_answer_post(ctx_webui *webui)
{
    mhdrslt retcd;

    LOG_MSG(DBG, NO_ERRNO ,"processing post");

    webu_post_main(webui);

    if (webui->app->conf->webcontrol_interface == "user") {
        webu_html_user(webui);
    } else {
        webu_html_page(webui);
    }

    retcd = webu_mhd_send(webui);
    if (retcd == MHD_NO) {
        LOG_MSG(NTC, NO_ERRNO ,"send post page failed");
    }

    return retcd;

}

/*Append more data on to an existing entry in the post info structure */
static void webu_iterate_post_append(ctx_webui *webui, int indx
        , const char *data, size_t datasz)
{

    webui->post_info[indx].key_val = (char*)realloc(
        webui->post_info[indx].key_val
        , webui->post_info[indx].key_sz + datasz + 1);

    memset(webui->post_info[indx].key_val +
        webui->post_info[indx].key_sz, 0, datasz + 1);

    if (datasz > 0) {
        memcpy(webui->post_info[indx].key_val +
            webui->post_info[indx].key_sz, data, datasz);
    }

    webui->post_info[indx].key_sz += datasz;

}

/*Create new entry in the post info structure */
static void webu_iterate_post_new(ctx_webui *webui, const char *key
        , const char *data, size_t datasz)
{
    int retcd;

    webui->post_sz++;
    if (webui->post_sz == 1) {
        webui->post_info = (ctx_key *)malloc(sizeof(ctx_key));
    } else {
        webui->post_info = (ctx_key *)realloc(webui->post_info
            , webui->post_sz * sizeof(ctx_key));
    }

    webui->post_info[webui->post_sz-1].key_nm = (char*)malloc(strlen(key)+1);
    retcd = snprintf(webui->post_info[webui->post_sz-1].key_nm, strlen(key)+1, "%s", key);

    webui->post_info[webui->post_sz-1].key_val = (char*)malloc(datasz+1);
    memset(webui->post_info[webui->post_sz-1].key_val,0,datasz+1);
    if (datasz > 0) {
        memcpy(webui->post_info[webui->post_sz-1].key_val, data, datasz);
    }

    webui->post_info[webui->post_sz-1].key_sz = datasz;

    if (retcd < 0) {
        LOG_MSG(NTC, NO_ERRNO ,"Error processing post data\n");
    }

}

static mhdrslt webu_iterate_post (void *ptr, enum MHD_ValueKind kind
        , const char *key, const char *filename, const char *content_type
        , const char *transfer_encoding, const char *data, uint64_t off, size_t datasz)
{
    (void) kind;
    (void) filename;
    (void) content_type;
    (void) transfer_encoding;
    (void) off;

    ctx_webui *webui = (ctx_webui *)ptr;
    int indx;

    for (indx=0; indx < webui->post_sz; indx++) {
        if (mystreq(webui->post_info[indx].key_nm, key)) {
            break;
        }
    }
    if (indx < webui->post_sz) {
        webu_iterate_post_append(webui, indx, data, datasz);
    } else {
        webu_iterate_post_new(webui, key, data, datasz);
    }

    return MHD_YES;
}

/* Answer the get request from the user */
static mhdrslt webu_answer_get(ctx_webui *webui)
{
    mhdrslt retcd;

    LOG_MSG(DBG, NO_ERRNO ,"processing get");

    retcd = MHD_NO;
    if ((webui->uri_cmd0 == "json")) {
        webu_json_config(webui);
        if (webui->resp_page == "") {
            webu_html_badreq(webui);
        }
        retcd = webu_mhd_send(webui);
        if (retcd == MHD_NO) {
            LOG_MSG(NTC, NO_ERRNO ,"send page failed.");
        }

    } else {
        if (webui->app->conf->webcontrol_interface == "user") {
            webu_html_user(webui);
        } else {
            webu_html_page(webui);
        }

        retcd = webu_mhd_send(webui);
        if (retcd == MHD_NO) {
            LOG_MSG(NTC, NO_ERRNO ,"send page failed.");
        }
    }
    return retcd;
}

/* Answer the connection request for the webcontrol*/
static mhdrslt webu_answer(void *cls, struct MHD_Connection *connection, const char *url
        , const char *method, const char *version, const char *upload_data, size_t *upload_data_size
        , void **ptr)
{
    (void)cls;
    (void)url;
    (void)version;
    (void)upload_data;
    (void)upload_data_size;
    (void)method;

    mhdrslt retcd;
    ctx_webui *webui =(ctx_webui *) *ptr;

    webui->cnct_type = WEBUI_CNCT_CONTROL;
    webui->connection = connection;

    /* Throw bad URLS back to user*/
    if (webui->url.length() == 0) {
        webu_html_badreq(webui);
        retcd = webu_mhd_send(webui);
        return retcd;
    }

    if (webui->app->webcontrol_finish == true) {
        LOG_MSG(NTC, NO_ERRNO ,"Shutting down");
        return MHD_NO;
    }

    if (webui->clientip.length() == 0) {
        webu_clientip(webui);
    }

    if (webu_failauth_check(webui) == MHD_NO) {
        return MHD_NO;
    }

    webu_hostname(webui);

    if (!webui->authenticated) {
        retcd = webu_mhd_auth(webui);
        if (!webui->authenticated) {
            return retcd;
        }
    }

    webu_client_connect(webui);

    if (webui->mhd_first) {
        webui->mhd_first = false;
        if (mystreq(method,"POST")) {
            webui->post_processor = MHD_create_post_processor (webui->connection
                , WEBUI_POST_BFRSZ, webu_iterate_post, (void *)webui);
            if (webui->post_processor == NULL) {
                return MHD_NO;
            }
            webui->cnct_method = WEBUI_METHOD_POST;
        } else {
            webui->cnct_method = WEBUI_METHOD_GET;
        }
        return MHD_YES;
    }

    if (mystreq(method,"POST")) {
        if (*upload_data_size != 0) {
            retcd = MHD_post_process (webui->post_processor, upload_data, *upload_data_size);
            *upload_data_size = 0;
        } else {
            retcd = webu_answer_post(webui);
        }
    } else {
        retcd = webu_answer_get(webui);
    }

    return retcd;

}

/* Initialize the MHD answer */
static void *webu_mhd_init(void *cls, const char *uri, struct MHD_Connection *connection)
{
    ctx_app *app = (ctx_app *)cls;
    ctx_webui *webui;
    int retcd;

    (void)connection;

    mythreadname_set("wc", 0, NULL);

    webui = new ctx_webui;

    webu_context_init(app, webui);

    webui->mhd_first = true;

    webui->url.assign(uri);

    retcd = webu_parseurl(webui);
    if (retcd != 0) {
        webui->uri_cmd0 = "";
        webui->uri_cmd1 = "";
        webui->uri_cmd2 = "";
        webui->uri_cmd3 = "";
        webui->url = "";
    }

    webu_parms_edit(webui);

    return webui;
}

/* Clean up our variables when the MHD connection closes */
static void webu_mhd_deinit(void *cls, struct MHD_Connection *connection
        , void **con_cls, enum MHD_RequestTerminationCode toe)
{
    ctx_webui *webui =(ctx_webui *) *con_cls;

    (void)connection;
    (void)cls;
    (void)toe;

    if (webui != NULL) {
        LOG_MSG(INF, NO_ERRNO ,"Closing connection");
        webu_context_free(webui);
    }

    return;
}

/* Validate that the MHD version installed can process basic authentication */
static void webu_mhd_features_basic(ctx_mhdstart *mhdst)
{
    #if MHD_VERSION < 0x00094400
        (void)mhdst;
    #else
        mhdrslt retcd;
        retcd = MHD_is_feature_supported (MHD_FEATURE_BASIC_AUTH);
        if (retcd == MHD_YES) {
            LOG_MSG(DBG, NO_ERRNO ,"Basic authentication: available");
        } else {
            if (mhdst->app->conf->webcontrol_auth_method == "basic") {
                LOG_MSG(NTC, NO_ERRNO ,"Basic authentication: disabled");
                mhdst->app->conf->webcontrol_auth_method = "none";
            } else {
                LOG_MSG(INF, NO_ERRNO ,"Basic authentication: disabled");
            }
        }
    #endif
}

/* Validate that the MHD version installed can process digest authentication */
static void webu_mhd_features_digest(ctx_mhdstart *mhdst)
{
    #if MHD_VERSION < 0x00094400
        (void)mhdst;
    #else
        mhdrslt retcd;
        retcd = MHD_is_feature_supported (MHD_FEATURE_DIGEST_AUTH);
        if (retcd == MHD_YES) {
            LOG_MSG(DBG, NO_ERRNO ,"Digest authentication: available");
        } else {
            if (mhdst->app->conf->webcontrol_auth_method == "digest") {
                LOG_MSG(NTC, NO_ERRNO ,"Digest authentication: disabled");
                mhdst->app->conf->webcontrol_auth_method = "none";
            } else {
                LOG_MSG(INF, NO_ERRNO ,"Digest authentication: disabled");
            }
        }
    #endif
}

/* Validate that the MHD version installed can process IPV6 */
static void webu_mhd_features_ipv6(ctx_mhdstart *mhdst)
{
    #if MHD_VERSION < 0x00094400
        if (mhdst->ipv6) {
            LOG_MSG(INF, NO_ERRNO ,"libmicrohttpd libary too old ipv6 disabled");
            if (mhdst->ipv6) {
                mhdst->ipv6 = 0;
            }
        }
    #else
        mhdrslt retcd;
        retcd = MHD_is_feature_supported (MHD_FEATURE_IPv6);
        if (retcd == MHD_YES) {
            LOG_MSG(DBG, NO_ERRNO ,"IPV6: available");
        } else {
            LOG_MSG(NTC, NO_ERRNO ,"IPV6: disabled");
            if (mhdst->ipv6) {
                mhdst->ipv6 = 0;
            }
        }
    #endif
}

/* Validate that the MHD version installed can process tls */
static void webu_mhd_features_tls(ctx_mhdstart *mhdst)
{
    #if MHD_VERSION < 0x00094400
        if (mhdst->tls_use) {
            LOG_MSG(INF, NO_ERRNO ,"libmicrohttpd libary too old SSL/TLS disabled");
            mhdst->tls_use = false;
        }
    #else
        mhdrslt retcd;
        retcd = MHD_is_feature_supported (MHD_FEATURE_SSL);
        if (retcd == MHD_YES) {
            LOG_MSG(DBG, NO_ERRNO ,"SSL/TLS: available");
        } else {
            if (mhdst->tls_use) {
                LOG_MSG(NTC, NO_ERRNO ,"SSL/TLS: disabled");
                mhdst->tls_use = false;
            } else {
                LOG_MSG(INF, NO_ERRNO ,"SSL/TLS: disabled");
            }
        }
    #endif
}

/* Validate the features that MHD can support */
static void webu_mhd_features(ctx_mhdstart *mhdst)
{
    webu_mhd_features_basic(mhdst);

    webu_mhd_features_digest(mhdst);

    webu_mhd_features_ipv6(mhdst);

    webu_mhd_features_tls(mhdst);

}

/* Load a either the key or cert file for MHD*/
static std::string webu_mhd_loadfile(std::string fname)
{
    /* This needs conversion to c++ stream */
    FILE        *infile;
    size_t      file_size, read_size;
    char        *file_char;
    std::string filestr;

    filestr = "";
    if (fname != "") {
        infile = myfopen(fname.c_str() , "rbe");
        if (infile != NULL) {
            fseek(infile, 0, SEEK_END);
            file_size = ftell(infile);
            if (file_size > 0 ) {
                file_char = (char*)mymalloc(file_size +1);
                fseek(infile, 0, SEEK_SET);
                read_size = fread(file_char, file_size, 1, infile);
                if (read_size > 0 ) {
                    file_char[file_size] = 0;
                    filestr.assign(file_char, file_size);
                } else {
                    LOG_MSG(ERR, NO_ERRNO
                        ,"Error reading file for SSL/TLS support.");
                }
                free(file_char);
            }
            myfclose(infile);
        }
    }
    return filestr;

}

/* Validate that we have the files needed for tls*/
static void webu_mhd_checktls(ctx_mhdstart *mhdst)
{

    if (mhdst->tls_use) {
        if ((mhdst->app->conf->webcontrol_cert == "") || (mhdst->tls_cert == "")) {
            LOG_MSG(NTC, NO_ERRNO
                ,"SSL/TLS requested but no cert file provided.  SSL/TLS disabled");
            mhdst->tls_use = false;
        }
        if ((mhdst->app->conf->webcontrol_key == "") || (mhdst->tls_key == "")) {
            LOG_MSG(NTC, NO_ERRNO
                ,"SSL/TLS requested but no key file provided.  SSL/TLS disabled");
            mhdst->tls_use = false;
        }
    }

}

/* Set the initialization function for MHD to call upon getting a connection */
static void webu_mhd_opts_init(ctx_mhdstart *mhdst)
{
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_URI_LOG_CALLBACK;
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = (intptr_t)webu_mhd_init;
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = mhdst->app;
    mhdst->mhd_opt_nbr++;
}

/* Set the MHD option on the function to call when the connection closes */
static void webu_mhd_opts_deinit(ctx_mhdstart *mhdst)
{
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_NOTIFY_COMPLETED;
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = (intptr_t)webu_mhd_deinit;
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = NULL;
    mhdst->mhd_opt_nbr++;

}

/* Set the MHD option on acceptable connections */
static void webu_mhd_opts_localhost(ctx_mhdstart *mhdst)
{
    if (mhdst->app->conf->webcontrol_localhost) {
        if (mhdst->ipv6) {
            memset(&mhdst->lpbk_ipv6, 0, sizeof(struct sockaddr_in6));
            mhdst->lpbk_ipv6.sin6_family = AF_INET6;
            mhdst->lpbk_ipv6.sin6_port = htons((uint16_t)mhdst->app->conf->webcontrol_port);
            mhdst->lpbk_ipv6.sin6_addr = in6addr_loopback;

            mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_SOCK_ADDR;
            mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = 0;
            mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = (struct sosockaddr *)(&mhdst->lpbk_ipv6);
            mhdst->mhd_opt_nbr++;

        } else {
            memset(&mhdst->lpbk_ipv4, 0, sizeof(struct sockaddr_in));
            mhdst->lpbk_ipv4.sin_family = AF_INET;
            mhdst->lpbk_ipv4.sin_port = htons((uint16_t)mhdst->app->conf->webcontrol_port);
            mhdst->lpbk_ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

            mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_SOCK_ADDR;
            mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = 0;
            mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = (struct sockaddr *)(&mhdst->lpbk_ipv4);
            mhdst->mhd_opt_nbr++;
        }
    }

}

/* Set the mhd digest options */
static void webu_mhd_opts_digest(ctx_mhdstart *mhdst)
{
    if (mhdst->app->conf->webcontrol_auth_method == "digest") {

        mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_DIGEST_AUTH_RANDOM;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = sizeof(mhdst->app->webcontrol_digest_rand);
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = mhdst->app->webcontrol_digest_rand;
        mhdst->mhd_opt_nbr++;

        mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_NONCE_NC_SIZE;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = 300;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = NULL;
        mhdst->mhd_opt_nbr++;

        mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_CONNECTION_TIMEOUT;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = (unsigned int) 120;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = NULL;
        mhdst->mhd_opt_nbr++;
    }

}

/* Set the MHD options needed when we want TLS connections */
static void webu_mhd_opts_tls(ctx_mhdstart *mhdst)
{
    if (mhdst->tls_use) {

        mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_HTTPS_MEM_CERT;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = 0;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = (void *)mhdst->tls_cert.c_str();
        mhdst->mhd_opt_nbr++;

        mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_HTTPS_MEM_KEY;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = 0;
        mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = (void *)mhdst->tls_key.c_str();
        mhdst->mhd_opt_nbr++;
    }

}

/* Set all the MHD options based upon the configuration parameters*/
static void webu_mhd_opts(ctx_mhdstart *mhdst)
{
    mhdst->mhd_opt_nbr = 0;

    webu_mhd_checktls(mhdst);

    webu_mhd_opts_deinit(mhdst);

    webu_mhd_opts_init(mhdst);

    webu_mhd_opts_localhost(mhdst);

    webu_mhd_opts_digest(mhdst);

    webu_mhd_opts_tls(mhdst);

    mhdst->mhd_ops[mhdst->mhd_opt_nbr].option = MHD_OPTION_END;
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].value = 0;
    mhdst->mhd_ops[mhdst->mhd_opt_nbr].ptr_value = NULL;
    mhdst->mhd_opt_nbr++;

}

/* Set the mhd start up flags */
static void webu_mhd_flags(ctx_mhdstart *mhdst)
{
    mhdst->mhd_flags = MHD_USE_THREAD_PER_CONNECTION;

    if (mhdst->ipv6) {
        mhdst->mhd_flags = mhdst->mhd_flags | MHD_USE_DUAL_STACK;
    }

    if (mhdst->tls_use) {
        mhdst->mhd_flags = mhdst->mhd_flags | MHD_USE_SSL;
    }

}

/* Start the webcontrol */
static void webu_init_webcontrol(ctx_app *app)
{
    ctx_mhdstart mhdst;
    unsigned int randnbr;

    LOG_MSG(NTC, NO_ERRNO
        , "Starting webcontrol on port %d"
        , app->conf->webcontrol_port);

    app->webcontrol_headers.update_params = true;
    util_parms_parse(app->webcontrol_headers,"webu"
        , app->conf->webcontrol_headers);

    mhdst.tls_cert = webu_mhd_loadfile(app->conf->webcontrol_cert);
    mhdst.tls_key  = webu_mhd_loadfile(app->conf->webcontrol_key);
    mhdst.app = app;
    mhdst.ipv6 = app->conf->webcontrol_ipv6;
    mhdst.tls_use = app->conf->webcontrol_tls;

    /* Set the rand number for webcontrol digest if needed */
    srand((unsigned int)time(NULL));
    randnbr = (unsigned int)(42000000.0 * rand() / (RAND_MAX + 1.0));
    snprintf(app->webcontrol_digest_rand
        ,sizeof(app->webcontrol_digest_rand),"%d",randnbr);

    mhdst.mhd_ops =(struct MHD_OptionItem*)mymalloc(sizeof(struct MHD_OptionItem)*WEBUI_MHD_OPTS);
    webu_mhd_features(&mhdst);
    webu_mhd_opts(&mhdst);
    webu_mhd_flags(&mhdst);

    app->webcontrol_daemon = MHD_start_daemon (
        mhdst.mhd_flags
        , (uint16_t)app->conf->webcontrol_port
        , NULL, NULL
        , &webu_answer, app
        , MHD_OPTION_ARRAY, mhdst.mhd_ops
        , MHD_OPTION_END);

    free(mhdst.mhd_ops);
    if (app->webcontrol_daemon == NULL) {
        LOG_MSG(NTC, NO_ERRNO ,"Unable to start MHD");
    } else {
        LOG_MSG(NTC, NO_ERRNO
            ,"Started webcontrol on port %d"
            ,app->conf->webcontrol_port);
    }
    return;
}

/* Shut down the webcontrol */
void webu_deinit(ctx_app *app)
{
    if (app->webcontrol_daemon != NULL) {
        app->webcontrol_finish = true;
        MHD_stop_daemon(app->webcontrol_daemon);
    }
    LOG_MSG(NTC, NO_ERRNO, "Closed webcontrol");
}

/* Start the webcontrol and streams */
void webu_init(ctx_app *app)
{
    struct sigaction act;

    /* We need to block some signals otherwise MHD will not function correctly. */
    /* set signal handlers TO IGNORE */
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);
    sigaction(SIGCHLD, &act, NULL);

    app->webcontrol_daemon = NULL;
    app->webcontrol_finish = false;

     /* Start the webcontrol */
    if (app->conf->webcontrol_port != 0 ) {
        webu_init_webcontrol(app);
    }

    return;

}
