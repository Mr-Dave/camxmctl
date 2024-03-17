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

static void webu_json_config_item(ctx_webui *webui, ctx_config *conf, int indx_parm)
{
    size_t indx;
    std::string parm_orig, parm_val, parm_list, parm_enable;

    parm_orig = "";
    parm_val = "";
    parm_list = "";

    if (webui->app->conf->webcontrol_parms < WEBUI_LEVEL_LIMITED) {
        parm_enable = "false";
    } else {
        parm_enable = "true";
    }

    conf_edit_get(conf, config_parms[indx_parm].parm_name
        , parm_orig, config_parms[indx_parm].parm_cat);

    for (indx = 0; indx < parm_orig.length(); indx++) {
        if ((parm_orig[indx] == '"') ||
            (parm_orig[indx] == '\\')) {
            parm_val += '\\';
        }
        parm_val += parm_orig[indx];
    }

    if (config_parms[indx_parm].parm_type == PARM_TYP_INT) {
        webui->resp_page +=
            "\"" + config_parms[indx_parm].parm_name + "\"" +
            ":{" +
            " \"value\":" + parm_val +
            ",\"enabled\":" + parm_enable +
            ",\"category\":" + std::to_string(config_parms[indx_parm].parm_cat) +
            ",\"type\":\"" + conf_type_desc(config_parms[indx_parm].parm_type) + "\"" +
            "}";

    } else if (config_parms[indx_parm].parm_type == PARM_TYP_BOOL) {
        if (parm_val == "on") {
            webui->resp_page +=
                "\"" + config_parms[indx_parm].parm_name + "\"" +
                ":{" +
                " \"value\":true" +
                ",\"enabled\":" + parm_enable +
                ",\"category\":" + std::to_string(config_parms[indx_parm].parm_cat) +
                ",\"type\":\"" + conf_type_desc(config_parms[indx_parm].parm_type) + "\""+
                "}";
        } else {
            webui->resp_page +=
                "\"" + config_parms[indx_parm].parm_name + "\"" +
                ":{" +
                " \"value\":false" +
                ",\"enabled\":" + parm_enable +
                ",\"category\":" + std::to_string(config_parms[indx_parm].parm_cat) +
                ",\"type\":\"" + conf_type_desc(config_parms[indx_parm].parm_type) + "\"" +
                "}";
        }
    } else {
        webui->resp_page +=
            "\"" + config_parms[indx_parm].parm_name + "\"" +
            ":{" +
            " \"value\":\"" + parm_val + "\"" +
            ",\"enabled\":" + parm_enable +
            ",\"category\":" + std::to_string(config_parms[indx_parm].parm_cat) +
            ",\"type\":\""+ conf_type_desc(config_parms[indx_parm].parm_type) + "\"" +
            "}";
    }

}

static void webu_json_config_parms(ctx_webui *webui, ctx_config *conf)
{
    int indx_parm;
    bool first;
    std::string response;

    indx_parm = 0;
    first = true;
    while ((config_parms[indx_parm].parm_name != "") ) {
        if ((config_parms[indx_parm].webui_level == WEBUI_LEVEL_NEVER)) {
            indx_parm++;
            continue;
        }
        if (first) {
            first = false;
            webui->resp_page += "{";
        } else {
            webui->resp_page += ",";
        }
        /* Allow limited parameters to be read only to the web page */
        if ((config_parms[indx_parm].webui_level >
                webui->app->conf->webcontrol_parms) &&
            (config_parms[indx_parm].webui_level > WEBUI_LEVEL_LIMITED)) {

            webui->resp_page +=
                "\""+config_parms[indx_parm].parm_name+"\"" +
                ":{" +
                " \"value\":\"\"" +
                ",\"enabled\":false" +
                ",\"category\":" + std::to_string(config_parms[indx_parm].parm_cat) +
                ",\"type\":\""+ conf_type_desc(config_parms[indx_parm].parm_type) + "\"";

            if (config_parms[indx_parm].parm_type == PARM_TYP_LIST) {
                webui->resp_page += ",\"list\":[\"na\"]";
            }
            webui->resp_page +="}";
        } else {
           webu_json_config_item(webui, conf, indx_parm);
        }
        indx_parm++;
    }
    webui->resp_page += "}";

}

static void webu_json_config_cam_parms(ctx_webui *webui)
{
    webui->resp_page += "{";
    webui->resp_page += "\"default\": ";
    webu_json_config_parms(webui, webui->app->conf);
    webui->resp_page += "}";

    return;
}

static void webu_json_config_cam_list(ctx_webui *webui)
{
    std::string response;
    std::string strid;

    webui->resp_page += "{\"count\" : 1";

    webui->resp_page += "}";

    return;
}

static void webu_json_config_categories(ctx_webui *webui)
{
    int indx_cat;
    std::string catnm_short, catnm_long;

    webui->resp_page += "{";

    indx_cat = 0;
    while (indx_cat != PARM_CAT_MAX) {
        if (indx_cat != 0) {
            webui->resp_page += ",";
        }
        webui->resp_page += "\"" + std::to_string(indx_cat) + "\": ";

        catnm_long = conf_cat_desc((enum PARM_CAT)indx_cat, false);
        catnm_short = conf_cat_desc((enum PARM_CAT)indx_cat, true);

        webui->resp_page += "{\"name\":\"" + catnm_short + "\",\"display\":\"" + catnm_long + "\"}";

        indx_cat++;
    }

    webui->resp_page += "}";

    return;

}

void webu_json_config_camxmctl(ctx_webui *webui)
{
    webui->resp_page += "{\"version\" : \" 0.1\"";

    webui->resp_page += ",\"cameras\" : ";
    webu_json_config_cam_list(webui);

    webui->resp_page += ",\"configuration\" : ";
    webu_json_config_cam_parms(webui);

    webui->resp_page += ",\"categories\" : ";
    webu_json_config_categories(webui);

    webui->resp_page += "}";

}

void webu_json_config(ctx_webui *webui)
{
    webui->resp_type = WEBUI_RESP_JSON;
    webui->resp_page = "";

    if (webui->uri_cmd1 == "all") {
        webui->app->status_msg = "";
        camctl_config_get_all(webui->app);
        webui->resp_page = webui->app->caminfo.val_out;

    } else if (webui->uri_cmd1 == "status") {
        webui->resp_page += "{\"status\" : \"";
        webui->resp_page += webui->app->status_msg;
        webui->resp_page += "\"}";

    } else if (webui->uri_cmd1 == "config") {
        webu_json_config_camxmctl(webui);

    } else {
        camctl_config_get_jstr(webui->app, webui->uri_cmd1);
        webui->resp_page = webui->app->caminfo.val_out;
    }
}


