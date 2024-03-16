/*   This file is part of camxmctl.
 *
 *   camxmctl is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   camxmctl is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with camxmctl.  If not, see <https://www.gnu.org/licenses/>.
 */


#include "camxmctl.hpp"
#include "util.hpp"
#include "logger.hpp"
#include "conf.hpp"
#include "webu.hpp"
#include "webu_json.hpp"

bool finish;

ctx_retcd cam_retcds[] = {
    {100 , "OK"},
    {101 , "unknown mistake"},
    {102 , "Version not supported"},
    {103 , "Illegal request"},
    {104 , "The user has logged in"},
    {105 , "The user is not logged in"},
    {106 , "username or password is wrong"},
    {107 , "No permission"},
    {108 , "time out"},
    {109 , "Failed to find no corresponding file found"},
    {110 , "Find successful, return all files"},
    {111 , "Find success, return some files"},
    {112 , "This user already exists"},
    {113 , "this user does not exist"},
    {114 , "This user group already exists"},
    {115 , "This user group does not exist"},
    {116 , "Error 116"},
    {117 , "Wrong message format"},
    {118 , "PTZ protocol not set"},
    {119 , "No query to file"},
    {120 , "Configure to enable"},
    {121 , "MEDIA_CHN_NOT CONNECT digital channel is not connected"},
    {150 , "Successful, the device needs to be restarted"},
    {202 , "User not logged in"},
    {203 , "The password is incorrect"},
    {204 , "User illegal"},
    {205 , "User is locked"},
    {206 , "User is on the blacklist"},
    {207 , "Username is already logged in"},
    {208 , "Input is illegal"},
    {209 , "The index is repeated if the user to be added already exists, etc."},
    {210 , "No object exists, used when querying"},
    {211 , "Object does not exist"},
    {212 , "Account is in use"},
    {213 , "The subset is out of scope (such as the group's permissions exceed the permission table, the user permissions exceed the group permission range, etc."},
    {214 , "The password is illegal"},
    {215 , "Passwords do not match"},
    {216 , "Retain account"},
    {502 , "The command is illegal"},
    {503 , "Intercom has been turned on"},
    {504 , "Intercom is not turned on"},
    {511 , "Already started upgrading"},
    {512 , "Not starting upgrade"},
    {513 , "Upgrade data error"},
    {514 , "upgrade unsuccessful"},
    {515 , "update successed"},
    {521 , "Restore default failed"},
    {522 , "Need to restart the device"},
    {523 , "Illegal default configuration"},
    {602 , "Need to restart the app"},
    {603 , "Need to restart the system"},
    {604 , "Error writing a file"},
    {605 , "Feature not supported"},
    {606 , "verification failed"},
    {607 , "Configuration does not exist"},
    {608 , "Configuration parsing error"},
    {-999, NULL}
};

static void signal_handler(int signo)
{
    switch(signo) {
    case SIGALRM:
        LOG_MSG(INF, NO_ERRNO,"Caught alarm signal.");
        break;
    case SIGINT:
        LOG_MSG(INF, NO_ERRNO, "Caught interrupt signal.");
        finish = true;
        break;
    case SIGABRT:
        LOG_MSG(INF, NO_ERRNO, "Caught abort signal.");
        break;
    case SIGHUP:
        LOG_MSG(INF, NO_ERRNO, "Caught hup signal.");
        break;
    case SIGQUIT:
        LOG_MSG(INF, NO_ERRNO, "Caught quit signal.");
        break;
    case SIGIO:
        LOG_MSG(INF, NO_ERRNO, "Caught IO signal.");
        break;
    case SIGTERM:
        LOG_MSG(INF, NO_ERRNO, "Caught term signal.");
        break;
    case SIGPIPE:
        LOG_MSG(INF, NO_ERRNO, "Caught pipe signal.");
        break;
    case SIGVTALRM:
        LOG_MSG(INF, NO_ERRNO, "Caught alarm signal.");
        break;
    }
}

static void signal_setup()
{
    if (signal(SIGPIPE, signal_handler) == SIG_ERR) {
        LOG_MSG(INF, NO_ERRNO, "Can not catch pipe signal.");
    }
    if (signal(SIGALRM, signal_handler) == SIG_ERR) {
        LOG_MSG(INF, NO_ERRNO, "Can not catch alarm signal.");
    }
    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        LOG_MSG(INF, NO_ERRNO, "Can not catch term signal.");
    }
    if (signal(SIGQUIT, signal_handler) == SIG_ERR) {
        LOG_MSG(INF, NO_ERRNO, "Can not catch quit signal.");
    }
    if (signal(SIGHUP, signal_handler) == SIG_ERR) {
        LOG_MSG(INF, NO_ERRNO, "Can not catch hup signal.");
    }
    if (signal(SIGABRT, signal_handler) == SIG_ERR) {
        LOG_MSG(INF, NO_ERRNO, "Can not catch abort signal.");
    }
    if (signal(SIGVTALRM, signal_handler) == SIG_ERR) {
        LOG_MSG(INF, NO_ERRNO, "Can not catch VTalarm");
    }
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        LOG_MSG(INF, NO_ERRNO, "Can not catch VTalarm");
    }
}

static int camctl_socket_open(ctx_app *app)
{
    int retcd;
    struct sockaddr_in cam_addr;
    struct timeval timeout;

    app->caminfo.cnct.sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (app->caminfo.cnct.sockfd < 0)  {
        LOG_MSG(INF, NO_ERRNO,"Socket creation error");
        return -1;
    }

    LOG_MSG(INF, NO_ERRNO, "IP %s Port val %d Port string %s"
        , app->caminfo.ip.c_str(), atoi(app->caminfo.port.c_str())
        ,app->caminfo.port.c_str());

    cam_addr.sin_family = AF_INET;
    cam_addr.sin_port = htons(atoi(app->caminfo.port.c_str()));

    // Convert IPv4 and IPv6 addresses from text to binary form
    retcd = inet_pton(AF_INET, app->caminfo.ip.c_str(), &cam_addr.sin_addr);
    if(retcd <=0 ) {
        LOG_MSG(INF, NO_ERRNO, "Invalid IP address");
        return -1;
    }
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    retcd = setsockopt(app->caminfo.cnct.sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    if (retcd < 0 ) {
        LOG_MSG(INF, NO_ERRNO, "Error setting timeout rcv %d", retcd);
        return -1;
    }

    retcd = setsockopt(app->caminfo.cnct.sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
    if (retcd < 0 ) {
        LOG_MSG(INF, NO_ERRNO,"\nError setting timeout snd %d", retcd);
        return -1;
    }

    retcd = connect(app->caminfo.cnct.sockfd, (struct sockaddr *)&cam_addr, sizeof(cam_addr));
    if (retcd < 0) {
        LOG_MSG(INF, NO_ERRNO,"Connection Failed %d", retcd);
        return -1;
    }

    LOG_MSG(INF, NO_ERRNO, "Connected");

    return 0;
}

void camctl_socket_read(ctx_app *app)
{
    struct ctx_msgresp  resp;
    char buffer_out[1024];
    ssize_t bytes_read, nbytes;

    memset(buffer_out, 0, 1024);
    bytes_read = read(app->caminfo.cnct.sockfd, buffer_out, 1024);
    if (bytes_read >= 20) {
        memcpy(&resp, buffer_out, sizeof(struct ctx_msgresp));
        app->caminfo.cnct.sid = resp.msg_sid;
        app->caminfo.cnct.seq = resp.msg_seq;
        app->caminfo.cfg_val += std::string(buffer_out + 20).substr(0, bytes_read - 20);
        nbytes = resp.msg_size + 20 - bytes_read;
        if (nbytes < 0) {
           nbytes = 0;
        }
        while (nbytes > 0) {
            memset(buffer_out, 0, 1024);
            bytes_read = read(app->caminfo.cnct.sockfd, buffer_out, 1024);
            app->caminfo.cfg_val += std::string(buffer_out).substr(0, bytes_read);
            nbytes = nbytes - bytes_read;
        }
        app->status_msg += "Success. ";
    } else {
        LOG_MSG(INF, NO_ERRNO
            ,"Read from socket failed to get 20 bytes: %ld"
            , bytes_read);
        app->status_msg += "Failed. ";
    }
}

void camctl_socket_send(ctx_app *app, short int msgid)
{
    ssize_t bytes_send;
    int msgsz;
    char *buffer;

    msgsz = strlen(app->caminfo.cnct.msg)+1;
    buffer = (char*)mymalloc(msgsz+20);

    memcpy(buffer, "\xff\x00\x00\x00", 4);
    memcpy(buffer + 4, &app->caminfo.cnct.sid, 4);
    memcpy(buffer + 8,"\x00\x00\x00\x00", 4);
    memcpy(buffer + 14, &msgid, 2);
    memcpy(buffer + 16, &msgsz, 4);
    memcpy(buffer + 20, app->caminfo.cnct.msg, msgsz);
    bytes_send = send(app->caminfo.cnct.sockfd, buffer, msgsz+20, 0);
    if (bytes_send != (msgsz+20)) {
        LOG_MSG(ERR, NO_ERRNO
            , "Failed to send all bytes: Retcd: %d Sz: %d msg: %s"
            ,bytes_send, msgsz+20, buffer);
    }
    /*
    int indx;
    for (indx=0;indx<30;indx++){
        LOG_MSG(INF, NO_ERRNO,"buffer: %04x %s",&buffer+indx,&buffer+indx);
    }
    LOG_MSG(INF, NO_ERRNO,"buf %s",&buffer+20);
    LOG_MSG(INF, NO_ERRNO,"msg: %s",app->caminfo.cnct.msg);
    free(buffer);
    */
}

static void camctl_prepare_md5(ctx_app *app)
{
    MD5_CTX mdctx;
    int indx;
    unsigned char digest[16];
    char onebyte;

    memset(app->caminfo.cnct.hash, 0, sizeof(app->caminfo.cnct.hash));

    MD5_Init(&mdctx);
    MD5_Update(&mdctx, app->caminfo.pwd.c_str(), app->caminfo.pwd.length());
    MD5_Final(digest, &mdctx);

    for (indx = 0 ; indx < 8 ; indx++ ) {
        onebyte = (digest[ (indx * 2) ] + digest[ (indx *2) + 1 ] ) % 0x3e;
        if (onebyte < 10) {
            onebyte += 48;
        } else if (onebyte < 36) {
            onebyte += 55;
        } else {
            onebyte += 61;
        }
        app->caminfo.cnct.hash[indx] = onebyte;
    }

}

void camctl_logout(ctx_app *app)
{
    if (app->caminfo.cnct.sid == 0) {
        return;
    }

    app->status_msg += " Logout:";

    camctl_prepare_md5(app);

    app->caminfo.cnct.msg = (char*)mymalloc(1024);
        snprintf(app->caminfo.cnct.msg, 1024
            ,"{\"LoginType\"   : \"camxmctl\" "
            ",\"PassWord\"    : \"%s\" "
            ",\"UserName\"    : \"%s\" "
            ",\"EncryptType\" : \"MD5\" }"
            , app->caminfo.cnct.hash
            , app->caminfo.user.c_str());
        camctl_socket_send(app, LOGOUT_REQ);
    myfree(&app->caminfo.cnct.msg);
    close(app->caminfo.cnct.sockfd);

    app->caminfo.cnct.sockfd = 0;
    app->caminfo.cnct.sid = 0;
    app->caminfo.cnct.seq = 0;

    LOG_MSG(INF, NO_ERRNO,"logged out");
    app->status_msg += "Success";

}

void camctl_login_default(ctx_app *app)
{
    if (app->caminfo.ip == "") {
        app->caminfo.ip = "10.0.0.67";
        app->caminfo.user = "admin";
        app->caminfo.port = "34567";
    }

}

void camctl_login(ctx_app *app)
{
    int retcd;

    if (app->caminfo.cnct.sid != 0) {
        return;
    }

    app->status_msg += " Login:";

    camctl_login_default(app);

    retcd = camctl_socket_open(app);
    if (retcd != 0) {
        app->status_msg += " Failed";
        app->caminfo.cnct.sid = 0;
        app->caminfo.cnct.seq = 0;
        LOG_MSG(INF, NO_ERRNO,"Login failed");
        return;
    }

    camctl_prepare_md5(app);

    app->caminfo.cnct.msg = (char*)mymalloc(1024);
        snprintf(app->caminfo.cnct.msg, 1024
            ,"{\"LoginType\":\"camxmctl\" "
            ",\"PassWord\":\"%s\" "
            ",\"UserName\":\"%s\" "
            ",\"EncryptType\":\"MD5\" }"
            , app->caminfo.cnct.hash
            , app->caminfo.user.c_str());
        camctl_socket_send(app, LOGIN_REQ2);
    myfree(&app->caminfo.cnct.msg);

    camctl_socket_read(app);

    if (app->caminfo.cnct.sid == 0) {
        LOG_MSG(INF, NO_ERRNO,"Login failed");
        app->status_msg += "Failed.";
    } else {
        LOG_MSG(INF, NO_ERRNO,"Logged in");
        app->status_msg += "Success.";
    }
}

void camctl_cmd_send(ctx_app *app, const char *cmd, const char *subcmd)
{
    app->status_msg += "Command: " + std::string(cmd);

    if (app->caminfo.cnct.sid == 0) {
        camctl_login(app);
        if (app->caminfo.cnct.sid == 0) {
            LOG_MSG(INF, NO_ERRNO,"Login failed");
            app->status_msg += " Failed";
            return;
       }
    }

    app->caminfo.cnct.msg = (char*)mymalloc(1024);
    if (mystreq(cmd,"reboot") ) {
        snprintf(app->caminfo.cnct.msg, 1024
            ,"{\"Name\":\"OPMachine\",\"SessionID\":\"%08x\" "
             ",\"OPMachine\":{\"Action\":\"Reboot\"} }"
            ,app->caminfo.cnct.sid);
        camctl_socket_send(app, SYSMANAGER_REQ);
        camctl_socket_read(app);
    } else if (mystreq(cmd,"Config") ) {
        snprintf(app->caminfo.cnct.msg, 1024
            ,"{\"Name\": \"%s\",\" SessionID\":\"%08x\" } "
            ,subcmd, app->caminfo.cnct.sid);
        if (mystreq(subcmd,"SystemInfo") ) {
            camctl_socket_send(app, SYSINFO_REQ);
        } else {
            camctl_socket_send(app, CONFIG_GET);
        }
        camctl_socket_read(app);
    }
    myfree(&app->caminfo.cnct.msg);

}

void camctl_cmd_ptz(ctx_app *app)
{
    std::string parms;
    struct timespec slp;

    if (app->caminfo.cnct.sid == 0) {
        camctl_login(app);
        if (app->caminfo.cnct.sid == 0) {
            app->status_msg += " Failed";
            return;
       }
    }

    app->status_msg += "Command: PTZ";

    parms =  ",\"Parameter\":";
    parms += "{\"MenuOpts\":\"Enter\"";
    parms += ",\"Pattern\":\"SetBegin\"";
    parms += ",\"Tour\":0,\"Step\":5,\"Channel\":0";
    parms += ",\"AUX\":{\"Status\":\"On\",\"Number\":0}";
    parms += ",\"POINT\":{\"left\":0,\"right\":0,\"top\":0,\"bottom\":0}";

    app->caminfo.cnct.msg = (char*)mymalloc(1024);

    snprintf(app->caminfo.cnct.msg, 1024
        ,"{\"Name\":\"OPPTZControl\",\"SessionID\":\"%08x\""
        ",\"OPPTZControl\":{\"Command\":\"%s\"%s"
        ",\"Preset\":65535}}}"
        , app->caminfo.cnct.sid
        , app->caminfo.ptz_action.c_str()
        , parms.c_str());
    camctl_socket_send(app, PTZ_REQ);
    camctl_socket_read(app);

    slp.tv_sec = atoi(app->caminfo.ptz_duration.c_str());
    slp.tv_nsec= (atof(app->caminfo.ptz_duration.c_str())-slp.tv_sec)*1000000000L;
    SLEEP(slp.tv_sec, slp.tv_nsec);

    snprintf(app->caminfo.cnct.msg, 1024
        ,"{\"Name\":\"OPPTZControl\",\"SessionID\":\"%08x\""
        ",\"OPPTZControl\":{\"Command\":\"%s\"%s"
        ",\"Preset\":-1}}}"
        , app->caminfo.cnct.sid
        , app->caminfo.ptz_action.c_str()
        , parms.c_str());
    camctl_socket_send(app, PTZ_REQ);
    camctl_socket_read(app);

    myfree(&app->caminfo.cnct.msg);

    /* Sample
    { "SessionID":"0x00000002"
     ,"Name":"OPPTZControl"
     ,"OPPTZControl":
       {"Command":"DirectionUp"
       ,"Parameter":{
          "MenuOpts":"Enter"
         ,"Pattern":"SetBegin"
         ,"Tour":0,"Step":5,"Channel":0
         ,"AUX":{"Status":"On","Number":0}
         ,"POINT":{"left":0,"top":0,"right":0,"bottom":0}
         ,"Preset":-1
         }}}
    {"SessionID":"0x00000002"
    ,"Name":"OPPTZControl"
    ,"OPPTZControl":
      {"Command":"DirectionUp"
      ,"Parameter":{
        "MenuOpts":"Enter"
       ,"Pattern":"SetBegin"
       ,"Tour":0,"Step":5,"Channel":0
       ,"AUX":{"Number":0,"Status":"On"}
       ,"POINT":{"bottom":0,"right":0,"top":0,"left":0}
       ,"Preset":65535
       }}}

    {"SessionID":"0x00000001"
     ,"Name":"OPPTZControl"
     ,"OPPTZControl":
      {"Command":"ZoomTile"
       ,"Parameter":{
        ,"MenuOpts":"Enter"
        ,"Pattern":"SetBegin"
        ,"Tour":0,"Step":5,"Channel":0
        ,"AUX":{"Number":0,"Status":"On"}
        ,"POINT":{"top":0,"bottom":0,"left":0,"right":0}
        ,"Preset":-1}
    }}
    */

}

void camctl_config_get_all(ctx_app *app)
{
    if (app->caminfo.cnct.sid == 0) {
        std::ifstream ifs;
        std::string line;
        app->caminfo.cfg_val  = "";
        ifs.open("/home/dave/source/camxmctl/all.json");
            while (std::getline(ifs, line)) {
                mytrim(line);
                app->caminfo.cfg_val += line;
            }
        ifs.close();
        LOG_MSG(INF, NO_ERRNO,"Using the test file");

        return;
    }

    camctl_login(app);

    app->caminfo.cfg_val = "";

    app->caminfo.cfg_val += "{\"SystemInfo\" :"; camctl_cmd_send(app,"Config","SystemInfo");

    app->caminfo.cfg_val += ",\"Alarm\" :"; camctl_cmd_send(app,"Config","Alarm");
    app->caminfo.cfg_val += ",\"AVEnc\" :"; camctl_cmd_send(app,"Config","AVEnc");
    app->caminfo.cfg_val += ",\"Camera\" :";camctl_cmd_send(app,"Config","Camera");
    app->caminfo.cfg_val += ",\"Detect\" :";camctl_cmd_send(app,"Config","Detect");
    app->caminfo.cfg_val += ",\"fVideo\" :";camctl_cmd_send(app,"Config","fVideo");
    app->caminfo.cfg_val += ",\"General\" :";camctl_cmd_send(app,"Config","General");
    app->caminfo.cfg_val += ",\"IPAdaptive\" :";camctl_cmd_send(app,"Config","IPAdaptive");
    app->caminfo.cfg_val += ",\"NetWork\" :";camctl_cmd_send(app,"Config","NetWork");
    app->caminfo.cfg_val += ",\"Storage\" :";camctl_cmd_send(app,"Config","Storage");
    app->caminfo.cfg_val += ",\"StorageGlobal\" :";camctl_cmd_send(app,"Config","StorageGlobal");
    app->caminfo.cfg_val += ",\"System\" :";camctl_cmd_send(app,"Config","System");
    app->caminfo.cfg_val += ",\"Uart\" :";camctl_cmd_send(app,"Config","Uart");

    app->caminfo.cfg_val += "}";

    camctl_logout(app);

}

void camctl_config_get_jstr(ctx_app *app, std::string jstr)
{
    camctl_login(app);
    app->caminfo.cfg_val = "{";
    app->caminfo.cfg_val += "\""+jstr+"\" :"; camctl_cmd_send(app,"Config",jstr.c_str());
    app->caminfo.cfg_val += "}";
    camctl_logout(app);
}

void camctl_config_set(ctx_app *app)
{
    ssize_t bufflen;

    camctl_login(app);

    LOG_MSG(INF, NO_ERRNO,"msg length %d",app->caminfo.cfg_val.length());

    app->status_msg += "Set Config: ";

    bufflen = app->caminfo.cfg_nm.length() +
        app->caminfo.cfg_nm.length() +
        app->caminfo.cfg_val.length() + 45;

    app->caminfo.cnct.msg = (char*)mymalloc(bufflen);
        snprintf(app->caminfo.cnct.msg, bufflen
            ,"{\"Name\": \"%s\",\"%s\" : %s ,\" SessionID\" : \" %08x \" } "
            , app->caminfo.cfg_nm.c_str()
            , app->caminfo.cfg_nm.c_str()
            , app->caminfo.cfg_val.c_str()
            , app->caminfo.cnct.sid);
        camctl_socket_send(app, CONFIG_SET);
    myfree(&app->caminfo.cnct.msg);

    camctl_socket_read(app);

    camctl_logout(app);

}

int main(int argc, char **argv)
{
    std::string parameter_file;
    ctx_app *app;

    finish = false;

    app = new ctx_app;
    app->argc = argc;
    app->argv = argv;
    app->conf = new ctx_config;
    app->caminfo.pwd = "";
    app->caminfo.user = "";
    app->caminfo.ip = "";

    signal_setup();
    conf_init(app);
    log_init(app);
    conf_parms_log(app);
    webu_init(app);

    while (finish == false){
        SLEEP(1,0);
    }

    app->webcontrol_finish = true;

    LOG_MSG(NTC, NO_ERRNO,"Exiting");

    webu_deinit(app);

    delete app->conf;
    delete app;

    return 0;

}








/*
void hold_cmd_send(ctx_app *app)
{
    struct ctx_msgsend  msgsend;
    char buffer_in[1024];

    app->status_msg += " Logout:";

    camctl_prepare_md5(app);

    snprintf(buffer_in, 1024
        ,"{\"LoginType\"   : \"camxmctl\" "
         ",\"PassWord\"    : \"%s\" "
         ",\"UserName\"    : \"%s\" "
         ",\"EncryptType\" : \"MD5\" }"
         , app->caminfo.cnct.hash
         , app->caminfo.user.c_str());

    msgsend.msg_id = LOGOUT_REQ;
    msgsend.sid = app->caminfo.cnct.sid;
    msgsend.buffer = (char*)mymalloc(strlen(buffer_in) + 21);
        camctl_prepare_message(&msgsend, buffer_in);
        send(app->caminfo.cnct.sockfd
            , msgsend.buffer, msgsend.msg_size, 0 );
    free(msgsend.buffer);
    close(app->caminfo.cnct.sockfd);

    app->caminfo.cnct.sockfd = 0;
    app->caminfo.cnct.sid = 0;
    app->caminfo.cnct.seq = 0;

    LOG_MSG(INF, NO_ERRNO,"logged out");
    app->status_msg += "Success";

}

void hold_logout(ctx_app *app)
{
    struct ctx_msgsend  msgsend;
    char buffer_in[1024];

    app->status_msg += " Logout:";

    camctl_prepare_md5(app);

    snprintf(buffer_in, 1024
        ,"{\"LoginType\"   : \"camxmctl\" "
         ",\"PassWord\"    : \"%s\" "
         ",\"UserName\"    : \"%s\" "
         ",\"EncryptType\" : \"MD5\" }"
         , app->caminfo.cnct.hash
         , app->caminfo.user.c_str());

    msgsend.msg_id = LOGOUT_REQ;
    msgsend.sid = app->caminfo.cnct.sid;
    msgsend.buffer = (char*)mymalloc(strlen(buffer_in) + 21);
        camctl_prepare_message(&msgsend, buffer_in);
        send(app->caminfo.cnct.sockfd
            , msgsend.buffer, msgsend.msg_size, 0 );
    free(msgsend.buffer);
    close(app->caminfo.cnct.sockfd);

    app->caminfo.cnct.sockfd = 0;
    app->caminfo.cnct.sid = 0;
    app->caminfo.cnct.seq = 0;

    LOG_MSG(INF, NO_ERRNO,"logged out");
    app->status_msg += "Success";

}
static void camctl_config_write(ctx_app *app)
{
  std::ofstream cfgfile;

  cfgfile.open ("sample.json");
  cfgfile << app->caminfo.cfg_val;
  cfgfile.close();

}

static void camctl_config_export(ctx_app *app)
{
    struct ctx_msgsend  msgsend;
    struct ctx_msgresp  resp;
    ssize_t sbytes;
    char buffer_in[1024] = {0};
    char buffer_out[1024] = {0};

    snprintf(buffer_in, 1024,"{\"Name\": \"\", } ");

    msgsend.msg_id = CONFIG_EXPORT_REQ;
    camctl_prepare_message(&msgsend, buffer_in);
    sbytes = send(app->caminfo.cnct.sockfd, msgsend.buffer, msgsend.msg_size, 0 );

    sbytes = read(app->caminfo.cnct.sockfd, buffer_out, 1024);
    if (sbytes >= 20) {
        printf(" command sbytes read =%ld\n", sbytes);
        memcpy(&resp, buffer_out, sizeof(struct ctx_msgresp));
        LOG_MSG(INF, NO_ERRNO
            ," head=%d version=%d sid=%d seq=%d"
             " channel=%d endflag=%d msgid=%d msgsz=%d"
            , resp.msg_head
            , resp.msg_version
            , resp.msg_sid
            , resp.msg_seq
            , resp.msg_channel
            , resp.msg_endflag
            , resp.msg_id
            , resp.msg_size
            );
        // This function returns a zip file.   Need to continue to read from the socket and write it
        // to a file somewhere so that it can be opened externally to this application
    } else {
        LOG_MSG(INF, NO_ERRNO, "Read from socket failed =%ld", sbytes);
    }

}
static void camctl_config_print(ctx_app *app)
{
    struct ctx_msgsend  msgsend;
    struct ctx_msgresp  resp;
    ssize_t sbytes;
    char buffer_in[1024] = {0};
    char buffer_out[2048] = {0};

    snprintf(buffer_in, 1024, "{\"SessionID\" : \"0x%08x\" "
        ",\"Name\": \"%s\"  } "
        , app->caminfo.cnct.sid, "opt");

    msgsend.msg_id = CONFIG_GET;
    camctl_prepare_message(&msgsend, buffer_in);

    sbytes = send(app->caminfo.cnct.sockfd, msgsend.buffer, msgsend.msg_size, 0);

    sbytes = read(app->caminfo.cnct.sockfd, buffer_out, 2048);
    if (sbytes >= 20) {
        LOG_MSG(INF, NO_ERRNO,"command sbytes read =%ld", sbytes);
        memcpy(&resp, buffer_out, sizeof(struct ctx_msgresp));
        LOG_MSG(INF, NO_ERRNO
            ," head=%d version=%d sid=%d seq=%d channel=%d"
             " endflag=%d msgid=%d msgsz=%d\n"
            , resp.msg_head
            , resp.msg_version
            , resp.msg_sid
            , resp.msg_seq
            , resp.msg_channel
            , resp.msg_endflag
            , resp.msg_id
            , resp.msg_size
            );
        LOG_MSG(INF, NO_ERRNO,"%s", buffer_out + 20);

    } else {
        LOG_MSG(INF, NO_ERRNO,"read from socket failed =%ld", sbytes);
    }

}

*/

    /*

    -c      DVR/NVR/IPC command: OPTimeSetting, OPDefaultConfig, Users,
            Groups, WorkState, StorageInfo, , SystemFunction,
            OEMInfo, LogExport, BrowserLanguage, ConfigExport, ConfigImport,
            sCustomExport, OPStorageManagerClear, OPFileQuery, OPLogQuery,
            OPVersionList, , AuthorityList, OPTimeQuery, Ability,
            User, DeleteUser, BrowserLanguage, ChannelTitle, ,
            ChannelTitleSet, , Upgrade, ProbeCommand, ProbeCommandRaw,
            OPTelnetControl, Talk
    SystemInfo
    ConfigSet
    ConfigGet
    Reboot

    -co     Config option: Sections: AVEnc, AVEnc.VideoWidget,
            AVEnc.SmartH264V2.[0], Ability, Alarm, BrowserLanguage, Detect,
            General, General.AutoMaintain, General.General,
            General.Location, Guide, NetWork, NetWork.DigManagerShow,
            NetWork.Wifi, NetWork.OnlineUpgrade, Profuce, Record,
            Status.NatInfo, Storage, System, fVideo, fVideo.GUISet, Uart,
            Simplify.Encode, Camera. Subsection could be requested in as
            object property, example: Uart.Comm

            Ability options: SystemFunction, AHDEncodeL, BlindCapability,
            Camera, Encode264ability, MultiLanguage, MultiVstd,
            SupportExtRecord, VencMaxFps

            OPTelnetControl options: TelnetEnable, TelnetDisEnable

            OPDefaultConfig option:
            CommPtz,Record,NetServer,CameraPARAM,Account,Encode,General,NetC
            ommon,Factory,Preview,Alarm

    config_print(app,"Ability");
    config_print(app,"Alarm");
    config_print(app,"Alarm.second");
    config_print(app,"AVEnc");
    config_print(app,"AVEnc.second");
    config_print(app,"Camera");
    config_print(app,"Camera.second");
    config_print(app,"Detect");
    config_print(app,"Detect.second");
    config_print(app,"fVideo");
    config_print(app,"fVideo.second");
    config_print(app,"General");
    config_print(app,"General.second");
    config_print(app,"Guide");
    config_print(app,"NetWork");
    config_print(app,"NetWork.second");
    config_print(app,"OEMcfg");
    config_print(app,"OEMcfg.second");
    config_print(app,"Produce");
    config_print(app,"Record");
    config_print(app,"Record.second");
    config_print(app,"SplitMode");
    config_print(app,"Storage");
    config_print(app,"Storage.second");
    config_print(app,"System");
    config_print(app,"System.second");
    config_print(app,"Uart");
    config_print(app,"Uart.second");
    */


