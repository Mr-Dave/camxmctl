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
 *
*/

#ifndef _INCLUDE_UTIL_HPP_
#define _INCLUDE_UTIL_HPP_
    #if MHD_VERSION >= 0x00097002
        typedef enum MHD_Result mhdrslt; /* Version independent return result from MHD */
    #else
        typedef int             mhdrslt; /* Version independent return result from MHD */
    #endif

    int mystrceq(const char* var1, const char* var2);
    int mystrcne(const char* var1, const char* var2);
    int mystreq(const char* var1, const char* var2);
    int mystrne(const char* var1, const char* var2);

    void myfree(void *ptr_addr);

    void *mymalloc(size_t nbytes);
    void *myrealloc(void *ptr, size_t size, const char *desc);
    FILE *myfopen(const char *path, const char *mode);
    int myfclose(FILE *fh);

    void mythreadname_set(const char *abbr, int threadnbr, const char *threadname);
    void mythreadname_get(char *threadname);

    void myltrim(std::string &parm);
    void myrtrim(std::string &parm);
    void mytrim(std::string &parm);
    void myunquote(std::string &parm);

    void util_parms_parse(ctx_params &params, std::string parm_desc, std::string confline);
    void util_parms_add_default(ctx_params &params, std::string parm_nm, std::string parm_vl);
    void util_parms_add_default(ctx_params &params, std::string parm_nm, int parm_vl);
    void util_parms_add(ctx_params &params, std::string parm_nm, std::string parm_val);
    void util_parms_update(ctx_params &params, std::string &confline);

#endif /* _INCLUDE_UTIL_HPP_ */
