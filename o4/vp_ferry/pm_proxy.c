#include "pm_proxy.h"

//struct pm_proxy g_pm = {-1,0,0,0, NULL, NULL,NULL,NULL,NULL,NULL};
struct pm_proxy g_pm = {0,-1,0,0,0, NULL, NULL,NULL,NULL,NULL,NULL};


bool pm_init(struct pm_proxy *pm, const char *parg)
{
    if ((pm == NULL) || (pm->manu == NULL))
        return false;

    memcpy(&g_pm, pm, sizeof(struct pm_proxy));

    if (strcmp(pm->manu, FERRY_MANU_AMPLESKY) == 0)
    {
        if (__amplesky_init() < 0)
            return false;

        pm->do_recv = NULL;
        pm->do_request = __amplesky_request;
        pm->do_reply = NULL;
        pm->do_close = NULL;
        pm->pm_quit = __amplesky_quit;

        loginf_fmt("ferry %s init:  [OK]",  pm->manu);
    }
    else if (strcmp(pm->manu, FERRY_MANU_AMPLESKY28181) == 0)
    {
        if (__amplesky28181_init(parg) < 0)
            return false;

        pm->do_socket = __amplesky28181_socket;
        pm->do_recv = NULL;
        pm->do_request = __amplesky28181_request;
        pm->do_reply = __amplesky28181_reply;
        //pm->do_reply = NULL;
        pm->do_close = __amplesky28181_close;
        pm->pm_quit =  __amplesky28181_quit;   

        loginf_fmt("ferry %s init:  [OK]",  pm->manu);
    } 
    else if (strcmp(pm->manu, FERRY_MANU_HIK28181) == 0)
    {
        if (__hik28181_init(parg) < 0)
            return false;

        pm->do_socket = __hik28181_socket;
        pm->do_recv = NULL;
        pm->do_request = __hik28181_request;
        pm->do_reply = __hik28181_reply;
        //pm->do_reply = NULL;
        pm->do_close = __hik28181_close;
        pm->pm_quit =  __hik28181_quit;   

        loginf_fmt("ferry %s init:  [OK]",  pm->manu);
    }
	else if (strcmp(pm->manu, FERRY_MANU_KEDA2800) == 0)
	{
        // KDM2800 V1R4B3SP2Fix5, cu V0383
		if ( is_tms())
		{
			return true;
		}
		
		if (__keda2800_init(parg) < 0)
			return false;
		pm->do_socket = __keda2800_socket;
		pm->do_request = __keda2800_request;
		pm->do_reply = __keda2800_reply;
		pm->do_close = __keda2800_close;
		pm->pm_quit = __keda2800_quit;

        loginf_fmt("ferry %s init:  [OK]",  pm->manu);
	}
	else if (strcmp(pm->manu, FERRY_MANU_KEDA2801E) == 0)
    {
        if (__keda2801e_init(parg) < 0)
        {
            loginf_fmt("ferry %s init:  [FAILED]",  pm->manu);
            return false;
        }
		//pm->do_socket = __keda2801e_socket;
        pm->pm_quit = __keda2801e_quit;

        loginf_fmt("ferry %s init:  [OK]",  pm->manu);
    }
	else if (strcmp(pm->manu, FERRY_MANU_DATANG) == 0)
	{
		if (__datang_init() < 0)
			return false;
		pm->do_socket = __datang_socket;
		pm->do_request = __datang_request;
		pm->do_reply = __datang_reply;
		pm->do_close = __datang_close;
		pm->pm_quit = __datang_quit;
	}
    else if (strcmp(pm->manu, FERRY_MANU_SANDUN) == 0)
    {
        if (__sandun_init() < 0)
            return false;

        pm->do_recv = NULL;
        pm->do_request = __sandun_request;
        pm->do_reply = __sandun_reply;
        pm->do_close = __sandun_close;
        pm->pm_quit = __sandun_quit;

        loginf_out("ferry sandun init:  [OK]");
    }
    else if (strcmp(pm->manu, FERRY_MANU_HUASAN) == 0)
    {
        if (__huasan_init() < 0)
            return false;
        //pm->head_type = E_WCLIENT;

        pm->do_socket = __huasan_socket;
        pm->do_recv = NULL;
        pm->do_request = __huasan_request;
        pm->do_reply = __huasan_reply;
        pm->do_close = __huasan_close;
        pm->pm_quit = __huasan_quit;

        loginf_out("ferry huasan init: [OK]");
    } 
    else if (strcmp(pm->manu, FERRY_MANU_H3C_V8500) == 0)
    {
        if ( __h3c_v8500_init() < 0)
        {
            logwar_out("ferry h3c v8500 init failed!");
            return false;
        }

        pm->do_socket = __h3c_v8500_socket;
        pm->do_recv = __h3c_v8500_recv;
        pm->do_request = __h3c_v8500_request;
        pm->do_reply = __h3c_v8500_reply;
        pm->do_close = __h3c_v8500_close;
        pm->pm_quit = __h3c_v8500_quit;

        loginf_out("ferry h3c v8500 init: [OK]");
    }
	else if (strcmp(pm->manu, FERRY_MANU_JCH3C) == 0)
	{
		if (__h3c_v8500_init() < 0)
		{
			loginf_out("ferry jincheng h3c init: [FAILED!]");
			return false;
		}
		pm->do_socket = __h3c_v8500_socket;
		pm->do_recv = __h3c_v8500_recv;
		pm->do_request = __h3c_v8500_request;
		pm->do_reply = __h3c_v8500_reply;
		pm->do_close = __h3c_v8500_close;
		pm->pm_quit = __h3c_v8500_quit;

		loginf_out("ferry jincheng h3c init: [OK]");
	}
	else if (!strcmp(pm->manu, FERRY_MANU_H3C)) 
	{
        if (h3c_init() < 0)
            return false;

        pm->do_socket = h3c_socket;
        pm->do_recv = h3c_recv;
        pm->do_request = h3c_request;
        pm->do_close = h3c_close;
        pm->pm_quit = h3c_quit;
    }
    else if (!strcmp(pm->manu, FERRY_MANU_DAHUA)) 
    {
        if (__dahua_init() < 0)
            return false;

        pm->do_socket = __dahua_socket;
        pm->do_recv = __dahua_recv;
        pm->do_request = __dahua_request;
        pm->do_reply = __dahua_reply;
        pm->do_close = __dahua_close;
        pm->pm_quit = __dahua_quit;
    }
    else if (!strcmp(pm->manu, FERRY_MANU_ZSYH)) 
    {
        if (__zsyh_init() < 0)
            return false;

        pm->do_socket = __zsyh_socket;
        pm->do_recv = __zsyh_recv;
        pm->do_request = __zsyh_request;
        pm->do_reply = __zsyh_reply;
        pm->do_close = __zsyh_close;
        pm->pm_quit = __zsyh_quit;
    
    }
    else if (!strcmp(pm->manu, FERRY_MANU_H3C_FS)) 
	{
        if (h3c_init() < 0)
            return false;

        //pm->do_socket = h3c_fs_socket;
        pm->do_recv = h3c_fs_recv;
        pm->do_request = h3c_fs_request;
        pm->do_reply = h3c_fs_reply;
        pm->do_close = h3c_fs_close;
        //pm->pm_quit = h3c_quit;
    
    }
    else if (!strcmp(pm->manu, FERRY_MANU_H3C_HARBIN)) 
	{
        if (h3c_harbin_init() < 0)
            return false;

        //pm->do_socket = h3c_harbin_socket;
        pm->do_recv = h3c_harbin_recv;
        pm->do_request = h3c_harbin_request;
        pm->do_reply = h3c_harbin_reply;
        pm->do_close = h3c_harbin_close;
        //pm->pm_quit = h3c_harbin_quit;
    }
    else if (!strcmp(pm->manu, FERRY_MANU_TIANDIWEIYE)) 
    {
      //pm->lport = FERRY_PORT_TIANDIWEIYE;
      //__gg.ferry_port = pm->lport;
    }else if (!strcmp(pm->manu, FERRY_MENU_HIK)) 
	{
        if (hik_fcg_init() < 0)
            return false;

        pm->do_socket = NULL;
        pm->do_recv = NULL;
        pm->do_request = hik_fcg_request;
        pm->do_reply = hik_fcg_reply;
        pm->do_close = NULL;
        pm->pm_quit = hik_fcg_quit;
    }                          
    else if (!strcmp(pm->manu, FERRY_MANU_ZHONGXING))
    {
        if ( zhongxing_henan_init(NULL) < 0)
            return false;
        pm->pm_quit = zhongxing_henan_quit;
        if (is_tms())
            pm->do_socket = zhongxing_socket;
            //pm->do_request = zhongxing_henan_tms_request;
        else
            pm->do_request = zhongxing_henan_request;
    }
    else if (strcmp(pm->manu, FERRY_SHANGXI_JONET) == 0)
    {
        if (jonet_init(NULL) < 0)
            return false;

        pm->do_socket = jonet_socket;
        pm->do_recv = jonet_recv;
        pm->do_request = jonet_request;
        pm->do_reply = jonet_reply;
        pm->do_close = jonet_close;
        pm->pm_quit = jonet_quit;
    }
    else if (strcmp(pm->manu, FERRY_HENAN_ZHONGXING) == 0)
    {
        if (zhongxing_henan_init(NULL) < 0)
            return false;
        pm->pm_quit = zhongxing_henan_quit;
        pm->do_request = zhongxing_henan_request;
    }
	else if ( !strcmp(pm->manu, FERRY_MANU_FIBER))
	{
		if ( __fiber_init(NULL) < 0)
			return false;
		pm->do_socket = __fiber_socket;
		pm->do_request = __fiber_request;
		pm->do_reply = __fiber_reply;
		pm->do_close = __fiber_close;
	}

    /*
    else if (strcmp(pm->manu, FERRY_MANU_HARERBIN_KEDA_CHENGGUAN) == 0)
    {
        if (__keda_haerbin_chengguan_init() < 0)
            return false;

        pm->do_recv = __keda_haerbin_chengguan_recv;
        pm->do_socket = __keda_haerbin_chengguan_socket;
        pm->do_request = __keda_haerbin_chengguan_request;
        pm->do_reply = __keda_haerbin_chengguan_reply;
        pm->do_close = __keda_haerbin_chengguan_close;
        pm->pm_quit = __keda_haerbin_chengguan_quit;
    }
    else if (strcmp(pm->manu, FERRY_MANU_TIANDIWEIYE) == 0)
    {
        pm->lport = FERRY_PORT_TIANDIWEIYE;
	    __gg.ferry_port = pm->lport;

        if (__tiandiweiye_init(parg) < 0)
            return false;

        pm->pm_quit = __tiandiweiye_quit;
        pm->do_recv = __tiandiweiye_recv;
        pm->do_socket = __tiandiweiye_socket;
        pm->do_request = __tiandiweiye_request;
        pm->do_reply = __tiandiweiye_reply;
        pm->do_close = __tiandiweiye_close;
    }
    */
    else
    {
        pm_quit();
        loginf_fmt("ferry cannot find manufactery \"%s\" which is being supported.", pm->manu);
        return false;
    }
    // refill g_pm because of callback functions have been set.
    memcpy(&g_pm, pm, sizeof(struct pm_proxy));

    return true;
}

void pm_quit()
{
    if (g_pm.pm_quit != NULL)
        g_pm.pm_quit();

    memset(&g_pm, 0, sizeof(struct pm_proxy));
    g_pm.proxy_type = -1;
}

int __start_media_proxy(char *type, u32 lip, u32 dip, u16 lport, u16 dport, u16 tout, int priv_port)
{
    char       psmid[32];
    clivlist * psmvn;
	char	   port[16];
    char     * arg[8];
    
    sprintf(psmid, "%d", get_sharemem_pid());

    if ((psmvn = create_tuvs_smem(psmid)) == NULL)
        return -1;
   // memcpy(psmvn, pcvn, sizeof(clivlist));
	psmvn->lip = lip;
	psmvn->dip = dip;
    psmvn->lvport = lport;
    psmvn->dvport = dport;
    psmvn->platform_id = 0;
    psmvn->vstream_tout = tout;

	sprintf(port, "%d", priv_port);

    arg[0] = type;
    arg[1] = psmid;
    arg[2] = (char*)"-p";
    arg[3] = (char*)port;
    arg[4] = (char*)0;
    if (start_vstream_proxy(arg[0], arg) < 0)
		return -1;

	return 1;
}

bool is_tms()
{
    //return ((__gg.local_priv_addr & 0xFF) == 1);
    return (__gg.host_side == HOST_SIDE_INNER);
}

