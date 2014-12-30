#include "vp_thread_setting.h"

static bool only_1bit_is_1(uint64_t n)
{
	int count = 0;
	while (n != 0)
	{
		if ((n & 0x01) == 0x01)
			++count;
		if (count > 1)
			return false;
		n = n >> 1;
	}

	return true;
}

bool tset_set(th_set *tset, e_flg_tset flg, bool has_arg, void *arg_ptr, int64_t arg_n)
{
	tset_arg *targ = NULL;

	if (tset == NULL)
		return false;

	if ( ! has_arg)
	{
		tset->flg |= flg;
		return true;
	}

	if ( ! only_1bit_is_1(flg))
	{
		logdbg_out("thread setting: has argument, but flag is more than 1");
		return false;
	}

    if (oss_malloc(&targ, sizeof(tset_arg)) < 0)
    {
		logdbg_out("thread setting: malloc failed!");
        return false;
    }

	targ->flg = flg;
	targ->ptr = arg_ptr;
	targ->n = arg_n;

	if (tset->targ != NULL)
	{
		targ->next = tset->targ;
		tset->targ = targ;
	}
	else
	{
		tset->targ = targ;
	}

    // 
	tset->flg |= flg;
	
	return true;
}

/*
 * for the argument "put" is copyed each thread, threads have their own buf.
 * so call the flowing two function to oprate the "list put->targ" is safe.
 */
tset_arg *tset_fetch_arg(th_set *tset, e_flg_tset flg)
{
	tset_arg *targ = NULL;

	if ((tset == NULL) || ((tset->flg & flg) != flg))
		return NULL;

	targ = tset->targ;
	while (targ != NULL)
	{
		if (targ->flg == flg)
			break;
		targ = targ->next;
	}

	return targ;
}

void tset_rm(th_set *tset, e_flg_tset flg)
{
	tset_arg *targ = NULL;
	tset_arg *targ_last = NULL;

	if (tset == NULL)
		return;

    tset->flg &= ~TSET_ENABLE_CHUNKED;

    // find flag item
	targ = tset->targ;
	targ_last = targ;
	while (targ != NULL)
	{
		if (targ->flg == flg)
			break;
        targ_last = targ;
		targ = targ->next;
	}
    // remove item
    if (targ != NULL)
    {
        targ_last->next = targ->next;
		oss_free(&targ);
    }
}

bool tset_is_flg_set(th_set *tset, e_flg_tset flg)
{
	if (tset == NULL)
		return false;
	return ((tset->flg & flg) == flg);
}

void tset_clear(th_set *tset)
{
	tset_arg *targ = NULL;

	if (tset == NULL) 
		return;

	while (tset->targ != NULL)
	{
		targ = tset->targ;
		tset->targ = tset->targ->next;

		oss_free(&targ);
	}
	tset->flg = TSET_DEF_NONE;
	tset->targ = NULL;
}

//////
// simple thread setting functions.

void tset_none(th_set *tset)
{
	if (tset != NULL)
		tset_set(tset, TSET_DEF_NONE, false, NULL,0);
}

void tset_conn_times(th_set *tset, int times)
{
	if ((tset != NULL) && (times > 0))
		tset_set(tset, TSET_CONN_TIMES, true, NULL, times);
}

void tset_port_free(th_set *tset)
{
	if (tset != NULL)
		tset_set(tset, TSET_PPORT_FREE, false, NULL, 0);
}

void tset_thread_tout(th_set *tset, time_t tout)
{
    if (tset != NULL)
        tset_set(tset, TSET_LSN_TOUT_EXIT, true, NULL, tout);
}

void tset_enable_chunked(th_set *tset)
{
	if (tset != NULL)
		tset_set(tset, TSET_ENABLE_CHUNKED, false, NULL, 0);
}
/*
void tset_enable_proto_receiver(th_set *tset, sdk_request_reply *srr)
{
	if (tset != NULL)
		tset_set(tset, TSET_USE_PROTO_RECEIVER, true, (void*)srr, 0);
}
*/
void tset_enable_proto_tms_client(th_set *tset, int type)
{
	if (tset != NULL)
		tset_set(tset, TSET_USE_PROTO_TMS_CLIENT, true, NULL, type);
}
void tset_enable_proto_tms_server(th_set *tset, int type)
{
	if (tset != NULL)
		tset_set(tset, TSET_USE_PROTO_TMS_SERVER, true, NULL, type);
}
void tset_enable_proto_ums_client(th_set *tset, int type)
{
	if (tset != NULL)
		tset_set(tset, TSET_USE_PROTO_UMS_CLIENT, true, NULL, type);
}
void tset_enable_proto_ums_server(th_set *tset, int type)
{
	if (tset != NULL)
		tset_set(tset, TSET_USE_PROTO_UMS_SERVER, true, NULL, type);
}

