#include "sysheader.h"

/* Compress gzip data */
//args:srcstr,srcstrsize,gzipstr,gzipstrsize
int gzcompress(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata)
{
	z_stream c_stream;
	int err = 0;

	if(data && ndata > 0)
	{
		c_stream.zalloc = (alloc_func)0;
		c_stream.zfree = (free_func)0;
		c_stream.opaque = (voidpf)0;
		if(deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY)
				!= Z_OK) 
			return -1;
		c_stream.next_in  = data;
		c_stream.avail_in  = ndata;
		c_stream.next_out = zdata;
		c_stream.avail_out  = *nzdata;
		while (c_stream.avail_in != 0 && c_stream.total_out < *nzdata) 
		{
			if(deflate(&c_stream, Z_NO_FLUSH) != Z_OK) return -1;
		}
		if(c_stream.avail_in != 0) return c_stream.avail_in;
		for (;;) 
		{
			if((err = deflate(&c_stream, Z_FINISH)) == Z_STREAM_END) break;
			if(err != Z_OK) return -1;
		}
		if(deflateEnd(&c_stream) != Z_OK) return -1;
		*nzdata = c_stream.total_out;
		return 0;
	}
	return -1;
}

/* Uncompress gzip data */
int gzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata)
{
	int err = 0;
	z_stream d_stream = {0}; /* decompression stream */
	static char dummy_head[2] = 
	{
		0x8 + 0x7 * 0x10,
		(((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
	};
	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in  = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if(inflateInit2(&d_stream, -MAX_WBITS) != Z_OK) return -1;
	//if(inflateInit2(&d_stream, 47) != Z_OK) return -1;
	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) break;
		if(err != Z_OK )
		{
			if(err == Z_DATA_ERROR)
			{
				d_stream.next_in = (Bytef*) dummy_head;
				d_stream.avail_in = sizeof(dummy_head);
				if((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK) 
				{
					return -1;
				}
			}
			else return -1;
		}
	}
	if(inflateEnd(&d_stream) != Z_OK) return -1;
	*ndata = d_stream.total_out;
	return 0;
}

/* Compress data */
int zcompress(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata)
{
	z_stream c_stream;
	int err = 0;

	if(data && ndata > 0)
	{
		c_stream.zalloc = (alloc_func)0;
		c_stream.zfree = (free_func)0;
		c_stream.opaque = (voidpf)0;
		if(deflateInit(&c_stream, Z_DEFAULT_COMPRESSION) != Z_OK) return -1;
		//if(deflateInit(&c_stream, Z_BEST_SPEED) != Z_OK) return -1;
		//if(deflateInit(&c_stream, Z_BEST_COMPRESSION) != Z_OK) return -1;
		//if(deflateInit(&c_stream, Z_NO_COMPRESSION) != Z_OK) return -1;
		c_stream.next_in  = data;
		c_stream.avail_in  = ndata;
		c_stream.next_out = zdata;
		c_stream.avail_out  = *nzdata;
		while (c_stream.avail_in != 0 && c_stream.total_out < *nzdata) 
		{
			if(deflate(&c_stream, Z_NO_FLUSH) != Z_OK) return -1;
		}
		if(c_stream.avail_in != 0) return c_stream.avail_in;
		for (;;) 
		{
			if((err = deflate(&c_stream, Z_FINISH)) == Z_STREAM_END) break;
			if(err != Z_OK) return -1;
		}
		if(deflateEnd(&c_stream) != Z_OK) return -1;
		*nzdata = c_stream.total_out;
		return 0;
	}
	return -1;
}

/* Uncompress data */
int zdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata)
{
	int err = 0;
	z_stream d_stream; /* decompression stream */

	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in  = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if(inflateInit(&d_stream) != Z_OK) return -1;
	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) 
	{
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) break;
		if(err != Z_OK) return -1;
	}
	if(inflateEnd(&d_stream) != Z_OK) return -1;
	*ndata = d_stream.total_out;
	return 0;
}

/* HTTP gzip decompress */
int httpgzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata)
{
	static char dummy_head[2] = 
	{
		0x8 + 0x7 * 0x10,
		(((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
	};
	int err = 0;
	z_stream d_stream = {0}; /* decompression stream */

	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in  = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;

	if (inflateInit2(&d_stream, 47) != Z_OK) 
		return -1;

	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) 
	{
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if ((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) 
			break;
		if (err != Z_OK )
		{
			if (err == Z_DATA_ERROR)
			{
				d_stream.next_in = (Bytef*) dummy_head;
				d_stream.avail_in = sizeof(dummy_head);
				if ((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK) 
				{
					return -1;
				}
			}
			else return -1;
		}
	}
	if (inflateEnd(&d_stream) != Z_OK) 
		return -1;
	*ndata = d_stream.total_out;

	return 0;
}

/*
int 
hextxt2byte(unsigned char HexTxt[2])
{
	int dec = -1;
	unsigned char ch = HexTxt[0];
	//printf("ch1:%c, ch2:%c\n", HexTxt[0], HexTxt[1]);

	if ((ch >= '0') && (ch <= '9'))
		dec = (ch - '0') * 16;
	else if ((ch >= 'a') && (ch <= 'f'))
		dec = ((ch - 'a') + 10) * 16;
	else
	{
		printf("convert hex text to bin error!\n");
		return -1;
	}
	//printf("ch1: %c  dec:%d \n", ch, dec);

	ch = HexTxt[1];
	if ((ch >= '0') && (ch <= '9'))
		dec += (ch - '0');
	else if ((ch >= 'a') && (ch <= 'f'))
		dec += ((ch - 'a') + 10);
	else
	{
		printf("convert hex text to bin error!\n");
		return -1;
	}
	//printf("ch2: %c  dec:%d \n", ch, dec);

	return dec;
}

bool hextxt2bin(unsigned char *pHexTxt, int lenHexTxt, unsigned char *buf, unsigned long *len_buf)
{
	int i = 0;
	int dec = 0;
	if (lenHexTxt % 2 != 0)
	{
		puts("Invalid HexText length!");
		return false;
	}
	if ((int)(*len_buf) < lenHexTxt/2)
	{
		printf("Buffer is not large enough! %ld %d\n", *len_buf, lenHexTxt/2);
		return false;
	}

	for (; i < lenHexTxt; i += 2)
	{
		if ((dec = hextxt2byte(pHexTxt + i)) < 0)
		{
			puts("Convert Failed!");
			break;	
		}
		buf[i/2] = dec;
	}
	*len_buf = i/2;

	return true;
}

int
main(int argc, char *argv[])
{
	unsigned char hextxt[] = "789c63606060342000180c2d0d8c50854c80d8108a810a1898b8f62efff52a81010898e458191999412c82da12537233f31c4e5dd8b97ac3a67dd7f4aaaaf432f2184802407bffd5ffffbf4628b78a81419b0926fcea0169c6d01ad8ee4e08958ec8282929b0d2d73733d4333436d7b334d003868e7e726969414a6249aabe7368706a4969815e6a45ea403b974680fd2b8fbcb8b53594020075a53a80";
	unsigned char d[160] = {0};
	unsigned long len_d = sizeof(d);
	unsigned char buf[1024] = {0};
	unsigned long len_buf = sizeof(buf);

	if ( ! hextxt2bin(hextxt, sizeof(hextxt)-1, d, &len_d))
	{
		printf("Convert failed!\n");
		return -1;
	}
	// uncompress
	puts("===================================================================");
	t_disbuf(d, len_d);
	puts("===================================================================");
	if (zdecompress(d,len_d, buf,&len_buf) < 0)
	{
		printf("Uncompress failed!\n");
		return -1;
	}
    printf(">>>>>>> len:%d\n", len_buf);
	//t_disbuf(buf, len_buf);
	puts("-------------------------------------------");

	// compress
	unsigned char zdata[256] = {0};
	unsigned long nzdata = sizeof(zdata);
	if (zcompress(buf,len_buf, zdata, &nzdata) < 0)
	{
		printf("Compress failed!\n");
		return -1;
	}
	//printf("nzdata:%d\n", nzdata);
	t_disbuf(zdata, nzdata);
	puts("-------------------------------------------");

	return 0;
}
*/

