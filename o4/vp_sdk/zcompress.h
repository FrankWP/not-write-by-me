#ifndef _ZCOMPRESS_H_
#define _ZCOMPRESS_H_

int httpgzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata);
int zdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata);
int zcompress(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata);
int gzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata);
int gzcompress(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata);

#endif  // _ZCOMPRESS_H_

