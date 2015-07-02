/*
  +----------------------------------------------------------------------+
  | DCode tools extendsion                                               |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2014 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: pochonlee@gmail.com                                          |
  +----------------------------------------------------------------------+
*/

/* $Id$ */
#ifndef DCODE_H
#define DCODE_H

#define DCODE_KEY "THIS IS SHIT"
#define DCODE_CN "DCode"
#define DCODE_MD5_SIZE 32
#define DCODE_MD5_SIZE_H 16
#define DCODE_MICROTIME_SIZE 100
#define DCODE_MICRO_IN_SEC 1000000.00

typedef struct _png_mem_encode {
    char *buffer;
    size_t size;
} png_mem_encode ;

static char* dcode_md5(char *, uint, char *);
static char* dcode_microtime(char *);
static long dcode_time();
static void dcode_png_writer(png_structp, png_bytep, png_size_t);
static char* dcode_write_to_png(QRcode *, int, int, int *);

#endif
/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
