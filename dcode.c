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

#include <sys/time.h>
#include <errno.h>
#include <png.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_dcode.h"

#include "ext/standard/md5.h"
#include "ext/standard/php_smart_str.h"
#include "ext/standard/base64.h"
#include "ext/standard/php_string.h"
#include "Zend/zend_strtod.h"
#include "qrencode/qrencode.h"
#include "dcode.h"

/* If you declare any globals in php_dcode.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(dcode)
*/

/* True global resources - no need for thread safety here */
static int le_dcode;

zend_class_entry *dcode_ce;

/* {{{ dcode_functions[]
 *
 * Every user visible function must have an entry in dcode_functions[].
 */
const zend_function_entry dcode_functions[] = {
    PHP_FE_END  /* Must be the last line in dcode_functions[] */
};

const zend_function_entry dcode_methods[] = {
    PHP_ME(dcode, encrypt, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(dcode, decrypt, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(dcode, qrcode, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};
/* }}} */

/* {{{ dcode_module_entry
 */
zend_module_entry dcode_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    "dcode",
    dcode_functions,
    PHP_MINIT(dcode),
    PHP_MSHUTDOWN(dcode),
    PHP_RINIT(dcode),       /* Replace with NULL if there's nothing to do at request start */
    PHP_RSHUTDOWN(dcode),   /* Replace with NULL if there's nothing to do at request end */
    PHP_MINFO(dcode),
#if ZEND_MODULE_API_NO >= 20010901
    PHP_DCODE_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_DCODE
ZEND_GET_MODULE(dcode)
#endif

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("dcode.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_dcode_globals, dcode_globals)
    STD_PHP_INI_ENTRY("dcode.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_dcode_globals, dcode_globals)
PHP_INI_END()
*/
/* }}} */

/* {{{ php_dcode_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_dcode_init_globals(zend_dcode_globals *dcode_globals)
{
    dcode_globals->global_value = 0;
    dcode_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(dcode)
{
    zend_class_entry ce;
    INIT_CLASS_ENTRY(ce, DCODE_CN, dcode_methods);
    dcode_ce = zend_register_internal_class(&ce TSRMLS_CC);
    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(dcode)
{
    /* uncomment this line if you have INI entries
    UNREGISTER_INI_ENTRIES();
    */
    return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(dcode)
{
    return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(dcode)
{
    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(dcode)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "dcode support", "enabled");
    php_info_print_table_end();

    /* Remove comments if you have entries in php.ini
    DISPLAY_INI_ENTRIES();
    */
}
/* }}} */


/* Remove the following function when you have successfully modified config.m4
   so that your module can be compiled into PHP, it exists only for testing
   purposes. */

/** {{{ dcode_md5(char *src, uint src_len, char* out)
    Return char* out */
static char* dcode_md5(char *src, uint src_len, char *md5str)
{
    PHP_MD5_CTX context;
    unsigned char digest[DCODE_MD5_SIZE_H];
    PHP_MD5Init(&context);
    PHP_MD5Update(&context, src, src_len);
    PHP_MD5Final(digest, &context);
    make_digest_ex(md5str, digest, DCODE_MD5_SIZE_H);
    return md5str;
}
/** }}} */

/** {{{ decode_microtime(char *out)
    Return char* out */
static char* dcode_microtime(char *microtime)
{
    struct timeval tp = {0};
    gettimeofday(&tp, NULL);
    snprintf(microtime, DCODE_MICROTIME_SIZE, "%.8F %ld", tp.tv_usec / DCODE_MICRO_IN_SEC, tp.tv_sec);
    return microtime;
}
/** }}} */

/** {{{ dcode_time()
    Return long */
static long dcode_time()
{
    return (long) time(NULL);
}
/** }}} */

static void dcode_png_writer(png_structp png_ptr, png_bytep data, png_size_t length)
{
    struct png_mem_encode* p = (struct png_mem_encode*) png_get_io_ptr(png_ptr);
    size_t nsize = p->size + length;
    if (p->buffer)
    {
        p->buffer = erealloc(p->buffer, nsize);
    }
    else {
        p->buffer = emalloc(nsize);
    }

    if (!p->buffer)
    {
        png_error(png_ptr, "Png image write error");
        exit(FAILURE);
    }

    memcpy(p->buffer + p->size, data, length);
    p->size += length;
}

static int dcode_write_to_png(QRcode *qrcode, int size, int margin, char **bin_data)
{
    struct png_mem_encode state;
    state.buffer = NULL;
    state.size = 0;

    png_structp png_ptr;
    png_infop info_ptr;

    unsigned char *row, *p, *q;
    int x, y, xx, yy, bit;
    int realwidth;

    realwidth = (qrcode->width + margin * 2) * size;

    int row_fill_len = (realwidth + 7) / 8;
    row = (unsigned char *) emalloc(row_fill_len);

    if (row == NULL)
    {
        php_error(E_ERROR, "Failed to allocate memory");
        return 0;
    }

    png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (png_ptr == NULL)
    {
        php_error(E_ERROR, "Failed to initialize PNG writer");
        return 0;
    }

    info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == NULL)
    {
        php_error(E_ERROR, "Failed to initialize PNG writer");
        return 0;
    }

    if (setjmp(png_jmpbuf(png_ptr)))
    {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        php_error(E_ERROR, "Failed to write PNG image");
        return 0;
    }
    //
    // fseek(fp, 0, SEEK_SET);
    // ftruncate(fileno(fp), 0);
    png_set_write_fn(png_ptr, &state, dcode_png_writer, NULL);

    // png_init_io(png_ptr, fp);
    png_set_IHDR(png_ptr, info_ptr,
                realwidth, realwidth,
                1,
                PNG_COLOR_TYPE_GRAY,
                PNG_INTERLACE_NONE,
                PNG_COMPRESSION_TYPE_DEFAULT,
                PNG_FILTER_TYPE_DEFAULT);
    png_write_info(png_ptr, info_ptr);

    /* top margin */
    memset(row, 0xff, row_fill_len);
    for(y = 0; y < margin * size; y ++)
    {
        png_write_row(png_ptr, row);
    }

    /* data */
    p = qrcode->data;
    for(y = 0; y < qrcode->width; y ++)
    {
        bit = 7;
        memset(row, 0xff, row_fill_len);
        q = row;
        q += margin * size / 8;
        bit = 7 - (margin * size % 8);
        for(x = 0; x < qrcode->width; x ++)
        {
            for(xx = 0; xx < size; xx ++)
            {
                *q ^= (*p & 1) << bit;
                bit--;
                if(bit < 0)
                {
                    q++;
                    bit = 7;
                }
            }
            p++;
        }

        for(yy = 0; yy < size; yy ++)
        {
            png_write_row(png_ptr, row);
        }
    }
    /* bottom margin */
    memset(row, 0xff, row_fill_len);
    for(y = 0; y < margin * size; y ++)
    {
        png_write_row(png_ptr, row);
    }

    png_write_end(png_ptr, info_ptr);
    png_destroy_write_struct(&png_ptr, &info_ptr);

    efree(row);

    if (state.buffer) {
        *bin_data = estrndup(state.buffer, 1);
        efree(state.buffer);
        return 1;
    }
    return 0;
}

/** {{{ DCode::encrypt($src, $sec_key = "THIS IS SHIT", $sec_rand_key_len = 8, $expire = 0)
    Return False or String */
PHP_METHOD(dcode, encrypt)
{
    char *src = NULL;
    char *key = DCODE_KEY;

    int src_len = 0;
    int key_len = strlen(key);

    long ck_len = 8;
    long expire = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|sll", &src, &src_len, &key, &key_len, &ck_len, &expire) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Invalid arguments");
        RETURN_FALSE;
    }

    if (ck_len > DCODE_MD5_SIZE || ck_len < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Invalid arguments sec_rand_key_len must 0-32");
        RETURN_FALSE;
    }

    if (expire < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Invalid arguments expire >= 0");
        RETURN_FALSE;
    }

    char *md5_key = safe_emalloc(1, DCODE_MD5_SIZE, 1);
    char *md5_keya = safe_emalloc(1, DCODE_MD5_SIZE, 1);
    char *md5_keyb = safe_emalloc(1, DCODE_MD5_SIZE, 1);

    dcode_md5(key, key_len, md5_key);
    dcode_md5(md5_key, DCODE_MD5_SIZE_H, md5_keya);
    dcode_md5(md5_key + DCODE_MD5_SIZE_H, DCODE_MD5_SIZE_H, md5_keyb);

    efree(md5_key);

    char *microtime = safe_emalloc(1, DCODE_MICROTIME_SIZE, 0);
    dcode_microtime(microtime);

    char *md5_microtime = safe_emalloc(1, DCODE_MD5_SIZE, 1);
    dcode_md5(microtime, strlen(microtime), md5_microtime);

    efree(microtime);

    int offset = (DCODE_MD5_SIZE - ck_len);
    char *keyc = estrndup(md5_microtime + offset, ck_len);

    efree(md5_microtime);

    smart_str sec_key_ac = {0};
    smart_str_appends(&sec_key_ac, md5_keya);
    smart_str_appends(&sec_key_ac, keyc);
    smart_str_0(&sec_key_ac);

    char *md5_kac = safe_emalloc(1, DCODE_MD5_SIZE, 1);
    dcode_md5(sec_key_ac.c, sec_key_ac.len, md5_kac);
    smart_str_free(&sec_key_ac);

    smart_str cryptkey = {0};
    smart_str_appends(&cryptkey, md5_keya);
    smart_str_appends(&cryptkey, md5_kac);
    smart_str_0(&cryptkey);

    efree(md5_kac);
    efree(md5_keya);

    char *prefix;
    spprintf(&prefix, 0, "%010d", (int) (expire ? expire + dcode_time() : 0));

    smart_str tmp_src = {0};
    smart_str_appends(&tmp_src, src);
    smart_str_appends(&tmp_src, md5_keyb);
    smart_str_0(&tmp_src);

    efree(md5_keyb);

    char *md5_src_kb = safe_emalloc(1, DCODE_MD5_SIZE, 1);
    dcode_md5(tmp_src.c, tmp_src.len, md5_src_kb);
    smart_str_free(&tmp_src);

    char *md5_src_kb_h = estrndup(md5_src_kb, DCODE_MD5_SIZE_H);
    efree(md5_src_kb);

    smart_str new_src = {0};
    smart_str_appends(&new_src, prefix);
    smart_str_appends(&new_src, md5_src_kb_h);
    smart_str_appends(&new_src, src);
    smart_str_0(&new_src);

    efree(md5_src_kb_h);
    efree(prefix);

    int box[256];
    int rndkey[256];
    for (int i = 0; i < 256; i ++) box[i] = i;
    for (int i = 0; i < 256; i ++) rndkey[i] = (int) cryptkey.c[i%cryptkey.len];

    smart_str_free(&cryptkey);

    int tmp = 0;
    for (int j = 0, i = 0; i < 256; i++)
    {
        j = (j + box[i] + rndkey[i]) % 256;
        tmp = box[i];
        box[i] = box[j];
        box[j] = tmp;
    }

    smart_str result = {0};
    for (int a = 0, i = 0, j = 0; i < new_src.len; i ++)
    {
        a = (a + 1) % 256;
        j = (j + box[a]) % 256;
        tmp = box[a];
        box[a] = box[j];
        box[j] = tmp;
        smart_str_appendc(&result, (char)(((int) new_src.c[i]) ^ box[(box[a] + box[j]) % 256]));
    }
    smart_str_0(&result);
    smart_str_free(&new_src);

    int ret_len;
    unsigned char *ret;
    ret = php_base64_encode((unsigned char *)result.c, result.len, &ret_len);
    smart_str_free(&result);

    zval *zret;
    MAKE_STD_ZVAL(zret);
    char *to = STR_EMPTY_ALLOC();
    php_char_to_str((char *)ret, ret_len, '=', to, strlen(to), zret);
    efree(ret);
    efree(to);

    smart_str last_result = {0};
    smart_str_appends(&last_result, keyc);
    smart_str_appends(&last_result, Z_STRVAL_P(zret));
    smart_str_0(&last_result);

    zval_ptr_dtor(&zret);
    efree(keyc);

    ZVAL_STRINGL(return_value, last_result.c, last_result.len, 1);
    smart_str_free(&last_result);
    return;
}
/** }}} */

/** {{{ DCode::decrypt($src, $sec_key = "THIS IS SHIT", $sec_rand_key_len = 8)
    Return False or Success's string */
PHP_METHOD(dcode, decrypt)
{
    char *src = NULL;
    char *key = DCODE_KEY;

    int src_len = 0;
    int key_len = strlen(key);

    long ck_len = 8;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|sl", &src, &src_len, &key, &key_len, &ck_len) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Invalid arguments");
        RETURN_FALSE;
    }

    if (ck_len > DCODE_MD5_SIZE || ck_len < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Invalid arguments sec_rand_key_len must 0-32");
        RETURN_FALSE;
    }

    char *md5_key = safe_emalloc(1, DCODE_MD5_SIZE, 1);
    char *md5_keya = safe_emalloc(1, DCODE_MD5_SIZE, 1);
    char *md5_keyb = safe_emalloc(1, DCODE_MD5_SIZE, 1);

    dcode_md5(key, key_len, md5_key);
    dcode_md5(md5_key, DCODE_MD5_SIZE_H, md5_keya);
    dcode_md5(md5_key + DCODE_MD5_SIZE_H, DCODE_MD5_SIZE_H, md5_keyb);
    efree(md5_key);

    char *keyc = estrndup(src, ck_len);

    smart_str sec_key_ac = {0};
    smart_str_appends(&sec_key_ac, md5_keya);
    smart_str_appends(&sec_key_ac, keyc);
    smart_str_0(&sec_key_ac);

    efree(keyc);

    char *md5_kac = safe_emalloc(1, DCODE_MD5_SIZE, 1);
    dcode_md5(sec_key_ac.c, sec_key_ac.len, md5_kac);
    smart_str_free(&sec_key_ac);

    smart_str cryptkey = {0};
    smart_str_appends(&cryptkey, md5_keya);
    smart_str_appends(&cryptkey, md5_kac);
    smart_str_0(&cryptkey);

    efree(md5_kac);
    efree(md5_keya);

    char *str_to_decode = estrndup(src + ck_len, src_len - ck_len);

    int str_decode_len;
    char *str_decode = (char *) php_base64_decode((unsigned char *) str_to_decode, src_len - ck_len, &str_decode_len);

    efree(str_to_decode);

    int box[256];
    int rndkey[256];
    for (int i = 0; i < 256; i ++) box[i] = i;
    for (int i = 0; i < 256; i ++) rndkey[i] = (int) cryptkey.c[i%cryptkey.len];

    smart_str_free(&cryptkey);

    int tmp = 0;
    for (int j = 0, i = 0; i < 256; i++)
    {
        j = (j + box[i] + rndkey[i]) % 256;
        tmp = box[i];
        box[i] = box[j];
        box[j] = tmp;
    }

    smart_str result = {0};
    for (int a = 0, i = 0, j = 0; i < str_decode_len; i ++)
    {
        a = (a + 1) % 256;
        j = (j + box[a]) % 256;
        tmp = box[a];
        box[a] = box[j];
        box[j] = tmp;
        smart_str_appendc(&result, (char)(((int) str_decode[i]) ^ box[(box[a] + box[j]) % 256]));
    }
    smart_str_0(&result);
    efree(str_decode);

    char *sub10 = estrndup(result.c, 10);
    double expire_time = zend_strtod(sub10, NULL);
    efree(sub10);

    char *cmp_kb = estrndup(result.c + 10, 16);
    char *cmp_kb_md5 = estrndup(result.c + 26, result.len - 26);

    smart_str_free(&result);

    smart_str cmp_kb_md5_all = {0};
    smart_str_appends(&cmp_kb_md5_all, cmp_kb_md5);
    smart_str_appends(&cmp_kb_md5_all, md5_keyb);
    smart_str_0(&cmp_kb_md5_all);

    efree(md5_keyb);

    char *cmp_md5 = safe_emalloc(1, DCODE_MD5_SIZE, 1);
    dcode_md5(cmp_kb_md5_all.c, cmp_kb_md5_all.len, cmp_md5);
    smart_str_free(&cmp_kb_md5_all);

    char *cmp_md5_h = estrndup(cmp_md5, 16);
    efree(cmp_md5);

    if ((expire_time == 0 || (expire_time - dcode_time()) > 0)
        && strcmp(cmp_kb, cmp_md5_h) == 0)
    {
            ZVAL_STRING(return_value, cmp_kb_md5, 1);
            efree(cmp_kb_md5);
            efree(cmp_md5_h);
            efree(cmp_kb);
            return;
    }
    efree(cmp_kb_md5);
    efree(cmp_md5_h);
    efree(cmp_kb);
    RETURN_FALSE;
}
/** }}} */

PHP_METHOD(dcode, qrcode)
{
    char *str_encode;
    int str_encode_len;

    int version = 0;
    int level   = (int) QR_ECLEVEL_L;
    int mode    = (int) QR_MODE_KANJI;
    int casesensitive = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|llll", &str_encode, &str_encode_len, &version, &level, &mode, &casesensitive) == FAILURE) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "Invalid arguments");
        RETURN_FALSE;
    }

    QRcode *qcode = NULL;
    qcode = QRcode_encodeString(str_encode, version, (QRecLevel) level, (QRencodeMode) mode, casesensitive);
    if (qcode == NULL)
    {
        if (errno == EINVAL) {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "DCode::qrcode error, error invalid input object");
        }
        else if (errno == ENOMEM) {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "DCode::qrcode error, unable to allocate memory for input objects");
        }
        else if (errno == ERANGE) {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "DCode::qrcode error, input data is too large");
        }
        else {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "DCode::qrcode error, errno : %d", errno);
        }
        RETURN_FALSE;
    }

    char *bin_data = NULL;
    int ok = dcode_write_to_png(qcode, 3, 4, &bin_data);
    QRcode_free(qcode);
    qcode = NULL;
    if (ok)
    {
        ZVAL_STRING(return_value, bin_data, 1);
        efree(bin_data);
        return;
    }
    else {
        RETURN_FALSE;
    }
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
