dnl $Id$
dnl config.m4 for extension dcode

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

PHP_ARG_WITH(dcode, for dcode support,
Make sure that the comment is aligned:
[  --with-dcode             Include dcode support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(dcode, whether to enable dcode support,
dnl Make sure that the comment is aligned:
dnl [  --enable-dcode           Enable dcode support])

if test "$PHP_DCODE" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-dcode -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/dcode.h"  # you most likely want to change this
  dnl if test -r $PHP_DCODE/$SEARCH_FOR; then # path given as parameter
  dnl   DCODE_DIR=$PHP_DCODE
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for dcode files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       DCODE_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$DCODE_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the dcode distribution])
  dnl fi

  dnl # --with-dcode -> add include path
  dnl PHP_ADD_INCLUDE($DCODE_DIR/include)

  dnl # --with-dcode -> check for lib and symbol presence
  dnl LIBNAME=dcode # you may want to change this
  dnl LIBSYMBOL=dcode # you most likely want to change this

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $DCODE_DIR/lib, DCODE_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_DCODELIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong dcode lib version or lib not found])
  dnl ],[
  dnl   -L$DCODE_DIR/lib -lm
  dnl ])
  dnl
  dnl PHP_SUBST(DCODE_SHARED_LIBADD)

  PHP_NEW_EXTENSION(dcode, dcode.c qrencode/bitstream.c qrencode/mask.c qrencode/mmask.c qrencode/mqrspec.c qrencode/qrenc.c qrencode/qrencode.c qrencode/qrinput.c qrencode/qrspec.c qrencode/rscode.c qrencode/split.c, $ext_shared)
fi
