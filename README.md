# DCode

### It's php extension for encrypt、 decrypt and gen qrcode, the en/decrypt implement algorithm of discuz authcode function, qrcode based on QR Code encoder.

## QRcode

It's based on [QR Code encoder](http://fukuchi.org/works/qrencode/), just use a simple api `QRcode_encodeString`, `QRcode_encodeString8bit`,`QRcode_encodeData`


## dependencies
```
php5.4+
libpng
```

## Usage

```php
DCode::encrypt($src, $key = "THIS IS SHIT", $ckeylength = 8, $expire = 0);
DCode::decrypt($src, $key = "THIS IS SHIT", $ckeylength = 8);

/** 
* DCode::qrcode($str, $version = 0, $level = QR_ECLEVEL_L, $mode = QR_MODE_KANJI, $casesensitive = 0);
* @param $str;
* @param $version = 0;
* @param $level = QR_ECLEVEL_L;
* @param $model = QR_MODE_KANJI;
* @param $casesensitive = 0;
* @return string
*/
$filecontent = DCode::qrcode("HELLO");
file_put_contents("test.png", $filecontent);

/**
* DCode::qrcode8bit($str, $version = 0, $level = QR_ECLEVEL_L);
* @param $str;
* @param $version = 0;
* @param $level = QR_ECLEVEL_L;
* @return string
*/
$filecontent = DCode::qrcode8bit("HELLO WORLD");
file_put_contents("test1.png", $filecontent);

/**
* DCode::qrcodedata($sizeof, $data, $version = 0, $level = QR_ECLEVEL_L);
* @param $sizeof
* @param $data
* @param $version = 0;
* @param $level = QR_ECLEVEL_L;
* @return string
*/
$filecontent = DCode::qrcodedata(strlen("HELLO WORLD"), "HELLO WORLD");
file_put_contents("test2.png", $filecontent);

dcode_encrypt($src, $key = "THIS IS SHIT", $ckeylength = 8, $expire = 0);
dcode_decrypt($src, $key = "THIS IS SHIT", $ckeylength = 8);

$filecontent = dcode_qrcode("HELLO");
file_put_contents("test.png", $filecontent);

$filecontent = dcode_qrcode8bit("HELLO 8bit");
file_put_contents("test1.png", $filecontent);

$filecontent = dcode_qrcodedata(strlen("HELLO 8bit"), "HELLO 8bit");
file_put_contents("test2.png", $filecontent);
```

## Install

```git
git clone git@github.com:outman/dcode.git
cd dcode
phpize
./configure
make && make test
make install
```

## PHP.ini
```
extension=dcode.so
```

## Time test code
```
dcode.php
<?php
for ($i = 0; $i < 100000; $i ++) {
    $code = DCode::encrypt($i);
    DCode::decrypt($code);
}

authcode.php

<?php
function authcode(.............

for ($i = 0; $i < 100000; $i ++) {
    $code = authcode($i, "ENCODE");
    authcode($code);
}
```

## Time test result
```
100000 times en/decrypt code
time php authcode.php   90.37s user 0.18s system 99% cpu 1:30.59 total
time php dcode.php   2.19s user 0.08s system 99% cpu 2.278 total

5000000 times decode.php
116.53s user 4.79s system 92% cpu 2:11.73 total
```

## LICENSE
```
MIT
```
