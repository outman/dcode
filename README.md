# DCode

### It's php extension for encrypt、 decrypt and gen qrcode, then en/decrypt implement algorithm of discuz authcode function, qrcode based on QR Code encoder.

## QRcode
```
It's based on [QR Code encoder](http://fukuchi.org/works/qrencode/), just use a simple api `QRcode_encodeString`
```

## Usage

```php
DCode::encrypt($src, $key = "THIS IS SHIT", $ckeylength = 8, $expire = 0);
DCode::decrypt($src, $key = "THIS IS SHIT", $ckeylength = 8);
$filecontent = DCode::qrcode("HELLO");
file_put_contents("test.png", $filecontent);
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
