--TEST--
Check for dcode's qrcode functions
--SKIPIF--
<?php if (!extension_loaded("dcode")) print "skip"; ?>
--FILE--
<?php
$qrcode = DCode::qrcode("HELLO");
echo strlen($qrcode), "\n";
echo strlen(dcode_qrcode("HELLO")), "\n";

$qrcode = DCode::qrcode8bit("HELLO");
echo strlen($qrcode), "\n";
echo strlen(dcode_qrcode8bit("HELLO"));
$test = "世界,你好!";
$qrcode = DCode::qrcodedata(strlen($test), $test);
echo strlen($qrcode), "\n";
echo strlen(dcode_qrcodedata(strlen($test), $test));

?>
--EXPECT--
238
238
239
239
238
238
