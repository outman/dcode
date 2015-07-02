--TEST--
Check for dcode's qrcode functions
--SKIPIF--
<?php if (!extension_loaded("dcode")) print "skip"; ?>
--FILE--
<?php
$qrcode = DCode::qrcode("HELLO");
echo strlen($qrcode), "\n";
echo strlen(dcode_qrcode("HELLO"));

$qrcode = DCode::qrcode8bit("HELLO");
echo strlen($qrcode), "\n";
echo strlen(dcode_qrcode8bit("HELLO"));
?>
--EXPECT--
238
238
