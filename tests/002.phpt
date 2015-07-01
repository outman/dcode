--TEST--
Check for dcode's qrcode functions
--SKIPIF--
<?php if (!extension_loaded("dcode")) print "skip"; ?>
--FILE--
<?php
$qrcode = DCode::qrcode("HELLO");
echo strlen($qrcode);
?>
--EXPECT--
238