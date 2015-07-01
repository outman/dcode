--TEST--
Check for dcode's en/decrypt functions
--SKIPIF--
<?php if (!extension_loaded("dcode")) print "skip"; ?>
--FILE--
<?php
$t = 0;
$loop = 100000;
for ($i = 0; $i < $loop; $i ++) {
	$encode = DCode::encrypt("THIS IS SHIT");
	if ($encode) {
		$decode = DCode::decrypt($encode);
		if ($decode)
			$t ++;
	}
}
echo $t, "\n";

$encode = DCode::encrypt("HELLO WORLD", "", 0, 0);
if (($decode = DCode::decrypt($encode, "", 0))) {
	echo $decode, "\n";
}
$encode = DCode::encrypt("HELLO WORLD", "", 32, 0);
if (($decode = DCode::decrypt($encode, "", 32))) {
	echo $decode, "\n";
}
?>
--EXPECT--
100000
HELLO WORLD
HELLO WORLD
