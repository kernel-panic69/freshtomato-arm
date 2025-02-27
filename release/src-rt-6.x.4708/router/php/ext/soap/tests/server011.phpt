--TEST--
SOAP Server 11: bind
--SKIPIF--
<?php
if (PHP_OS_FAMILY === "Windows") {
    die("skip currently unsupported on Windows");
}
?>
--EXTENSIONS--
soap
--GET--
wsdl
--INI--
soap.wsdl_cache_enabled=0
--ENV--
LSAN_OPTIONS=detect_leaks=0
--FILE--
<?php
function Add($x,$y) {
  return $x+$y;
}

$server = new soapserver(__DIR__."/test.wsdl");
ob_start();
$server->handle();
$wsdl = ob_get_contents();
ob_end_clean();
if ($wsdl == file_get_contents(__DIR__."/test.wsdl")) {
  echo "ok\n";
} else {
    echo "fail\n";
}
?>
--EXPECT--
ok
