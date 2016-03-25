<?php
	include_once('cubeSQLServer.php');
	
	$cubesql = New cubeSQLServer;
	$rc = $cubesql->connect("localhost", 4430, "admin", "admin");
	
	if ($rc === true) {
		$tstart = microtime(true);
		$rs = $cubesql->select("SHOW INFO;");
		$tend = (microtime(true) - $tstart);
		var_dump($rs);
		echo "Time Elapsed: " . $tend . " secs. \n";
	} else {
		echo "Error: " . $cubesql->errorMessage . "\n";
	}
?>