<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/class/dvzip.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");

$zip = new DirectZip();
$zip->open(date("Y-m-d H-i-s").'_log.zip');

function listFolders($dir){
	$dh = scandir($dir);
	$return = array();

	foreach ($dh as $folder) {
		if ($folder != '.' && $folder != '..') {
			if (is_dir($dir . '/' . $folder)) {
//				$return[] = array($folder => listFolders($dir . '/' . $folder));  
			}else{
				$return[] = $folder;
			}
		}
	}
	return $return;
}
$files = listFolders("/tmp/qcalog/");
for($i=0; $i < count($files); $i++){
	$zip->addFile('/tmp/qcalog/'.$files[$i], $files[$i]);
}
$zip->close();
?>
