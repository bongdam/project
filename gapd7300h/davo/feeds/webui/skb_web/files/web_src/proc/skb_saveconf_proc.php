<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");

	$act_ = dv_post("act");
	if($act_ == "reboot"){
		echo(rtn_reboot_page("/","system_restart"));
	}elseif($act_ == "factory"){
		echo(rtn_reboot_page("/","system_factory"));
	}


?>