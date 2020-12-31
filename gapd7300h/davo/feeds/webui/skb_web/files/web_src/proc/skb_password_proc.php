<?php
	require_once($_SERVER["DOCUMENT_ROOT"]."/inc/default_ssi.php");
	require_once($_SERVER["DOCUMENT_ROOT"]."/skb_common.php");
	$act = dv_post("act");
	switch($act){
		case "set_user_password":
			$newpass_ = dv_post("newpass");
			$newpass_ = base64_decode($newpass_);
			$cmd = new dvcmd();
			$cmd->add("setpasswd","admin|".$newpass_,"|");
			$cmd->run();
			$cmd->result();
			$cmd->close();
			echo("1");
			break;
	}
	
?>