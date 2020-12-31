<?php
	require_once($_SERVER["DOCUMENT_ROOT"]."/inc/default_ssi.php");
	require_once($_SERVER["DOCUMENT_ROOT"]."/skb_common.php");
	$act = dv_post("act");
	switch($act){
		case "change_password":
			$user_id_ = dv_post("user_id");
			$user_pwd_ = dv_post("user_pwd");
			$user_pwd_ = base64_decode($user_pwd_);
			$cmd = new dvcmd();
			$cmd->add("setpasswd",$user_id_."|".$user_pwd_,"|");
			$cmd->run();
			$result = $cmd->result()[0];
			$cmd->close();
			if($result[0] != ""){
				echo("1");
			}else{
				echo("0");
			}
			break;
	}
	
?>