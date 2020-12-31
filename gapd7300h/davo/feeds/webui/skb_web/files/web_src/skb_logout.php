<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_se.php");
	$flag_ = dv_get("flag");
	$param = Array(
		"type"		=> 0,
		"id"		=> dv_session("user_id"),
		"ip"		=> $_SERVER['REMOTE_ADDR'],
		"flag"		=> 0,
		"sec_key"	=> dv_session("secritkey")
	);
	$sock = new rcqm();
	$sock->connect();
	if($sock->con()){
	}else{
		echo("0");
	}
	$sock->write("session_check",$param);
	$json = $sock->read();
	$sock->disconnect();
	$cmd = new dvcmd();
//	$flag_
	Switch($flag_){
		Case "0":
			$cmd->add("dvmgmt","/log/output/web WEB: 10-minute timeout logout. (".dv_session("user_id").":".$_SERVER['REMOTE_ADDR'].")");
			$cmd->run();
			break;
		Case "1":
			$cmd->add("dvmgmt","/log/output/web WEB: Security breach log out. (".dv_session("user_id").":".$_SERVER['REMOTE_ADDR'].")");
			$cmd->run();
			break;
		Case "2":
			$cmd->add("dvmgmt","/log/output/web WEB: Security breach log out (device chagne). (".dv_session("user_id").":".$_SERVER['REMOTE_ADDR'].")");
			$cmd->run();
			break;
		Case "3":
			$cmd->add("dvmgmt","/log/output/web WEB: User logout. (".dv_session("user_id").":".$_SERVER['REMOTE_ADDR'].")");
			$cmd->run();
			break;
	}
	$cmd->close();
	session_start();
	if (isset($_SESSION)){
		session_destroy();
	}
	session_write_close();
	header("Location: /");
?>