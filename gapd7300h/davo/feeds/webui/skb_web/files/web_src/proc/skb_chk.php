<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_se.php");
	$act = dv_post("act");
	Switch($act){
		case "session_check":
			if(getTimestamp()-dv_session("session_time") > DEF_MAX_TIMEOUT){
				echo("0");
				return;
			}else{
				$param = Array(
					"type"			=> 0,
					"id"			=> dv_session("user_id"),
					"ip"			=> $_SERVER['REMOTE_ADDR'],
					"flag"			=> 2,
					"sec_key"		=> dv_session("secritkey"),
					"session_file"	=> "/tmp/php/session/sess_".session_id()
				);
				$sock = new rcqm();
				$sock->connect();
				if($sock->con()){
				}else{
					echo("0");
				}
				$sock->write("session_check",$param);
				$json = $sock->read();
				$temp = json_decode($json,true);
				if($temp["success"] == false){
					echo("0");
				}else{
					echo("1");
				}
				$sock->disconnect();
			}
			break;
		case "check_shard_key":
			$shard_key = dv_post("shard_key");
			if($shard_key != dv_session("shard_key")){
				echo("0");
			}else{
				echo("1");
			}
	}
	
?>