<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$act_ = dv_post("act");
	if($act_ == "get_diagnostic"){
		$param = null;
		$sock = new rcqm();
		$sock->connect();
		$diag = Array();
		if($sock->con()){
			$sock->write("diagnosis",$param);
			$diag = $sock->read();
			$diag = array_to_json(json_decode($diag,true)["data"]);
		}
		set_head_json();
		echo($diag);
	}elseif($act_ == "ping_test"){
		$cmd = new dvcmd();
		$ip_ = dv_post("ip");
		$cmd->add("ping",$ip_);
		$cmd->run();
		echo($cmd->result()[0]);
	}
	//	diagnosis

?>