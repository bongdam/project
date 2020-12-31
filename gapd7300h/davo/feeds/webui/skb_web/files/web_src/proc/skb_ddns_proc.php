<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");

	$cmd = new dvcmd();
	$cmd->add("ps_info"," | grep dynamic","!");
	$cmd->run();
	$ps = $cmd->result()[0];
	if(preg_match("/^[\s+]{0,}(\d+)/",$ps,$d) == true) {
		$proc_id = $d[1];
	}
	if($proc_id != ""){
		$cmd->add("kill_proc",$proc_id,"!");
		$cmd->run();
	}
	$uci = new uci();
	$uci->mode("set");
	if(dv_post("ddnsEnabled") == "1"){
		$uci->set("ddns.myddns_ipv4.enabled","1");
	}else{
		$uci->set("ddns.myddns_ipv4.enabled","0");
	}
	$uci->set("ddns.myddns_ipv4.service_name",dv_post("ddnsType"));
	$uci->set("ddns.myddns_ipv4.ip_source","web");
	$uci->set("ddns.myddns_ipv4.domain",dv_post("domain"));
	$uci->set("ddns.myddns_ipv4.username",dv_post("username"));
	$uci->set("ddns.myddns_ipv4.password",dv_post("password"));
	$uci->run();
	$uci->commit();
	if(dv_post("ddnsEnabled") == "1"){
		$cmd->add("ddns_restart");
		$cmd->run();
	}
	$cmd->close();
	header("Location:".dv_post("submit-url"));
?>