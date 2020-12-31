<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	
	$hole_enable_ = dv_post("holepunch_enabled");
	$cserver_ = dv_post("cserver"); //*************************
	$hole_port_ = dv_post("holepunch_port"); //*****

	$uci = new uci();
	$uci->mode("set");

	if($hole_enable_ == "1"){
		$uci->set("holepunch.opts.holepunch_enabled","1");
		if($cserver_ != "*************************" && $cserver_ != ""){
			$uci->set("holepunch.opts.holepunch_cserver",$cserver_);
		}
		if($hole_port_ != "*****" && $hole_port_ != ""){
			$uci->set("holepunch.opts.holepunch_cport",$hole_port_);
		}
	}else{
		$uci->set("holepunch.opts.holepunch_enabled","0");
	}
	$uci->run();
	$uci->commit();
	$uci->close();
	$cmd = new dvcmd();
	$cmd->add("snmp_restart");
	$cmd->run();
	$cmd->result();
	$cmd->close();
	usleep(700);
	header("Location:".dv_post("submit-url"));

?>