<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");

	$snmp_enable_ = dv_post("snmpEnable");
	$snmp_get_enable_ = dv_post("getsnmpEnable");
	$snmp_set_enable_ = dv_post("setsnmpEnable");
	$get_type_ = dv_post("getType");
	$get_pass_ = dv_post("getCom"); //*****
	$set_type_ = dv_post("setType");
	$set_pass_ = dv_post("setCom"); //*****
	$trap_enable_ = dv_post("snmpTrapEnable");
	$trap_community_ = dv_post("trapCommunity"); //******
	$trap_server_ = dv_post("trapServer"); //******
	$trap_server2_ = dv_post("trapServer2"); //******

	$uci = new uci();
	$uci->mode("set");
	if($snmp_enable_ == "1"){
		$uci->set("snmp.config.enable","enable");
	}else{
		$uci->set("snmp.config.enable","disable");
	}
	$get_val = "";
	$set_val = "";
	if($snmp_get_enable_ == "1"){
		$get_val = "1";
	}else{
		$get_val = "0";
	}
	if($get_type_ == "read_only"){
		$get_val.="_0";
	}else{
		$get_val.="_1";
	}
	$uci->set("snmp.config.snmp_com1",$get_val);
	if($get_pass_ != "" && $get_pass_ != "*****"){
		$uci->set("snmp.config.get_community",$get_pass_);
	}

	if($snmp_set_enable_ == "1"){
		$set_val = "1";
	}else{
		$set_val = "0";
	}
	if($set_type_ == "read_only"){
		$set_val.="_0";
	}else{
		$set_val.="_1";
	}
	$uci->set("snmp.config.snmp_com2",$set_val);
	if($set_pass_ != "" && $set_pass_ != "*****"){
		$uci->set("snmp.config.set_community",$set_pass_);
	}
	if($trap_enable_ == "1"){
		$uci->set("snmp.config.trap_enable","enable");
	}else{
		$uci->set("snmp.config.trap_enable","disable");
	}
	if($trap_community_ != "" && $trap_community_ != "******"){
		$uci->set("snmp.config.trap_community",$trap_community_);
	}
	if($trap_server_ != "" && $trap_server_ != "******"){
		$uci->set("snmp.config.snmp_trap_server",$trap_server_);
	}
	if($trap_server2_ != "" && $trap_server2_ != "******"){
		$uci->set("snmp.config.wifi_trap_server",$trap_server2_);
	}
	$uci->run();
	$uci->commit();
	$uci->result();
	$uci->close();
	$param = null;
	$sock = new rcqm();
	$sock->connect();
	$diag = Array();
	if($sock->con()){
		$sock->write("snmp_cfg_reload",$param);
		$diag = $sock->read();
	}
	$sock->disconnect();
	$cmd = new dvcmd();
	$cmd->add("snmp_restart");
	$cmd->run();
	$cmd->result();
	$cmd->close();
	usleep(500);
	header("Location:".dv_post("submit-url"));
	
?>