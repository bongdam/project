<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	
	$auto_enable_ = dv_post("autoreboot_enabled");
	$auto_usr_enable_ = dv_post("autoreboot_userforce");
	$auto_idle_ = dv_post("autoreboot_on_idle");
	$auto_uptime_ = dv_post("autoreboot_uptime");
	$auto_wan_ = dv_post("autoreboot_wan_idle");
	$auto_time_ = dv_post("autoreboot_time");
	$auto_week_ = dv_post("autoreboot_week_s");
	$auto_rate_ = dv_post("autoreboot_kbps");

	$uci = new uci();
	$uci->mode("set");
	if($auto_enable_ == "1"){
		$uci->set("dvmgmt.auto_reboot.auto_reboot_enable","1");
	}else{
		$uci->set("dvmgmt.auto_reboot.auto_reboot_enable","0");
	}

	if($auto_usr_enable_ == "1"){
		$uci->set("dvmgmt.auto_reboot.usr_auto_reboot_enable","1");
	}else{
		$uci->set("dvmgmt.auto_reboot.usr_auto_reboot_enable","0");
	}
	if($auto_idle_ == "1"){
		$uci->set("dvmgmt.auto_reboot.usr_auto_reboot_on_idle","1");
	}else{
		$uci->set("dvmgmt.auto_reboot.usr_auto_reboot_on_idle","0");
	}
	if($auto_uptime_ != ""){
		$uci->set("dvmgmt.auto_reboot.usr_uptime",$auto_uptime_);
	}
	if($auto_wan_ == "1"){
		$uci->set("dvmgmt.auto_reboot.usr_wan_port_idle","1");
	}else{
		$uci->set("dvmgmt.auto_reboot.usr_wan_port_idle","0");
	}

	if($auto_time_ != ""){
		$uci->set("dvmgmt.auto_reboot.usr_hour_range",$auto_time_);
	}
	if($auto_week_ != ""){
		$uci->set("dvmgmt.auto_reboot.usr_day_of_week",$auto_week_);
	}
	if($auto_rate_ != ""){
		$uci->set("dvmgmt.auto_reboot.usr_auto_avg_data",$auto_rate_);
	}
	$uci->run();
	$uci->result();
	$uci->commit();
	$uci->close();
	$cmd = new dvcmd();
	$cmd->add("dvmgmt","/TEST/Autoreboot reload");
	$cmd->run();
	$cmd->result();
	$cmd->close();
	header("Location:".dv_post("submit-url"));
?>