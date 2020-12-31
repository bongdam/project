<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	$submit_url_ = dv_post("submit-url");
	$act_ = dv_post("act");
	$syscall = new dvcmd();
	if($submit_url_ == "/skb_tcpiplan.php"){
		$syscall->add("dhcp_reload");
	}
	
	Switch($act_){
		case "network_restart":
			$syscall->add("dvmgmt","/log/output/web WEB: network cfg apply. (".dv_session("user_id").":".$_SERVER['REMOTE_ADDR'].")");
			$syscall->add("dvmgmt","TEST/SKb2gbw_restart");
			$syscall->add("network_restart");
			$syscall->add("snmp_restart");
			$syscall->add("dhcpr_reload");
			break;
		case "system_restart":
			$syscall->add("dvmgmt","/log/output/web WEB: system reboot by user. (".dv_session("user_id").":".$_SERVER['REMOTE_ADDR'].")");
			$syscall->add("reboot");
			$uci = new uci();
			$uci->mode("del");
			$uci->del("system.reboot");
			$uci->run();
			$uci->result();
			$uci->commit();
			$uci->close();
			break;
		case "system_factory":
			$syscall->add("restore","factory","!");
			break;
	}
	$syscall->run("fast");
	echo("network restart.");
	$syscall->close();
?>
