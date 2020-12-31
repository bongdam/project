<?php
	require_once($_SERVER["DOCUMENT_ROOT"]."/inc/default_ssi.php");
	require_once($_SERVER["DOCUMENT_ROOT"]."/skb_common.php");
	$act_ = dv_post("act");
	$ipaddr_ = dv_post("ip");

	
/*
	config redirect
        option target 'DNAT'
        option src 'wan'
        option dest 'lan'
        option proto 'all'
        option name 'DMZ'
        option dest_ip '192.168.35.150'
*/
	if(dv_post("dmzMode") == "dmz"){
		if($ipaddr_ != ""){
			$uci = new uci();
			$uci->mode("del");
			$uci->del("firewall.dmz");
			$uci->run();
			$uci->mode("set");
			$uci->set("firewall.dmz","redirect");
			$uci->set("firewall.dmz.target","DNAT");
			$uci->set("firewall.dmz.src","wan");
			$uci->set("firewall.dmz.dest","lan");
			$uci->set("firewall.dmz.proto","all");
			$uci->set("firewall.dmz.name","DMZ");
			$uci->set("firewall.dmz.dest_ip",$ipaddr_);
			$uci->run();
			$uci->commit();
//			echo("1");
		}else{
//			echo("0");
		}
	}else{
		$uci = new uci();
		$uci->mode("del");
		$uci->del("firewall.dmz");
		$uci->run();
		$uci->commit();
//		echo("1");
	}
	echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));
?>