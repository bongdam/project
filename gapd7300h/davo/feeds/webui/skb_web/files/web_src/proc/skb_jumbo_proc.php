<?php
	require_once($_SERVER["DOCUMENT_ROOT"]."/inc/default_ssi.php");
	require_once($_SERVER["DOCUMENT_ROOT"]."/skb_common.php");
	$jumbo_enable_ = dv_post("jumbo_enable");

	$uci = new uci();
	if($jumbo_enable_ == "0"){
		$uci->mode("del");
		$uci->del("network.miscframemaxsize");
//		$uci->del("network.wan.mtu");
//		$uci->del("network.lan.mtu");
		$uci->run();
		$uci->mode("set");
		$uci->set("network.wan.mtu","1500");
		$uci->set("network.lan.mtu","1500");
//		$uci->set("system.reboot","reboot");
//		$uci->set("system.reboot.status","1");
	}else{
		$uci->mode("set");
		$uci->set("network.miscframemaxsize","switch_ext");
		$uci->set("network.miscframemaxsize.device","switch0");
		$uci->set("network.miscframemaxsize.name","MiscFrameMaxSize");
		$uci->set("network.miscframemaxsize.frame_max_size","2290");
		$uci->set("network.wan.mtu","2290");
		$uci->set("network.lan.mtu","2290");
//		$uci->set("system.reboot","reboot");
//		$uci->set("system.reboot.status","1");
	}
	$uci->run();
	$uci->commit();
	echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));

?>
