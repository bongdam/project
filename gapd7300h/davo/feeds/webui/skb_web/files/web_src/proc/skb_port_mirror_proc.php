<?php
	require_once($_SERVER["DOCUMENT_ROOT"]."/inc/default_ssi.php");
	require_once($_SERVER["DOCUMENT_ROOT"]."/skb_common.php");
	$portMirrorMode_ = dv_post("portMirrorMode");

	$uci = new uci();
	$port_from_ = dv_post("port_from");
	$port_to_ = dv_post("port_to");
	$status = "enable";
	if($portMirrorMode_ == "0"){
		
		$status = "disable";
	}
	$uci->mode("del");
	$uci->del("network.mirroranalypt");
	$uci->del("network.mirrorptingress");
	$uci->del("network.mirrorptegress");
	$uci->run();
	$uci->mode("set");
	$uci->set("network.mirroranalypt","switch_ext");
	$uci->set("network.mirroranalypt.device","switch0");
	$uci->set("network.mirroranalypt.name","MirrorAnalyPt");
	$uci->set("network.mirroranalypt.analyst_port",$port_to_);

	$uci->set("network.mirrorptingress","switch_ext");
	$uci->set("network.mirrorptingress.device","switch0");
	$uci->set("network.mirrorptingress.name","MirrorPtIngress");
	$uci->set("network.mirrorptingress.ingress_port",$port_from_);
	$uci->set("network.mirrorptingress.status",$status);

	$uci->set("network.mirrorptegress","switch_ext");
	$uci->set("network.mirrorptegress.device","switch0");
	$uci->set("network.mirrorptegress.name","MirrorPtEgress");
	$uci->set("network.mirrorptegress.egress_port",$port_from_);
	$uci->set("network.mirrorptegress.status",$status);
	$uci->run();
	$uci->commit();
	echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));

?>