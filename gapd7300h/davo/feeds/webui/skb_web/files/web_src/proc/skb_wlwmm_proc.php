<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$act_ = dv_post("act");
	$dscp_ = dv_post("dscp");
	$radio_ = dv_session("wlan_id");
	if(DEF_MODEL != "QCA_REF" && DEF_ANT == "4x4"){
		if($radio_ == "0"){
			$radio = "1";
		}else{
			$radio = "0";
		}
	}else{
		exit;
	}
	if($act_ == "set_wmm"){
		$uci = new uci();
		$uci->mode("set");
		$uci->set("wireless.wifi".$radio.".dscp_wmm_map",$dscp_);
		$uci->run();
		$uci->commit();
		$uci->close();
		echo("1");
	}
?>