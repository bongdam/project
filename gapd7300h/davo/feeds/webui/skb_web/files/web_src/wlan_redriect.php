<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	$wlan_id_ = dv_get("wlan_id");
	if($wlan_id_ != ""){
		dv_set_session("wlan_id",$wlan_id_);
	}
	if(dv_get("redirect-url") != ""){
		header('Location: '.dv_get("redirect-url").'?wlan_id='.$wlan_id_);
	}else{
		header('Location: skb_sub_menu_wlan.php?wlan_id='.$wlan_id_);
	}
?>