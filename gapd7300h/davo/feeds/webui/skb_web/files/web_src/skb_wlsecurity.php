<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$uci = new uci();
	$uci->mode("get");
	$wlan_id = dv_session("wlan_id");
	if(DEF_MODEL != "QCA_REF" && DEF_ANT == "4x4"){
			$uci->get("wireless.wifi1");
			$uci->get("wireless.vap10");
			$uci->get("wireless.vap11");
			$uci->get("wireless.vap12");
			$uci->get("wireless.wifi0");
			$uci->get("wireless.vap00");
			$uci->get("wireless.vap01");
			$uci->get("wireless.vap02");
	}
	$uci->run();
	$wifi = json_decode($uci->result(),true);
	$ssid24 = Array();
	$ssid5 = Array();
	$ssid_disable24 = Array();
	$ssid_disable5 = Array();
	$enc24 = Array();
	$enc5 = Array();
	$auth_mode24 = Array();
	$auth_mode5 = Array();
	$cipher24 = Array();
	$cipher5 = Array();
	$keytype24 = Array();
	$keytype5 = Array();

	$macauth24 = Array();
	$macauth5 = Array();

	function auth_clean($val_){
		$val = "";
		$val = str_replace("wpa-mixed+","",$val_);
		$val = str_replace("wpa2+","",$val);
		$val = str_replace("wpa+","",$val);

		$val = str_replace("psk-mixed+","",$val);
		$val = str_replace("psk2+","",$val);
		$val = str_replace("psk+","",$val);

		$val = str_replace("wep+","",$val);
		return $val;
	}
	function cipher_clean($val_){
		$val = "";
		$val = str_replace("+tkip+aes","",$val_);
		$val = str_replace("+tkip","",$val);
		$val = str_replace("+aes","",$val);
		$val = str_replace("+shared","",$val);
		$val = str_replace("+open","",$val);
		$val = str_replace("+mixed","",$val);
//		$val = str_replace("psk","wpa",$val);
		return $val;
	}

//	if($wlan_id == "0"){
		$ssid24[] = get_array_val($wifi,"wireless.vap10.ssid","1");
		$ssid24[] = get_array_val($wifi,"wireless.vap11.ssid","1");
		$ssid24[] = get_array_val($wifi,"wireless.vap12.ssid","1");
		$ssid_disable24[] = get_array_val($wifi,"wireless.vap10.disabled","1");
		$ssid_disable24[] = get_array_val($wifi,"wireless.vap11.disabled","1");
		$ssid_disable24[] = get_array_val($wifi,"wireless.vap12.disabled","1");
		if(get_array_val($wifi,"wireless.vap10.encryption","1") == "8021x"){
			$enc24[] = "wep+mixed";
		}else{
			$enc24[] = get_array_val($wifi,"wireless.vap10.encryption","1");
		}
		if(get_array_val($wifi,"wireless.vap11.encryption","1") == "8021x"){
			$enc24[] = "wep+mixed";
		}else{
			$enc24[] = get_array_val($wifi,"wireless.vap11.encryption","1");
		}
		if(get_array_val($wifi,"wireless.vap12.encryption","1") == "8021x"){
			$enc24[] = "wep+mixed";
		}else{
			$enc24[] = get_array_val($wifi,"wireless.vap12.encryption","1");
		}
		$auth_mode24[] = cipher_clean($enc24[0]);
		$auth_mode24[] = cipher_clean($enc24[1]);
		$auth_mode24[] = cipher_clean($enc24[2]);
		if(auth_clean($enc24[0]) == "tkip+aes"){
			$cipher24[] = "tkip+aes";
		}elseif(auth_clean($enc24[0]) == "tkip") {
			$cipher24[] = "tkip";
		}elseif(auth_clean($enc24[0]) == "aes"){
			$cipher24[] = "aes";
		}elseif(auth_clean($enc24[0]) == "open"){
			$cipher24[] = "open";
		}elseif(auth_clean($enc24[0]) == "shared"){
			$cipher24[] = "shared";
		}elseif(auth_clean($enc24[0]) == "mixed"){
			$cipher24[] = "mixed";
		}
		if(auth_clean($enc24[1]) == "tkip+aes"){
			$cipher24[] = "tkip+aes";
		}elseif(auth_clean($enc24[1]) == "tkip"){
			$cipher24[] = "tkip";
		}elseif(auth_clean($enc24[1]) == "aes"){
			$cipher24[] = "aes";
		}elseif(auth_clean($enc24[1]) == "open"){
			$cipher24[] = "open";
		}elseif(auth_clean($enc24[1]) == "shared"){
			$cipher24[] = "shared";
		}elseif(auth_clean($enc24[1]) == "mixed"){
			$cipher24[] = "mixed";
		}
		if(auth_clean($enc24[2]) == "tkip+aes"){
			$cipher24[] = "tkip+aes";
		}elseif(auth_clean($enc24[2]) == "tkip"){
			$cipher24[] = "tkip";
		}elseif(auth_clean($enc24[2]) == "aes"){
			$cipher24[] = "aes";
		}elseif(auth_clean($enc24[2]) == "open"){
			$cipher24[] = "open";
		}elseif(auth_clean($enc24[2]) == "shared"){
			$cipher24[] = "shared";
		}elseif(auth_clean($enc24[2]) == "mixed"){
			$cipher24[] = "mixed";
		}
		$cipher242[] = get_array_val($wifi,"wireless.vap10.rsn_pairwise");
		$cipher242[] = get_array_val($wifi,"wireless.vap11.rsn_pairwise");
		$cipher242[] = get_array_val($wifi,"wireless.vap12.rsn_pairwise");
		if(get_array_val($wifi,"wireless.vap10.key") != ""){
			$key24[] = "1";
		}else{
			$key24[] = "0";
		}
		if(get_array_val($wifi,"wireless.vap11.key") != ""){
			$key24[] = "1";
		}else{
			$key24[] = "0";
		}
		if(get_array_val($wifi,"wireless.vap12.key") != ""){
			$key24[] = "1";
		}else{
			$key24[] = "0";
		}
		$keytype24[] = get_array_val($wifi,"wireless.vap10.key_type","1");
		$keytype24[] = get_array_val($wifi,"wireless.vap11.key_type","1");
		$keytype24[] = get_array_val($wifi,"wireless.vap12.key_type","1");

		$radius_ip24[] = get_array_val($wifi,"wireless.vap10.auth_server","1");
		$radius_ip24[] = get_array_val($wifi,"wireless.vap11.auth_server","1");
		$radius_ip24[] = get_array_val($wifi,"wireless.vap12.auth_server","1");

		$radius_port24[] = get_array_val($wifi,"wireless.vap10.auth_port","1");
		$radius_port24[] = get_array_val($wifi,"wireless.vap11.auth_port","1");
		$radius_port24[] = get_array_val($wifi,"wireless.vap12.auth_port","1");

		$radius_retry24[] = get_array_val($wifi,"wireless.vap10.radius_server_retries","1");
		$radius_retry24[] = get_array_val($wifi,"wireless.vap11.radius_server_retries","1");
		$radius_retry24[] = get_array_val($wifi,"wireless.vap12.radius_server_retries","1");

		$radius_intv24[] = get_array_val($wifi,"wireless.vap10.radius_max_retry_wait","1");
		$radius_intv24[] = get_array_val($wifi,"wireless.vap11.radius_max_retry_wait","1");
		$radius_intv24[] = get_array_val($wifi,"wireless.vap12.radius_max_retry_wait","1");

		$acct_use24[] = get_array_val($wifi,"wireless.vap10.acct_server_use","1");
		$acct_use24[] = get_array_val($wifi,"wireless.vap11.acct_server_use","1");
		$acct_use24[] = get_array_val($wifi,"wireless.vap12.acct_server_use","1");

		$acct_ip24[] = get_array_val($wifi,"wireless.vap10.acct_server","1");
		$acct_ip24[] = get_array_val($wifi,"wireless.vap11.acct_server","1");
		$acct_ip24[] = get_array_val($wifi,"wireless.vap12.acct_server","1");

		$acct_port24[] = get_array_val($wifi,"wireless.vap10.acct_port","1");
		$acct_port24[] = get_array_val($wifi,"wireless.vap11.acct_port","1");
		$acct_port24[] = get_array_val($wifi,"wireless.vap12.acct_port","1");

		$acct_retry_use24[] = get_array_val($wifi,"wireless.vap10.acct_interim_use","1");
		$acct_retry_use24[] = get_array_val($wifi,"wireless.vap11.acct_interim_use","1");
		$acct_retry_use24[] = get_array_val($wifi,"wireless.vap12.acct_interim_use","1");

		$acct_delay_time24[] = get_array_val($wifi,"wireless.vap10.radius_acct_interim_interval","1");
		$acct_delay_time24[] = get_array_val($wifi,"wireless.vap11.radius_acct_interim_interval","1");
		$acct_delay_time24[] = get_array_val($wifi,"wireless.vap12.radius_acct_interim_interval","1");

		//WEP
		$wep_radius24[] = get_array_val($wifi,"wireless.vap10.wep_radius");
		$wep_radius24[] = get_array_val($wifi,"wireless.vap11.wep_radius");
		$wep_radius24[] = get_array_val($wifi,"wireless.vap12.wep_radius");

		$wep_len24[] = get_array_val($wifi,"wireless.vap10.wep_key_len","1");
		$wep_len24[] = get_array_val($wifi,"wireless.vap11.wep_key_len","1");
		$wep_len24[] = get_array_val($wifi,"wireless.vap12.wep_key_len","1");

		$wep_type24[] = get_array_val($wifi,"wireless.vap10.wep_key_type","1");
		$wep_type24[] = get_array_val($wifi,"wireless.vap11.wep_key_type","1");
		$wep_type24[] = get_array_val($wifi,"wireless.vap12.wep_key_type","1");

		$wep_key24[] = get_array_val($wifi,"wireless.vap10.wep_key","1");
		$wep_key24[] = get_array_val($wifi,"wireless.vap11.wep_key","1");
		$wep_key24[] = get_array_val($wifi,"wireless.vap12.wep_key","1");

		$wep_macaddr24[] = get_array_val($wifi,"wireless.vap10.wep_macaddr","1");
		$wep_macaddr24[] = get_array_val($wifi,"wireless.vap11.wep_macaddr","1");
		$wep_macaddr24[] = get_array_val($wifi,"wireless.vap12.wep_macaddr","1");

		if(get_array_val($wifi,"wireless.vap10.key1","1") != ""){
			$key124[] = "1";
		}else{
			$key124[] = "";
		}
		if(get_array_val($wifi,"wireless.vap11.key1","1") != ""){
			$key124[] = "1";
		}else{
			$key124[] = "";
		}
		if(get_array_val($wifi,"wireless.vap12.key1","1") != ""){
			$key124[] = "1";
		}else{
			$key124[] = "";
		}
		if(get_array_val($wifi,"wireless.vap10.key2","1") != ""){
			$key224[] = "1";
		}else{
			$key224[] = "";
		}
		if(get_array_val($wifi,"wireless.vap11.key2","1") != ""){
			$key224[] = "1";
		}else{
			$key224[] = "";
		}
		if(get_array_val($wifi,"wireless.vap12.key2","1") != ""){
			$key224[] = "1";
		}else{
			$key224[] = "";
		}
		if(get_array_val($wifi,"wireless.vap10.key3","1") != ""){
			$key324[] = "1";
		}else{
			$key324[] = "";
		}
		if(get_array_val($wifi,"wireless.vap11.key3","1") != ""){
			$key324[] = "1";
		}else{
			$key324[] = "";
		}
		if(get_array_val($wifi,"wireless.vap12.key3","1") != ""){
			$key324[] = "1";
		}else{
			$key324[] = "";
		}
		if(get_array_val($wifi,"wireless.vap10.key4","1") != ""){
			$key424[] = "1";
		}else{
			$key424[] = "";
		}
		if(get_array_val($wifi,"wireless.vap11.key4","1") != ""){
			$key424[] = "1";
		}else{
			$key424[] = "";
		}
		if(get_array_val($wifi,"wireless.vap12.key4","1") != ""){
			$key424[] = "1";
		}else{
			$key424[] = "";
		}
		if(get_array_val($wifi,"wireless.vap10.macaddr_acl","1") == "2"){
			$macauth24[] = "2";
		}else{
			$macauth24[] = "";
		}
		if(get_array_val($wifi,"wireless.vap11.macaddr_acl","1") == "2"){
			$macauth24[] = "2";
		}else{
			$macauth24[] = "";
		}
		if(get_array_val($wifi,"wireless.vap12.macaddr_acl","1") == "2"){
			$macauth24[] = "2";
		}else{
			$macauth24[] = "";
		}

		
//	}else{
		$ssid5[] = get_array_val($wifi,"wireless.vap00.ssid","1");
		$ssid5[] = get_array_val($wifi,"wireless.vap01.ssid","1");
		$ssid5[] = get_array_val($wifi,"wireless.vap02.ssid","1");
		$ssid_disable5[] = get_array_val($wifi,"wireless.vap00.disabled","1");
		$ssid_disable5[] = get_array_val($wifi,"wireless.vap01.disabled","1");
		$ssid_disable5[] = get_array_val($wifi,"wireless.vap02.disabled","1");
		if(get_array_val($wifi,"wireless.vap00.encryption","1") == "8021x"){
			$enc5[] = "wep+mixed";
		}else{
			$enc5[] = get_array_val($wifi,"wireless.vap00.encryption","1");
		}
		if(get_array_val($wifi,"wireless.vap01.encryption","1") == "8021x"){
			$enc5[] = "wep+mixed";
		}else{
			$enc5[] = get_array_val($wifi,"wireless.vap01.encryption","1");
		}
		if(get_array_val($wifi,"wireless.vap02.encryption","1") == "8021x"){
			$enc5[] = "wep+mixed";
		}else{
			$enc5[] = get_array_val($wifi,"wireless.vap02.encryption","1");
		}

		$auth_mode5[] = cipher_clean($enc5[0]);
		$auth_mode5[] = cipher_clean($enc5[1]);
		$auth_mode5[] = cipher_clean($enc5[2]);

		if(auth_clean($enc5[0]) == "tkip+aes"){
			$cipher5[] = "tkip+aes";
		}elseif(auth_clean($enc5[0]) == "tkip") {
			$cipher5[] = "tkip";
		}elseif(auth_clean($enc5[0]) == "aes"){
			$cipher5[] = "aes";
		}elseif(auth_clean($enc5[0]) == "open"){
			$cipher5[] = "open";
		}elseif(auth_clean($enc5[0]) == "shared"){
			$cipher5[] = "shared";
		}elseif(auth_clean($enc5[0]) == "mixed"){
			$cipher5[] = "mixed";
		}
		if(auth_clean($enc5[1]) == "tkip+aes"){
			$cipher5[] = "tkip+aes";
		}elseif(auth_clean($enc5[1]) == "tkip"){
			$cipher5[] = "tkip";
		}elseif(auth_clean($enc5[1]) == "aes"){
			$cipher5[] = "aes";
		}elseif(auth_clean($enc5[1]) == "open"){
			$cipher5[] = "open";
		}elseif(auth_clean($enc5[1]) == "shared"){
			$cipher5[] = "shared";
		}elseif(auth_clean($enc5[1]) == "mixed"){
			$cipher5[] = "mixed";
		}
		if(auth_clean($enc5[2]) == "tkip+aes"){
			$cipher5[] = "tkip+aes";
		}elseif(auth_clean($enc5[2]) == "tkip"){
			$cipher5[] = "tkip";
		}elseif(auth_clean($enc5[2]) == "aes"){
			$cipher5[] = "aes";
		}elseif(auth_clean($enc5[2]) == "open"){
			$cipher5[] = "open";
		}elseif(auth_clean($enc5[2]) == "shared"){
			$cipher5[] = "shared";
		}elseif(auth_clean($enc5[2]) == "mixed"){
			$cipher5[] = "mixed";
		}
		$cipher52[] = get_array_val($wifi,"wireless.vap00.rsn_pairwise");
		$cipher52[] = get_array_val($wifi,"wireless.vap01.rsn_pairwise");
		$cipher52[] = get_array_val($wifi,"wireless.vap02.rsn_pairwise");
		if(get_array_val($wifi,"wireless.vap00.key") != ""){
			$key5[] = "1";
		}else{
			$key5[] = "0";
		}
		if(get_array_val($wifi,"wireless.vap01.key") != ""){
			$key5[] = "1";
		}else{
			$key5[] = "0";
		}
		if(get_array_val($wifi,"wireless.vap02.key") != ""){
			$key5[] = "1";
		}else{
			$key5[] = "0";
		}
		$keytype5[] = get_array_val($wifi,"wireless.vap00.key_type","1");
		$keytype5[] = get_array_val($wifi,"wireless.vap01.key_type","1");
		$keytype5[] = get_array_val($wifi,"wireless.vap02.key_type","1");

		$radius_ip5[] = get_array_val($wifi,"wireless.vap00.auth_server","1");
		$radius_ip5[] = get_array_val($wifi,"wireless.vap01.auth_server","1");
		$radius_ip5[] = get_array_val($wifi,"wireless.vap02.auth_server","1");

		$radius_port5[] = get_array_val($wifi,"wireless.vap00.auth_port","1");
		$radius_port5[] = get_array_val($wifi,"wireless.vap01.auth_port","1");
		$radius_port5[] = get_array_val($wifi,"wireless.vap02.auth_port","1");

		$radius_retry5[] = get_array_val($wifi,"wireless.vap00.radius_server_retries","1");
		$radius_retry5[] = get_array_val($wifi,"wireless.vap01.radius_server_retries","1");
		$radius_retry5[] = get_array_val($wifi,"wireless.vap02.radius_server_retries","1");

		$radius_intv5[] = get_array_val($wifi,"wireless.vap00.radius_max_retry_wait","1");
		$radius_intv5[] = get_array_val($wifi,"wireless.vap01.radius_max_retry_wait","1");
		$radius_intv5[] = get_array_val($wifi,"wireless.vap02.radius_max_retry_wait","1");

		$acct_use5[] = get_array_val($wifi,"wireless.vap00.acct_server_use","1");
		$acct_use5[] = get_array_val($wifi,"wireless.vap01.acct_server_use","1");
		$acct_use5[] = get_array_val($wifi,"wireless.vap02.acct_server_use","1");

		$acct_ip5[] = get_array_val($wifi,"wireless.vap00.acct_server","1");
		$acct_ip5[] = get_array_val($wifi,"wireless.vap01.acct_server","1");
		$acct_ip5[] = get_array_val($wifi,"wireless.vap02.acct_server","1");

		$acct_port5[] = get_array_val($wifi,"wireless.vap00.acct_port","1");
		$acct_port5[] = get_array_val($wifi,"wireless.vap01.acct_port","1");
		$acct_port5[] = get_array_val($wifi,"wireless.vap02.acct_port","1");

		$acct_retry_use5[] = get_array_val($wifi,"wireless.vap00.acct_interim_use","1");
		$acct_retry_use5[] = get_array_val($wifi,"wireless.vap01.acct_interim_use","1");
		$acct_retry_use5[] = get_array_val($wifi,"wireless.vap02.acct_interim_use","1");

		$acct_delay_time5[] = get_array_val($wifi,"wireless.vap00.radius_acct_interim_interval","1");
		$acct_delay_time5[] = get_array_val($wifi,"wireless.vap01.radius_acct_interim_interval","1");
		$acct_delay_time5[] = get_array_val($wifi,"wireless.vap02.radius_acct_interim_interval","1");
		
		//WEP
		$wep_radius5[] = get_array_val($wifi,"wireless.vap00.wep_radius");
		$wep_radius5[] = get_array_val($wifi,"wireless.vap01.wep_radius");
		$wep_radius5[] = get_array_val($wifi,"wireless.vap02.wep_radius");

		$wep_len5[] = get_array_val($wifi,"wireless.vap00.wep_key_len","1");
		$wep_len5[] = get_array_val($wifi,"wireless.vap01.wep_key_len","1");
		$wep_len5[] = get_array_val($wifi,"wireless.vap02.wep_key_len","1");

		$wep_type5[] = get_array_val($wifi,"wireless.vap00.wep_key_type","1");
		$wep_type5[] = get_array_val($wifi,"wireless.vap01.wep_key_type","1");
		$wep_type5[] = get_array_val($wifi,"wireless.vap02.wep_key_type","1");

		$wep_key5[] = get_array_val($wifi,"wireless.vap00.wep_key","1");
		$wep_key5[] = get_array_val($wifi,"wireless.vap01.wep_key","1");
		$wep_key5[] = get_array_val($wifi,"wireless.vap02.wep_key","1");

		$wep_macaddr5[] = get_array_val($wifi,"wireless.vap00.wep_macaddr","1");
		$wep_macaddr5[] = get_array_val($wifi,"wireless.vap01.wep_macaddr","1");
		$wep_macaddr5[] = get_array_val($wifi,"wireless.vap02.wep_macaddr","1");

		if(get_array_val($wifi,"wireless.vap00.key1","1") != ""){
			$key15[] = "1";
		}else{
			$key15[] = "";
		}
		if(get_array_val($wifi,"wireless.vap01.key1","1") != ""){
			$key15[] = "1";
		}else{
			$key15[] = "";
		}
		if(get_array_val($wifi,"wireless.vap02.key1","1") != ""){
			$key15[] = "1";
		}else{
			$key15[] = "";
		}
		if(get_array_val($wifi,"wireless.vap00.key2","1") != ""){
			$key25[] = "1";
		}else{
			$key25[] = "";
		}
		if(get_array_val($wifi,"wireless.vap01.key2","1") != ""){
			$key25[] = "1";
		}else{
			$key25[] = "";
		}
		if(get_array_val($wifi,"wireless.vap02.key2","1") != ""){
			$key25[] = "1";
		}else{
			$key25[] = "";
		}
		if(get_array_val($wifi,"wireless.vap00.key3","1") != ""){
			$key35[] = "1";
		}else{
			$key35[] = "";
		}
		if(get_array_val($wifi,"wireless.vap01.key3","1") != ""){
			$key35[] = "1";
		}else{
			$key35[] = "";
		}
		if(get_array_val($wifi,"wireless.vap02.key3","1") != ""){
			$key35[] = "1";
		}else{
			$key35[] = "";
		}
		if(get_array_val($wifi,"wireless.vap00.key4","1") != ""){
			$key45[] = "1";
		}else{
			$key45[] = "";
		}
		if(get_array_val($wifi,"wireless.vap01.key4","1") != ""){
			$key45[] = "1";
		}else{
			$key45[] = "";
		}
		if(get_array_val($wifi,"wireless.vap02.key4","1") != ""){
			$key45[] = "1";
		}else{
			$key45[] = "";
		}
		if(get_array_val($wifi,"wireless.vap00.macaddr_acl","1") == "2"){
			$macauth5[] = "2";
		}else{
			$macauth5[] = "";
		}
		if(get_array_val($wifi,"wireless.vap01.macaddr_acl","1") == "2"){
			$macauth5[] = "2";
		}else{
			$macauth5[] = "";
		}
		if(get_array_val($wifi,"wireless.vap02.macaddr_acl","1") == "2"){
			$macauth5[] = "2";
		}else{
			$macauth5[] = "";
		}
//	}
//	print_r($enc24);
//	print_r($enc5);
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>Wireless Security Setup</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<style>
.on {display:on}
.off {display:none}
.bggrey {
	BACKGROUND: #FFFFFF
}
.fieldset{
	border-right:#000000 1px solid;padding-right:10px;border-top:#000000 1px solid;padding-left:10px;padding-bottom:5px;border-left:#000000 1px solid;width:500px;padding-top:0px;border-bottom: #000000 1px solid;
}
</style>
<script type="text/javascript">
var wlan_idx=<?=$wlan_id?>;
var ssid24 = <?=json_to_array_string($ssid24);?>;
var ssid5 = <?=json_to_array_string($ssid5);?>;
var ssid_disable24 = <?=json_to_array_string($ssid_disable24);?>;
var ssid_disable5 = <?=json_to_array_string($ssid_disable5);?>;
var auth_mode24 = <?=json_to_array_string($auth_mode24);?>;
var auth_mode5 = <?=json_to_array_string($auth_mode5);?>;
var cipher24 = <?=json_to_array_string($cipher24);?>;
var cipher5 = <?=json_to_array_string($cipher5);?>;
var cipher242 = <?=json_to_array_string($cipher242);?>;
var cipher52 = <?=json_to_array_string($cipher52);?>;
var key24 = <?=json_to_array_string($key24);?>;
var key5 = <?=json_to_array_string($key5);?>;
var keytype24 = <?=json_to_array_string($keytype24);?>;
var keytype5 = <?=json_to_array_string($keytype5);?>;

var radius_ip24 = <?=json_to_array_string($radius_ip24);?>;
var radius_ip5 = <?=json_to_array_string($radius_ip5);?>;
var radius_port24 = <?=json_to_array_string($radius_port24);?>;
var radius_port5 = <?=json_to_array_string($radius_port5);?>;

var radius_retry24 = <?=json_to_array_string($radius_retry24);?>;
var radius_retry5 = <?=json_to_array_string($radius_retry5);?>;
var radius_intv24 = <?=json_to_array_string($radius_intv24);?>;
var radius_intv5 = <?=json_to_array_string($radius_intv5);?>;

var acct_use24 = <?=json_to_array_string($acct_use24);?>;
var acct_use5 = <?=json_to_array_string($acct_use5);?>;

var acct_ip24 = <?=json_to_array_string($acct_ip24);?>;
var acct_ip5 = <?=json_to_array_string($acct_ip5);?>;
var acct_port24 = <?=json_to_array_string($acct_port24);?>;
var acct_port5 = <?=json_to_array_string($acct_port5);?>;

var acct_retry_use24 = <?=json_to_array_string($acct_retry_use24);?>;
var acct_retry_use5 = <?=json_to_array_string($acct_retry_use5);?>;

var acct_delay_time24 = <?=json_to_array_string($acct_delay_time24);?>;
var acct_delay_time5 = <?=json_to_array_string($acct_delay_time5);?>;

var wep_len24 = <?=json_to_array_string($wep_len24)?>;
var wep_len5 = <?=json_to_array_string($wep_len5)?>;

var wep_type24 = <?=json_to_array_string($wep_type24)?>;
var wep_type5 = <?=json_to_array_string($wep_type5)?>;

var wep_key24 = <?=json_to_array_string($wep_key24);?>;
var wep_key5 = <?=json_to_array_string($wep_key5);?>;

var wep_radius24 = <?=json_to_array_string($wep_radius24);?>;
var wep_radius5 = <?=json_to_array_string($wep_radius5);?>;

var key124 = <?=json_to_array_string($key124);?>;
var key15 = <?=json_to_array_string($key15);?>;
var key224 = <?=json_to_array_string($key224);?>;
var key25 = <?=json_to_array_string($key25);?>;
var key324 = <?=json_to_array_string($key324);?>;
var key35 = <?=json_to_array_string($key35);?>;
var key424 = <?=json_to_array_string($key424);?>;
var key45 = <?=json_to_array_string($key45);?>;

var macauth24 = <?=json_to_array_string($macauth24);?>;
var macauth5 = <?=json_to_array_string($macauth5);?>;

var wep_macaddr24 = <?=json_to_array_string($wep_macaddr24);?>;
var wep_macaddr5 = <?=json_to_array_string($wep_macaddr5);?>;


function page_change(selectObj)
{
	if (selectObj.value==1)
		location.href='wlan_redriect.php?redirect-url=skb_wlsecurity.php&wlan_id=1';
	else
		location.href='wlan_redriect.php?redirect-url=skb_wlsecurity.php&wlan_id=0';
}

var create_ssid = function(){
	var tobj = $("#ssid");
	tobj.children().remove();
	if(wlan_idx == 0){
		for (var i=0; i < ssid24.length ; i++ )
		{
			if(ssid_disable24[i] != "1"){
				tobj.append("<option value=\""+ssid24[i]+"\" seq=\""+i+"\">"+ssid24[i]+"</option>");
			}
		}
	}else{
		for (var i=0; i < ssid5.length ; i++ )
		{
			if(ssid_disable5[i] != "1"){
				tobj.append("<option value=\""+ssid5[i]+"\" seq=\""+i+"\">"+ssid5[i]+"</option>");
			}
		}
	}
}
var change_ssid = function(){
	var ssid = $("#ssid").children("option").index($("#ssid").children(":selected"));
	var index = $("#ssid").children("option").eq(ssid).attr("seq");

	if(wlan_idx == 0){
		switch(auth_mode24[index]){
			case "wpa-mixed":
				$("#auth").val("wpa-mixed");
				$("#auth_type0").prop("checked",true);
				break;
			case "wpa2":
				$("#auth").val("wpa2");
				$("#auth_type0").prop("checked",true);
				break;
			case "wpa":
				$("#auth").val("wpa");
				$("#auth_type0").prop("checked",true);
				break;
			case "psk-mixed":
				$("#auth").val("wpa-mixed");
				$("#auth_type1").prop("checked",true);
				break;
			case "psk2":
				$("#auth").val("wpa2");
				$("#auth_type1").prop("checked",true);
				break;
			case "psk":
				$("#auth").val("wpa");
				$("#auth_type1").prop("checked",true);
				break;
			case "wep":
				$("#auth").val("wep");
				break;
			case "none":
				$("#auth").val("none");
				break;
		}
		switch(cipher24[index]){
			case "tkip+aes":
				$("#cipher0").prop("checked",true);
				$("#cipher1").prop("checked",true);
				break;
			case "tkip":
				$("#cipher0").prop("checked",true);
				$("#cipher1").prop("checked",false);
				break;
			case "aes":
				$("#cipher0").prop("checked",false);
				$("#cipher1").prop("checked",true);
				break;
			case "open":
				$("#auth_type10").prop("checked",true);
				break;
			case "shared":
				$("#auth_type11").prop("checked",true);
				break;
			case "mixed":
				$("#auth_type12").prop("checked",true);
				break;
			
		}
		switch(cipher242[index]){
			case "tkip+aes":
				$("#cipher20").prop("checked",true);
				$("#cipher21").prop("checked",true);
				break;
			case "tkip":
				$("#cipher20").prop("checked",true);
				$("#cipher21").prop("checked",false);
				break;
			case "aes":
				$("#cipher20").prop("checked",false);
				$("#cipher21").prop("checked",true);
				break;
		}
		var auth_type = $("[name='auth_type']:checked").val();
		switch(auth_type){
			case "psk":
				if(keytype24[index] == ""){
					$("#key_type").val("ascii");
				}else{
					$("#key_type").val(keytype24[index]);
				}
				$("#key").val("********");
				break;
			case "wpa":
				if(radius_ip24[index] == ""){
					$("#radius_ip").val("0.0.0.0");
				}else{
					$("#radius_ip").val(radius_ip24[index]);
				}
				break;
		}

	}else{
		switch(auth_mode5[index]){
			case "wpa-mixed":
				$("#auth").val("wpa-mixed");
				$("#auth_type0").prop("checked",true);
				break;
			case "wpa2":
				$("#auth").val("wpa2");
				$("#auth_type0").prop("checked",true);
				break;
			case "wpa":
				$("#auth").val("wpa");
				$("#auth_type0").prop("checked",true);
				break;
			case "psk-mixed":
				$("#auth").val("wpa-mixed");
				$("#auth_type1").prop("checked",true);
				break;
			case "psk2":
				$("#auth").val("wpa2");
				$("#auth_type1").prop("checked",true);
				break;
			case "psk":
				$("#auth").val("wpa");
				$("#auth_type1").prop("checked",true);
				break;
			case "wep":
				$("#auth").val("wep");
				break;
			case "none":
				$("#auth").val("none");
				break;
		}
		switch(cipher5[index]){
			case "tkip+aes":
				$("#cipher0").prop("checked",true);
				$("#cipher1").prop("checked",true);
				break;
			case "tkip":
				$("#cipher0").prop("checked",true);
				$("#cipher1").prop("checked",false);
				break;
			case "aes":
				$("#cipher0").prop("checked",false);
				$("#cipher1").prop("checked",true);
				break;
			case "open":
				$("#auth_type10").prop("checked",true);
				break;
			case "shared":
				$("#auth_type11").prop("checked",true);
				break;
			case "mixed":
				$("#auth_type12").prop("checked",true);
				break;
			
		}
		switch(cipher52[index]){
			case "tkip+aes":
				$("#cipher20").prop("checked",true);
				$("#cipher21").prop("checked",true);
				break;
			case "tkip":
				$("#cipher20").prop("checked",true);
				$("#cipher21").prop("checked",false);
				break;
			case "aes":
				$("#cipher20").prop("checked",false);
				$("#cipher21").prop("checked",true);
				break;
		}
	}
	change_auth();
	change_auth_type();
}
var change_auth = function(){
	var auth = $("#auth").children(":selected").val();
	var auth_type = $("[name='auth_type']:checked").val();
	if(auth_type == undefined){
		auth_type = "psk";
		$("#auth_type1").prop("checked",true);
		$("#key").val("********");
	}
	$(".wpa2").hide();
	switch(auth){
		case "wpa-mixed":
			$(".wpa2").show();
		case "wpa2":
		case "wpa":
			$(".no").hide();
			$(".wpa").show();
			$(".wep").hide();
			if(auth_type == "psk"){
				$(".psk").show();
				$(".radius").hide();
			}else{
				$(".psk").hide();
				$(".radius").show();
			}
			break;
		case "wep":
			$(".no").hide();
			$(".wep").show();
			$(".wpa").hide();
			$(".psk").hide();
			$(".radius").hide();
			$("#wep_radius").prop("checked",false);
			change_auth_type();
			
			break;
		case "none":
			$(".no").show();
			$(".wep").hide();
			$(".wpa").hide();
			$(".psk").hide();
			$(".radius").hide();
			$(".radius").find(".wpa").show();
			change_auth_type();
			break;
	}
}
var create_mask = function(wep_len_, wep_type_){
	if (wep_len_ == "64")
	{
		if(wep_type_ == "ascii"){
			return "*****";
		}else{
			return "**********";
		}
	}else{
		if(wep_type_ == "ascii"){
			return "*************";
		}else{
			return "**************************";
		}
	}
}
var change_auth_type = function(){
	var radio = $("#radio").children(":selected").val();
	var ssid = $("#ssid").children("option").index($("#ssid").children(":selected"));
	var index = $("#ssid").children("option").eq(ssid).attr("seq");
	var auth = $("#auth").children(":selected").val();
	var auth_type = $("[name='auth_type']:checked").val();
	if(auth_type == undefined){
		auth_type = "psk";
		$("#auth_type1").prop("checked",true);
		$("#key").val("********");
	}
	if(radio == "0"){
		if(auth == "wep"){
			if($("[name='auth_type1']:checked").val() == undefined ) {
				$("#auth_type10").prop("checked",true);
			}
			if(wep_len24[index] == ""){
				$("#wep_len").val("64");
			}else{
				$("#wep_len").val(wep_len24[index]);
			}
			if(wep_type24[index] == ""){
				$("#wep_type").val("ascii");
			}else{
				$("#wep_type").val(wep_type24[index]);
			}
			change_wep_len();
			if(wep_key24[index] == ""){
				$("#wep_key1").prop("checked",true);
			}else{
				$("#wep_key"+wep_key24[index]).prop("checked",true);
			}
			if(key124[index] == "1"){
				$("#key1").attr("flag",1);
			}
			if(key224[index] == "1"){
				$("#key2").attr("flag",1);
			}
			if(key324[index] == "1"){
				$("#key3").attr("flag",1);
			}
			if(key424[index] == "1"){
				$("#key4").attr("flag",1);
			}
			if(wep_radius24[index] == "1"){
				$("#wep_radius").prop("checked",true);
			}else{
				$("#wep_radius").prop("checked",false);
			}
			if(radius_ip24[index] == ""){
				$("#radius_ip").val("0.0.0.0");
			}else{
				$("#radius_ip").val(radius_ip24[index]);
			}
			if(radius_port24[index] == ""){
				$("#radius_port").val("1812");
			}else{
				$("#radius_port").val(radius_port24[index]);
			}
			if(radius_retry24[index] == ""){
				$("#radius_retry").val("3");
			}else{
				$("#radius_retry").val(radius_retry24[index]);
			}
			if(radius_intv24[index] == ""){
				$("#radius_intv").val("5");
			}else{
				$("#radius_intv").val(radius_intv24[index]);
			}
			if(acct_use24[index] == "1"){
				$("#acct_use").prop("checked",true);
			}else{
				$("#acct_use").prop("checked",false);
			}
			if(acct_ip24[index] == ""){
				$("#acct_ip").val("0.0.0.0");
			}else{
				$("#acct_ip").val(acct_ip24[index]);
			}
			if(acct_port24[index] == ""){
				$("#acct_port").val("1813");
			}else{
				$("#acct_port").val(acct_port24[index]);
			}
			if(acct_retry_use24[index] == "1"){
				$("#acct_retry_use").prop("checked",true);
			}else{
				$("#acct_retry_use").prop("checked",false);
			}
			if(acct_delay_time24[index] == ""){
				$("#acct_delay_time").val("60");
			}else{
				$("#acct_delay_time").val(acct_delay_time24[index]);
			}
			change_wep_radius();
		}else if(auth == "none"){
			if(radius_ip24[index] == ""){
				$("#radius_ip").val("0.0.0.0");
			}else{
				$("#radius_ip").val(radius_ip24[index]);
			}
			if(radius_port24[index] == ""){
				$("#radius_port").val("1812");
			}else{
				$("#radius_port").val(radius_port24[index]);
			}
			if(radius_retry24[index] == ""){
				$("#radius_retry").val("3");
			}else{
				$("#radius_retry").val(radius_retry24[index]);
			}
			if(radius_intv24[index] == ""){
				$("#radius_intv").val("5");
			}else{
				$("#radius_intv").val(radius_intv24[index]);
			}
			if(acct_use24[index] == "1"){
				$("#acct_use").prop("checked",true);
			}else{
				$("#acct_use").prop("checked",false);
			}
			if(acct_ip24[index] == ""){
				$("#acct_ip").val("0.0.0.0");
			}else{
				$("#acct_ip").val(acct_ip24[index]);
			}
			if(acct_port24[index] == ""){
				$("#acct_port").val("1813");
			}else{
				$("#acct_port").val(acct_port24[index]);
			}
			if(acct_retry_use24[index] == "1"){
				$("#acct_retry_use").prop("checked",true);
			}else{
				$("#acct_retry_use").prop("checked",false);
			}
			if(acct_delay_time24[index] == ""){
				$("#acct_delay_time").val("60");
			}else{
				$("#acct_delay_time").val(acct_delay_time24[index]);
			}
			if(macauth24[index] == "2"){
				$("#mac_auth").prop("checked",true);
				$(".radius").show();
				change_acct_use();
			}else{
				$("#mac_auth").prop("checked",false);
				$(".radius").hide();
			}
			if(wep_macaddr24[index] == "1"){
				$("#mac_auth").prop("checked",true);
				$(".radius").show();
				change_acct_use();
			}
		}else{
			switch(auth_type){
				case "psk":
					if(keytype24[index] == ""){
						$("#key_type").val("ascii");
					}else{
						$("#key_type").val(keytype24[index]);
					}
					$("#key").val("********");
					break;
				case "wpa":
					if(radius_ip24[index] == ""){
						$("#radius_ip").val("0.0.0.0");
					}else{
						$("#radius_ip").val(radius_ip24[index]);
					}
					if(radius_port24[index] == ""){
						$("#radius_port").val("1812");
					}else{
						$("#radius_port").val(radius_port24[index]);
					}
					if(radius_retry24[index] == ""){
						$("#radius_retry").val("3");
					}else{
						$("#radius_retry").val(radius_retry24[index]);
					}
					if(radius_intv24[index] == ""){
						$("#radius_intv").val("5");
					}else{
						$("#radius_intv").val(radius_intv24[index]);
					}
					if(acct_use24[index] == "1"){
						$("#acct_use").prop("checked",true);
					}else{
						$("#acct_use").prop("checked",false);
					}
					if(acct_ip24[index] == ""){
						$("#acct_ip").val("0.0.0.0");
					}else{
						$("#acct_ip").val(acct_ip24[index]);
					}
					if(acct_port24[index] == ""){
						$("#acct_port").val("1813");
					}else{
						$("#acct_port").val(acct_port24[index]);
					}
					if(acct_retry_use24[index] == "1"){
						$("#acct_retry_use").prop("checked",true);
					}else{
						$("#acct_retry_use").prop("checked",false);
					}
					if(acct_delay_time24[index] == ""){
						$("#acct_delay_time").val("60");
					}else{
						$("#acct_delay_time").val(acct_delay_time24[index]);
					}
					break;
			}
		}
	}else{
		if(auth == "wep"){
			if($("[name='auth_type1']:checked").val() == undefined ) {
				$("#auth_type10").prop("checked",true);
			}
			if(wep_len5[index] == ""){
				$("#wep_len").val("64");
			}else{
				$("#wep_len").val(wep_len5[index]);
			}
			if(wep_type5[index] == ""){
				$("#wep_type").val("ascii");
			}else{
				$("#wep_type").val(wep_type5[index]);
			}
			change_wep_len();
			if(wep_key5[index] == ""){
				$("#wep_key1").prop("checked",true);
			}else{
				$("#wep_key"+wep_key5[index]).prop("checked",true);
			}
			if(key15[index] == "1"){
				$("#key1").attr("flag",1);
			}
			if(key25[index] == "1"){
				$("#key2").attr("flag",1);
			}
			if(key35[index] == "1"){
				$("#key3").attr("flag",1);
			}
			if(key45[index] == "1"){
				$("#key4").attr("flag",1);
			}
			if(wep_radius5[index] == "1"){
				$("#wep_radius").prop("checked",true);
			}else{
				$("#wep_radius").prop("checked",false);
			}
			if(radius_ip5[index] == ""){
				$("#radius_ip").val("0.0.0.0");
			}else{
				$("#radius_ip").val(radius_ip5[index]);
			}
			if(radius_port5[index] == ""){
				$("#radius_port").val("1812");
			}else{
				$("#radius_port").val(radius_port5[index]);
			}
			if(radius_retry5[index] == ""){
				$("#radius_retry").val("3");
			}else{
				$("#radius_retry").val(radius_retry5[index]);
			}
			if(radius_intv5[index] == ""){
				$("#radius_intv").val("5");
			}else{
				$("#radius_intv").val(radius_intv5[index]);
			}
			if(acct_use5[index] == "1"){
				$("#acct_use").prop("checked",true);
			}else{
				$("#acct_use").prop("checked",false);
			}
			if(acct_ip5[index] == ""){
				$("#acct_ip").val("0.0.0.0");
			}else{
				$("#acct_ip").val(acct_ip5[index]);
			}
			if(acct_port5[index] == ""){
				$("#acct_port").val("1813");
			}else{
				$("#acct_port").val(acct_port5[index]);
			}
			if(acct_retry_use5[index] == "1"){
				$("#acct_retry_use").prop("checked",true);
			}else{
				$("#acct_retry_use").prop("checked",false);
			}
			if(acct_delay_time5[index] == ""){
				$("#acct_delay_time").val("60");
			}else{
				$("#acct_delay_time").val(acct_delay_time5[index]);
			}
			change_wep_radius();
		}else if(auth == "none"){
			if(radius_ip5[index] == ""){
				$("#radius_ip").val("0.0.0.0");
			}else{
				$("#radius_ip").val(radius_ip5[index]);
			}
			if(radius_port5[index] == ""){
				$("#radius_port").val("1812");
			}else{
				$("#radius_port").val(radius_port5[index]);
			}
			if(radius_retry5[index] == ""){
				$("#radius_retry").val("3");
			}else{
				$("#radius_retry").val(radius_retry5[index]);
			}
			if(radius_intv5[index] == ""){
				$("#radius_intv").val("5");
			}else{
				$("#radius_intv").val(radius_intv5[index]);
			}
			if(acct_use5[index] == "1"){
				$("#acct_use").prop("checked",true);
			}else{
				$("#acct_use").prop("checked",false);
			}
			if(acct_ip5[index] == ""){
				$("#acct_ip").val("0.0.0.0");
			}else{
				$("#acct_ip").val(acct_ip5[index]);
			}
			if(acct_port5[index] == ""){
				$("#acct_port").val("1813");
			}else{
				$("#acct_port").val(acct_port5[index]);
			}
			if(acct_retry_use5[index] == "1"){
				$("#acct_retry_use").prop("checked",true);
			}else{
				$("#acct_retry_use").prop("checked",false);
			}
			if(acct_delay_time5[index] == ""){
				$("#acct_delay_time").val("60");
			}else{
				$("#acct_delay_time").val(acct_delay_time5[index]);
			}
			if(macauth5[index] == "2"){
				$("#mac_auth").prop("checked",true);
				$(".radius").show();
				change_acct_use();
			}else{
				$("#mac_auth").prop("checked",false);
				$(".radius").hide();
			}
			if(wep_macaddr5[index] == "1"){
				$("#mac_auth").prop("checked",true);
				$(".radius").show();
				change_acct_use();
			}
		}else{
			switch(auth_type){
				case "psk":
					if(keytype5[index] == ""){
						$("#key_type").val("ascii");
					}else{
						$("#key_type").val(keytype5[index]);
					}
					$("#key").val("********");
					break;
				case "wpa":
					if(radius_ip5[index] == ""){
						$("#radius_ip").val("0.0.0.0");
					}else{
						$("#radius_ip").val(radius_ip5[index]);
					}
					if(radius_port5[index] == ""){
						$("#radius_port").val("1812");
					}else{
						$("#radius_port").val(radius_port5[index]);
					}
					if(radius_retry5[index] == ""){
						$("#radius_retry").val("3");
					}else{
						$("#radius_retry").val(radius_retry5[index]);
					}
					if(radius_intv5[index] == ""){
						$("#radius_intv").val("5");
					}else{
						$("#radius_intv").val(radius_intv5[index]);
					}
					if(acct_use5[index] == "1"){
						$("#acct_use").prop("checked",true);
					}else{
						$("#acct_use").prop("checked",false);
					}
					if(acct_ip5[index] == ""){
						$("#acct_ip").val("0.0.0.0");
					}else{
						$("#acct_ip").val(acct_ip5[index]);
					}
					if(acct_port5[index] == ""){
						$("#acct_port").val("1813");
					}else{
						$("#acct_port").val(acct_port5[index]);
					}
					if(acct_retry_use5[index] == "1"){
						$("#acct_retry_use").prop("checked",true);
					}else{
						$("#acct_retry_use").prop("checked",false);
					}
					if(acct_delay_time5[index] == ""){
						$("#acct_delay_time").val("60");
					}else{
						$("#acct_delay_time").val(acct_delay_time5[index]);
					}
					break;
			}
		}
	}
	$("#radius_passwd").val("********");
	$("#acct_passwd").val("********");
	if(auth != "wep" && auth != "none"){
		if(auth_type == "psk"){
			$(".psk").show();
			$(".radius").hide();
		}else{
			$(".psk").hide();
			$(".radius").show();
			change_acct_use();
		}
	}
}
var change_mac_auth = function(){
	if($("#mac_auth").prop("checked") == true){
		$(".radius").show();
		change_acct_use();
	}else{
		$(".radius").hide();
	}
}
var change_wep_len = function(){
	var wep_len = $("#wep_len").children(":selected").val();
	if(wep_len == "64"){
		$("#wep_type").children().eq(0).text("ASCII (5 characters)");
		$("#wep_type").children().eq(1).text("HEX (10 characters)");
	}else{
		$("#wep_type").children().eq(0).text("ASCII (13 characters)");
		$("#wep_type").children().eq(1).text("HEX (26 characters)");
	}
	$("#key1").val(create_mask($("#wep_len").children(":selected").val(),$("#wep_type").children(":selected").val()));
	$("#key2").val(create_mask($("#wep_len").children(":selected").val(),$("#wep_type").children(":selected").val()));
	$("#key3").val(create_mask($("#wep_len").children(":selected").val(),$("#wep_type").children(":selected").val()));
	$("#key4").val(create_mask($("#wep_len").children(":selected").val(),$("#wep_type").children(":selected").val()))
}
var change_acct_use = function(){
	if($("#acct_use:checked").val() == undefined){
		$("#acct_ip").prop("disabled",true);
		$("#acct_port").prop("disabled",true);
		$("#acct_passwd").prop("disabled",true);
		$("#acct_retry").prop("disabled",true);
		$("#acct_intv").prop("disabled",true);
		$("#acct_retry_use").prop("disabled",true);
		$("#acct_delay_time").prop("disabled",true);
	}else{
		$("#acct_ip").prop("disabled",false);
		$("#acct_port").prop("disabled",false);
		$("#acct_passwd").prop("disabled",false);
		$("#acct_retry").prop("disabled",false);
		$("#acct_intv").prop("disabled",false);
		$("#acct_retry_use").prop("disabled",false);
		$("#acct_delay_time").prop("disabled",false);
	}
}
var click_password_field = function(){
	$("#key").val("");
}
var click_clear = function(obj_){
	$(obj_).attr("flag",1);
	$(obj_).val("");
}
var change_wep_radius = function(){
	if($("#wep_radius").prop("checked") == true){
		//WEP Radius
		$(".wep").hide();
		$(".wep_radius").show();
		$(".radius").show();
		$(".radius").find(".wpa").show();
		$("[name='auth_type1']").prop("disabled",true);
		$("[name='auth_type1']").eq(2).prop("checked",true);
	}else{
		//WEP
		$(".wep_radius").hide();
		$(".wep").show();
		$(".radius").hide();
		$(".radius").find(".wpa").hide();
		$("[name='auth_type1']").prop("disabled",false);
	}
}
var form_save = function(){
	var regPwd = /^.*(?=.*\d)(?=.*[a-zA-Z])(?=.*[^a-zA-Z0-9]).*$/;
	var reg = /[^0-9a-fA-F]{1,}/;
	var radio = $("#radio").children(":selected").val();
	var auth = $("#auth").children(":selected").val();
	var auth_type = $("[name='auth_type']:checked").val();
	var ssid = $("#ssid").children(":selected").val();
//	var ssid_idx = $("#ssid").children(":selected");
	var ssid_idx = $("#ssid").children("option").index($("#ssid").children(":selected"));
	var index = $("#ssid").children("option").eq(ssid_idx).attr("seq");
	var cipher0 = $("#cipher0:checked").val();
	var cipher1 = $("#cipher1:checked").val();
	var cipher20 = $("#cipher20:checked").val();
	var cipher21 = $("#cipher21:checked").val();
	var key_type = $("#key_type").children(":selected").val();
	var key = $("#key").val();

	$("#frm_auth_type").val("");
	$("#frm_auth").val("");
	$("#frm_rsn_pairwise").val("");
	$("#frm_radio").val("");
	$("#frm_seq").val("");
	$("#frm_key_type").val("");
	$("#frm_key").val("");

	$("#frm_radius_ip").val("");
	$("#frm_radius_port").val("");
	$("#frm_radius_passwd").val("");
	$("#frm_radius_port").val("");
	$("#frm_radius_retry").val("");
	$("#frm_radius_intv").val("");

	$("#frm_acct_use").val("");
	$("#frm_acct_ip").val("");
	$("#frm_acct_port").val("");
	$("#frm_acct_passwd").val("");
	$("#frm_acct_retry").val("");
	$("#frm_acct_intv").val("");
	$("#frm_acct_retry_use").val("");
	$("#frm_acct_delay_time").val("");
	$("#frm_wep_radius").val("");

	$("#frm_auth_type1").val("");

	if(radio == "0"){
		$("#frm_radio").val("1");
	}else{
		$("#frm_radio").val("0");
	}
	$("#frm_seq").val(index);
	switch(auth){
		case "wpa-mixed":
		case "wpa2":
		case "wpa":
			var auth_ = "";
			var auth2_ = "";
			var auth_ck = false;
			if(auth_type == "psk"){
				auth_ = auth.replace("wpa","psk");
				$("#frm_auth_type").val(auth_type);
				auth_ck = true;
			}else{
				auth_ = auth;
				$("#frm_auth_type").val("wpa");
				auth_ck = true;
			}
			if(auth_ck == false){
				alert("Cipher Suite를 선택해주세요.");
				return;
			}
			var cipher_ck = false;
			if(cipher0 != undefined){
				auth_ += "+" + cipher0;
				cipher_ck = true;
			}
			if(cipher1 != undefined){
				auth_ += "+" + cipher1;
				cipher_ck = true;
			}
			if(cipher_ck == false){
				alert("WPA Cipher Suite를 선택해주세요.");
				$("#cipher0").focus();
				return;
			}
			if(auth == "wpa-mixed"){
				var cipher_ck2 = false;
				if(cipher20 != undefined){
					auth2_ += "+" + cipher20;
					cipher_ck2 = true;
				}
				if(cipher21 != undefined){
					auth2_ += "+" + cipher21;
					cipher_ck2 = true;
				}
				if(cipher_ck2 == false){
					alert("WPA Cipher Suite 2를 선택해주세요.");
					$("#cipher20").focus();
					return;
				}
				auth2_ = auth2_.substring(1,auth2_.length);
				$("#frm_rsn_pairwise").val(auth2_);
			}
			$("#frm_auth").val(auth_);
			$("#frm_key_type").val(key_type);
			$("#frm_key").val(key);
			var psk_key_check = true;
			if(key == "********"){
				if(radio == "0"){
					if(key24[index] != "" && keytype24[index] == key_type){
						psk_key_check = false;
					}
				}else{
					if(key5[index] != "" && keytype5[index] == key_type){
						psk_key_check = false;
					}
				}
			}
			if(auth_type == "psk"){
				//PSK인증
				if (psk_key_check == true){
					if(key_type == "ascii"){
						if(key.length < 8 || key.length > 63){
							alert("Pre-Shared Key가 8자 미만이거나 63자를 초과했습니다.");
							$("#key").focus();
							return;
						}
						
						if(!regPwd.test(key)) {
							alert('Pre-Shared Key는 영문, 숫자, 특수문자가 조합 되어야 합니다.\n특수문자는 `,~,!,@,#,$,%,^,&,*,(,),-,_,+,=,공백만 사용 가능합니다.');
							$("#key").focus();
							return;
						}
						if(!check_xss(key)){
							alert(xss_err_msg);
							$("#key").focus();
							return;
						}
					}else{
						if(key.replace(reg,'').length < key.length){
							alert("0~9 또는 a~f를 입력해 주시기바랍니다.");
							$("#key").focus();
							return;
						}
						if(key.length != 64){
							alert("Pre-Shared Key를 64자 입력해주세요.");
							$("#key").focus();
							return;
						}
						if(!check_xss(key)){
							alert(xss_err_msg);
							$("#key").focus();
							return;
						}
					}
				}
			}else{
				//Radius인증
				if(ipCheck($("#radius_ip").val()) == false) {
					alert("인증서버 IP가 잘못 되었습니다.");
					$("#radius_ip").focus();
					return;
				}
				if(check_tcp_port($("#radius_port").val()) == false){
					alert("인증 서버의 포트 번호가 올바르지 않습니다! 1에서 65535 사이의 값을 정수를 입력해야 합니다.");
					$("#radius_port").focus();
					return;
				}
				if($("#radius_passwd").val() == ""){
					alert("인증 서버의 비밀번호를 입력해주세요.");
					$("#radius_passwd").focus();
					return;
				}
				if(!check_xss($("#radius_passwd").val())){
					alert(xss_err_msg);
					$("#radius_passwd").focus();
					return;
				}
				if(check_min_max($("#radius_retry").val(),0,10) == false){
					alert("인증 서버 재시도 횟수는 최대 10입니다.");
					$("#radius_retry").focus();
					return;
				}
				if(check_min_max($("#radius_intv").val(),0,120) == false){
					alert("인증 서버 재시도 간격는 최대 120입니다.");
					$("#radius_retry").focus();
					return;
				}
				$("#frm_radius_ip").val($("#radius_ip").val());
				$("#frm_radius_port").val($("#radius_port").val());
				$("#frm_radius_passwd").val($("#radius_passwd").val());
				$("#frm_radius_retry").val($("#radius_retry").val());
				$("#frm_radius_intv").val($("#radius_intv").val());
				if($("#acct_use:checked").val() != undefined){
					$("#frm_acct_use").val("1");
					$("#frm_acct_ip").val($("#acct_ip").val());
					$("#frm_acct_port").val($("#acct_port").val());
					$("#frm_acct_passwd").val($("#acct_passwd").val());
					if($("#acct_retry_use:checked").val() != undefined){
						$("#frm_acct_retry_use").val("1");
						$("#frm_acct_delay_time").val($("#acct_delay_time").val());
					}
				}
			}
			break;
		case "wep":
			var auth_type1_ = $("[name=auth_type1]:checked").val();
			var wep_len = $("#wep_len").children(":selected").val();
			var wep_type = $("#wep_type").children(":selected").val();
			var wep_key = $("[name=wep_key]:checked").val();
			var wep_radius = $("#wep_radius").prop("checked") == true ? "1" : "0";
			var key1 = $("#key1").val();
			var key2 = $("#key2").val();
			var key3 = $("#key3").val();
			var key4 = $("#key4").val();
			$("#frm_auth_type").val("wep");
			$("#frm_auth_type1").val(auth+"+"+auth_type1_);
			$("#frm_wep_len").val(wep_len);
			if(wep_radius == "0"){
				if($("#key"+wep_key).attr("flag") == undefined){
					alert("Key "+wep_key+" 의 값이 비어있습니다.");
					$("#key"+wep_key).val("");
					$("#key"+wep_key).attr("flag",1);
					$("#key"+wep_key).focus();
					return;
				}
				if($("#key"+wep_key).val() == ""){
					alert("Key "+wep_key+" 의 값이 비어있습니다.");
					$("#key"+wep_key).focus();
					return;
				}
				if(!check_xss($("#key"+wep_key).val())){
					alert(xss_err_msg);
					$("#key"+wep_key).focus();
					return;
				}
	//			alert('Key ' + idx + ' 의 길이가 올바르지 않습니다. ' + len + '자 로 입력해 주세요.');
	//			alert('WEP Key 의 길이가 올바르지 않습니다. ' + len + '자로 입력해 주세요.');
				
				$("#frm_wep_type").val(wep_type);
				$("#frm_wep_key").val(wep_key);
				var ck_len = 5;
				if(wep_type == "ascii" && wep_len == "64"){
					ck_len = 5;
				}else if(wep_type == "hex" && wep_len == "64"){
					ck_len = 10;
				}else if(wep_type == "ascii" && wep_len == "128"){
					ck_len = 13;
				}else if(wep_type == "hex" && wep_len == "128"){
					ck_len = 26;
				}
				var mask_val = "";
				for (var i=0; i < ck_len ; i++ )
				{
					mask_val += "*";
				}
				var wep_key_ck = true;
				var wep_key_val = "";
				if(radio == "0"){
					if($("#key"+wep_key).val().replace(mask_val,"") == ""){
						switch(wep_key){
							case "1":
								if(key124[index] == ""){
									wep_key_ck = false;
								}
								break;
							case "2":
								if(key224[index] == ""){
									wep_key_ck = false;
								}
								break;
							case "3":
								if(key324[index] == ""){
									wep_key_ck = false;
								}
								break;
							case "4":
								if(key424[index] == ""){
									wep_key_ck = false;
								}
								break;
						}
						if(wep_key_ck == false){
							alert("Key1의 값이 비어있습니다.");
							$("#key"+wep_key).val("");
							$("#key"+wep_key).attr("flag",1);
							$("#key"+wep_key).focus();
							return;
						}else{
							wep_key_val = $("#key"+wep_key).val();
						}
						
					}else{
						wep_key_val = $("#key"+wep_key).val();
					}
					if(key124[index] == ""){
						key1 = wep_key_val;
					}
					if(key224[index] == ""){
						key2 = wep_key_val;
					}
					if(key324[index] == ""){
						key3 = wep_key_val;
					}
					if(key424[index] == ""){
						key4 = wep_key_val;
					}
				}else{
					if($("#key"+wep_key).val().replace(mask_val,"") == ""){
						switch(wep_key){
							case "1":
								if(key15[index] == ""){
									wep_key_ck = false;
								}
								break;
							case "2":
								if(key25[index] == ""){
									wep_key_ck = false;
								}
								break;
							case "3":
								if(key35[index] == ""){
									wep_key_ck = false;
								}
								break;
							case "4":
								if(key45[index] == ""){
									wep_key_ck = false;
								}
								break;
						}
						if(wep_key_ck == false){
							alert("Key1의 값이 비어있습니다.");
							$("#key"+wep_key).val("");
							$("#key"+wep_key).attr("flag",1);
							$("#key"+wep_key).focus();
							return;
						}else{
							wep_key_val = $("#key"+wep_key).val();
						}
						
					}else{
						wep_key_val = $("#key"+wep_key).val();
					}
					if(key15[index] == ""){
						key1 = wep_key_val;
					}
					if(key25[index] == ""){
						key2 = wep_key_val;
					}
					if(key35[index] == ""){
						key3 = wep_key_val;
					}
					if(key45[index] == ""){
						key4 = wep_key_val;
					}
//					console.log(key1,key2,key3,key4);
				}
				if(key1.length != ck_len && $("#key1").attr("flag") != undefined){
					alert("Key1의 값이 " + ck_len + "자를 입력해주세요.");
					$("#key1").focus();
					return;
				}
				if(key2.length != ck_len && $("#key2").attr("flag") != undefined){
					alert("Key2의 값이 " + ck_len + "자를 입력해주세요.");
					$("#key2").focus();
					return;
				}
				if(key3.length != ck_len && $("#key3").attr("flag") != undefined){
					alert("Key3의 값이 " + ck_len + "자를 입력해주세요.");
					$("#key3").focus();
					return;
				}
				if(key4.length != ck_len && $("#key4").attr("flag") != undefined){
					alert("Key4의 값이 " + ck_len + "자를 입력해주세요.");
					$("#key4").focus();
					return;
				}
				if(wep_type == "ascii"){
					if(check_to_passwd(key1) == 0 && $("#key1").attr("flag") != undefined){
						alert('암호화 KEY는 영문, 숫자, 특수문자가 조합 되어야 합니다.\n특수문자는 `,~,!,@,#,$,%,^,&,*,(,),-,_,+,=,공백만 사용 가능합니다.');
						$("#key1").focus();
						return;
					}
					if(check_to_passwd(key2) == 0 && $("#key2").attr("flag") != undefined){
						alert('암호화 KEY는 영문, 숫자, 특수문자가 조합 되어야 합니다.\n특수문자는 `,~,!,@,#,$,%,^,&,*,(,),-,_,+,=,공백만 사용 가능합니다.');
						$("#key2").focus();
						return;
					}
					if(check_to_passwd(key3) == 0 && $("#key3").attr("flag") != undefined){
						alert('암호화 KEY는 영문, 숫자, 특수문자가 조합 되어야 합니다.\n특수문자는 `,~,!,@,#,$,%,^,&,*,(,),-,_,+,=,공백만 사용 가능합니다.');
						$("#key3").focus();
						return;
					}
					if(check_to_passwd(key4) == 0 && $("#key4").attr("flag") != undefined){
						alert('암호화 KEY는 영문, 숫자, 특수문자가 조합 되어야 합니다.\n특수문자는 `,~,!,@,#,$,%,^,&,*,(,),-,_,+,=,공백만 사용 가능합니다.');
						$("#key4").focus();
						return;
					}
				}else{
					if(key1.replace(reg,'').length < key1.length && $("#key1").attr("flag") != undefined && mask_val != key1){
						alert('암호화 KEY는 0~9 또는 a~f를 입력해 주시기바랍니다.');
						$("#key1").focus();
						return;
					}
					if(key2.replace(reg,'').length < key2.length && $("#key2").attr("flag") != undefined && mask_val != key2){
						alert('암호화 KEY는 0~9 또는 a~f를 입력해 주시기바랍니다.');
						$("#key2").focus();
						return;
					}
					if(key3.replace(reg,'').length < key3.length && $("#key3").attr("flag") != undefined && mask_val != key3){
						alert('암호화 KEY는 0~9 또는 a~f를 입력해 주시기바랍니다.');
						$("#key3").focus();
						return;
					}
					if(key4.replace(reg,'').length < key4.length && $("#key4").attr("flag") != undefined && mask_val != key4){
						alert('암호화 KEY는 0~9 또는 a~f를 입력해 주시기바랍니다.');
						$("#key4").focus();
						return;
					}
				}
				
				$("#frm_key1").val(key1);
				$("#frm_key2").val(key2);
				$("#frm_key3").val(key3);
				$("#frm_key4").val(key4);
			}else{
				//WEP Radius
				$("#frm_wep_radius").val(wep_radius);
				if(ipCheck($("#radius_ip").val()) == false) {
					alert("인증서버 IP가 잘못 되었습니다.");
					$("#radius_ip").focus();
					return;
				}
				if(check_tcp_port($("#radius_port").val()) == false){
					alert("인증 서버의 포트 번호가 올바르지 않습니다! 1에서 65535 사이의 값을 정수를 입력해야 합니다.");
					$("#radius_port").focus();
					return;
				}
				if($("#radius_passwd").val() == ""){
					alert("인증 서버의 비밀번호를 입력해주세요.");
					$("#radius_passwd").focus();
					return;
				}
				if(check_min_max($("#radius_retry").val(),0,10) == false){
					alert("인증 서버 재시도 횟수는 최대 10입니다.");
					$("#radius_retry").focus();
					return;
				}
				if(check_min_max($("#radius_intv").val(),0,120) == false){
					alert("인증 서버 재시도 간격는 최대 120입니다.");
					$("#radius_retry").focus();
					return;
				}
				$("#frm_radius_ip").val($("#radius_ip").val());
				$("#frm_radius_port").val($("#radius_port").val());
//				console.log($("#radius_passwd").val());
				$("#frm_radius_passwd").val($("#radius_passwd").val());
				$("#frm_radius_retry").val($("#radius_retry").val());
				$("#frm_radius_intv").val($("#radius_intv").val());
				if($("#acct_use:checked").val() != undefined){
					$("#frm_acct_use").val("1");
					$("#frm_acct_ip").val($("#acct_ip").val());
					$("#frm_acct_port").val($("#acct_port").val());
					$("#frm_acct_passwd").val($("#acct_passwd").val());
					if($("#acct_retry_use:checked").val() != undefined){
						$("#frm_acct_retry_use").val("1");
						$("#frm_acct_delay_time").val($("#acct_delay_time").val());
					}
				}
			}
			break;
		case "none":
			$("#frm_auth_type").val("none");
			if($("#mac_auth").prop("checked") == true){
				$("#frm_mac_auth").val("2");
				if(ipCheck($("#radius_ip").val()) == false) {
					alert("인증서버 IP가 잘못 되었습니다.");
					$("#radius_ip").focus();
					return;
				}
				if(check_tcp_port($("#radius_port").val()) == false){
					alert("인증 서버의 포트 번호가 올바르지 않습니다! 1에서 65535 사이의 값을 정수를 입력해야 합니다.");
					$("#radius_port").focus();
					return;
				}
				if($("#radius_passwd").val() == ""){
					alert("인증 서버의 비밀번호를 입력해주세요.");
					$("#radius_passwd").focus();
					return;
				}
				if(check_min_max($("#radius_retry").val(),0,10) == false){
					alert("인증 서버 재시도 횟수는 최대 10입니다.");
					$("#radius_retry").focus();
					return;
				}
				if(check_min_max($("#radius_intv").val(),0,120) == false){
					alert("인증 서버 재시도 간격는 최대 120입니다.");
					$("#radius_retry").focus();
					return;
				}
				$("#frm_radius_ip").val($("#radius_ip").val());
				$("#frm_radius_port").val($("#radius_port").val());
				console.log($("#radius_passwd").val());
				$("#frm_radius_passwd").val($("#radius_passwd").val());
				$("#frm_radius_retry").val($("#radius_retry").val());
				$("#frm_radius_intv").val($("#radius_intv").val());
				if($("#acct_use:checked").val() != undefined){
					$("#frm_acct_use").val("1");
					$("#frm_acct_ip").val($("#acct_ip").val());
					$("#frm_acct_port").val($("#acct_port").val());
					$("#frm_acct_passwd").val($("#acct_passwd").val());
					if($("#acct_retry_use:checked").val() != undefined){
						$("#frm_acct_retry_use").val("1");
						$("#frm_acct_delay_time").val($("#acct_delay_time").val());
					}
				}
			}
			break;
	}
	$("[value='']").prop("disabled",true);
	document.saveform.submit();
	return;
}
$(document).ready(function(){
	$("#radio").val("<?=$wlan_id?>");
	create_ssid();
	change_ssid();
//	SSIDSelected();
});
</script>

</head>

<body>
<blockquote>
<h2>
<?php
	if(dv_session("wlan_id") == "1"){
		echo("무선 기본 설정 5G");
	}elseif(dv_session("wlan_id") == "0"){
		echo("무선 기본 설정 2.4G");
	}
?>
</h2>
<form action="proc/skb_wlsecurity_proc.php" method="POST" name="saveform">
<input type="hidden" value="/skb_wlsecurity.php" name="submit-url">

<input type="hidden" name="frm_radio" id="frm_radio" value="">
<input type="hidden" name="frm_seq" id="frm_seq" value="">
<input type="hidden" name="frm_auth" id="frm_auth" value="">
<input type="hidden" name="frm_auth_type" id="frm_auth_type" value="">
<!--#PSK//-->
<input type="hidden" name="frm_rsn_pairwise" id="frm_rsn_pairwise" value="">
<input type="hidden" name="frm_key_type" id="frm_key_type" value="">
<input type="hidden" name="frm_key" id="frm_key" value="">

<!--#WPA//-->
<input type="hidden" name="frm_radius_ip" id="frm_radius_ip" value="">
<input type="hidden" name="frm_radius_passwd" id="frm_radius_passwd" value="">
<input type="hidden" name="frm_radius_port" id="frm_radius_port" value="">
<input type="hidden" name="frm_radius_retry" id="frm_radius_retry" value="">
<input type="hidden" name="frm_radius_intv" id="frm_radius_intv" value="">

<input type="hidden" name="frm_acct_use" id="frm_acct_use" value="">
<input type="hidden" name="frm_acct_ip" id="frm_acct_ip" value="">
<input type="hidden" name="frm_acct_port" id="frm_acct_port" value="">
<input type="hidden" name="frm_acct_passwd" id="frm_acct_passwd" value="">
<input type="hidden" name="frm_acct_retry" id="frm_acct_retry" value="">
<input type="hidden" name="frm_acct_intv" id="frm_acct_intv" value="">
<input type="hidden" name="frm_acct_retry_use" id="frm_acct_retry_use" value="">
<input type="hidden" name="frm_acct_delay_time" id="frm_acct_delay_time" value="">

<!--#WEP//-->
<input type="hidden" name="frm_auth_type1" id="frm_auth_type1" value="">
<input type="hidden" name="frm_wep_radius" id="frm_wep_radius" value="">
<input type="hidden" name="frm_wep_len" id="frm_wep_len" value="">
<input type="hidden" name="frm_wep_type" id="frm_wep_type" value="">
<input type="hidden" name="frm_wep_key" id="frm_wep_key" value="">
<input type="hidden" name="frm_key1" id="frm_key1" value="">
<input type="hidden" name="frm_key2" id="frm_key2" value="">
<input type="hidden" name="frm_key3" id="frm_key3" value="">
<input type="hidden" name="frm_key4" id="frm_key4" value="">

<!--#MAC//-->
<input type="hidden" name="frm_mac_auth" id="frm_mac_auth" value="">
</form>
<form action="" method="POST" name="formEncrypt">
<table border=0 width="580" cellspacing="4" cellpadding="0">
    <tr>
		<td width="100%"><font size="2">
		무선 인터넷의 보안을 설정하는 페이지입니다.<br>
		WEP 또는 WPA 암호키를 사용하여 권한없이
		무선 인터넷에 접근하는 것을 예방할 수 있습니다.</font></td>
    </tr>
     <tr>
		<td width="100%"><hr size="1" noshade align="top"></td>
	</tr>
</table>
<table width="580" height="25" border="0" cellpadding="0" cellspacing="0">
<tr>
	<font size="2" height="20" >무선 비밀 번호 설정 시 <b><font color="red">영문·숫자·특수문자를  포함하여</font></b> 설정 바랍니다.<br></font>
</tr>
<tr>
<tr>
	<td width="25%"><font size="2"><b>무선:</b></font></td>
	<td width="75%">
		<select name="radio" id="radio" onchange="page_change(this)">
			<option value="0">2.4 GHz</option>
			<option value="1">5 GHz</option>
		</select>
	</td>
</tr>
<td  height="20" class="MainTD" width="25%"><font size="2"><b>SSID 선택:&nbsp;&nbsp;</b></td>
<td width="75%"><select name="ssid" id="ssid" onchange="change_ssid();"></select>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="button" value=" 적용 " name="save" onclick="form_save();">&nbsp;&nbsp;
<input type="button" value=" 취소 " name="reset1" onclick="ValidateForm(document.formEncrypt, 1);">
</td>
</tr>
</table>
<table width="580" height="25" border="0" cellpadding="0" cellspacing="0">
	<tr>
		<td  colspan="2" height="20"><hr color="#B5B5E6" size="1"></td>
	</tr>
</table>
<table width="580" border="0" cellpadding="0" cellspacing="0">
	<tr>
		<td>&nbsp;</td>
		<td width="540"><table width="100%" border="0" cellpadding="0" cellspacing="4">
			<tr>
				<td width="30%"><font size="2"><b>암호화:</b></font></td>
				<td width="70%"><font size="2"><select name="auth" id="auth" onchange="change_auth();">
					<option value="wpa-mixed"> WPA-Mixed </option>
					<option value="wpa2"> WPA2 </option>
					<option value="wpa"> WPA </option>
					<option value="wep"> WEP </option>
					<option value="none"> Disable </option>
				</select></font></td> 
			</tr>
		</table></td>
	</tr>
	<tr>
		<td>&nbsp;</td>
		<td><table width="100%" border="0" cellpadding="0" cellspacing="4">
			<tr class="wpa">
				<td width="30%"><font size="2"><b>인증 모드:</b></font></td>
				<td width="70%"><font size="2"><input name="auth_type" id="auth_type0" type="radio" value="wpa" onchange="change_auth_type(0);">Enterprise (RADIUS)
				<input name="auth_type" id="auth_type1" type="radio" value="psk" onchange="change_auth_type(1);">Personal (Pre-Shared Key)</font></td>
			</tr>
			<tr class="no">
				<td width="30%"><font size="2"><b>Mac 인증:</b></font></td>
				<td width="70%"><font size="2"><input name="mac_auth" id="mac_auth" type="checkbox" value="2" onchange="change_mac_auth();"></font></td>
			</tr>
			<tr class="wpa">
				<td><font size="2"><b>WPA Cipher Suite:</b></font></td>
				<td><font size="2"><input type="checkbox" name="cipher" id="cipher0" value="tkip" onclick="">TKIP&nbsp;
				<input type="checkbox" name="cipher" id="cipher1" value="aes">AES</font></td>
			</tr>
			<tr class="wpa2">
				<td><font size="2"><b>WPA Cipher Suite 2:</b></font></td>
				<td><font size="2"><input type="checkbox" name="cipher2" id="cipher20" value="tkip" onclick="">TKIP&nbsp;
				<input type="checkbox" name="cipher2" id="cipher21" value="aes">AES</font></td>
			</tr>
			<tr class="psk">
				<td><font size="2"><b>Key 형식:</b></font></td>
				<td><font size="2"><select name="key_type" id="key_type" onchange="">
					<option value="ascii">ASCII (8~63 characters)</option>
					<option value="hex">Hex (64 characters)</option>
				</select></td>
			</tr>
			<tr class="psk">
				<td><font size="2"><b>Pre-Shared&nbsp;Key:</b></font></td>
				<td><input type="password" name="key" id="key" size="32" maxlength="64" value="" onclick="click_password_field(2)" onmousedown="" onkeypress=""></td>
			</tr>
			<tr class="wep wep_radius">
				<td width="30%"><font size="2"><b>802.1x 인증:</b></font></td>
				<td width="70%"><font size="2"><input type="checkbox" name="wep_radius" id="wep_radius" value="1" onchange="change_wep_radius();"></font></td>
			</tr>
			<tr class="wep wep_radius">
				<td width="30%"><font size="2"><b>인증:</b></font></td>
				<td width="70%"><font size="2"><input name="auth_type1" id="auth_type10" type="radio" value="open">Open System
				<input name="auth_type1" id="auth_type11" type="radio" value="shared">Shared Key
				<input name="auth_type1" id="auth_type12" type="radio" value="mixed">Auto</font></td>
			</tr>
			<tr class="wep wep_radius">
				<td><font size="2"><b>Key 길이:</b></font></td>
				<td><font size="2" id="wep_len_ar"><select name="wep_len" id="wep_len" onchange="change_wep_len();">
					 <option value="64"> 64-bit</option>
					 <option value="128">128-bit</option>
				</select></font></td>
			</tr>
			<tr class="wep">
				<td><font size="2"><b>Key 형식:</b></font></td>
				<td><select name="wep_type" id="wep_type" onchange="change_wep_len()">
					<option value="ascii">ASCII</option>
					<option value="hex">Hex</option>
				</select></td>
			</tr>
			<tr class="wep">
				<td><font size="2"><b>암호화 Key 1:</b></font></td>
				<td>
					<input type="radio" name="wep_key" id="wep_key1" value="1">
					<input type="password" name="keys" id="key1" value="" onclick="click_clear(this);" maxlength="26" size="26"></td>
			</tr>
			<tr class="wep">
				<td><font size="2"><b>암호화 Key 2:</b></font></td>
				<td><input type="radio" name="wep_key" id="wep_key2" value="2">
					<input type="password" name="keys" id="key2" value="" onclick="click_clear(this);" maxlength="26" size="26">
			</td></tr>
			<tr class="wep">
				<td><font size="2"><b>암호화 Key 3:</b></font></td>
				<td><input type="radio" name="wep_key" id="wep_key3" value="3">
				<input type="password" name="keys" id="key3" value="" onclick="click_clear(this);" maxlength="26" size="26"></td>
			</tr>
			<tr class="wep">
				<td><font size="2"><b>암호화 Key 4:</b></font></td>
				<td><input type="radio" name="wep_key" id="wep_key4" value="4">
				<input type="password" name="keys" id="key4" value="" onclick="click_clear(this);" maxlength="26" size="26"></td>
			</tr>
		</table>
		<fieldset class="fieldset radius"><legend> 인증서버 </legend>
		<table width="100%" border="0" cellpadding="0" cellspacing="4">
			<tr class="wpa">
				<td width="30%"><font size="2"><b>IP 주소:</b></font></td>
				<td width="70%"><font size="2"><input type="text" name="radius_ip" id="radius_ip" value="0.0.0.0" size="16" maxlength="15"></font></td>
			</tr>
			<tr class="wpa">
				<td><font size="2"><b>포트:</b></font></td>
				<td><font size="2"><input type="text" name="radius_port" id="radius_port" value="1812" size="5" maxlength="5"></font></td>
			</tr>
			<tr class="wpa">
				<td><font size="2"><b>비밀번호:</b></font></td>
				<td><font size="2"><input type="password" name="radius_passwd" id="radius_passwd" value="" size="32" maxlength="64" onclick="click_clear(this);"></font></td>
			</tr>
			<tr class="wpa">
				<td><font size="2"><b>재시도 횟수:</b></font></td>
				<td><font size="2"><input type="text" name="radius_retry" id="radius_retry" value="3" size="1" maxlength="2"></font></td>
			</tr>
			<tr class="wpa">
				<td><font size="2"><b>재시도 간격:</b></font></td>
				<td><font size="2"><input type="text" name="radius_intv" id="radius_intv" value="5" size="2" maxlength="3"></font></td>
			</tr>
		</table></fieldset>
		<fieldset class="fieldset radius"><legend> 계정서버 </legend>
		<table width="100%" border="0" cellpadding="0" cellspacing="4">
			<tr class="wpa">
				<td width="30%"><font size="2"><b>계정 서버 사용:</b></font></td>
				<td width="70%"><font size="2"><input type="checkbox" name="acct_use" id="acct_use" value="1" onchange="change_acct_use();"></font></td>
			</tr>
			<tr class="wpa">
				<td><font size="2"><b>IP 주소:</b></font></td>
				<td><font size="2"><input type="text" name="acct_ip" id="acct_ip" value="0.0.0.0" size="16" maxlength="15"></font></td>
			</tr>
			<tr class="wpa">
				<td><font size="2"><b>포트:</b></font></td>
				<td><font size="2"><input type="text" name="acct_port" id="acct_port" value="1813" size="5" maxlength="5"></font></td>
			</tr>
			<tr class="wpa">
				<td><font size="2"><b>비밀번호:</b></font></td>
				<td><font size="2"><input type="password" name="acct_passwd" id="acct_passwd" value="1813" onclick="click_clear(this);" size="32" maxlength="64"></font></td>
			</tr>
<!-- 			<tr class="wpa"> -->
<!-- 				<td><font size="2"><b>재시도 횟수:</b></font></td> -->
<!-- 				<td><font size="2"><input type="text" name="acct_retry" id="acct_retry" size="1" maxlength="1" value="3"></font></td> -->
<!-- 			</tr> -->
<!-- 			<tr class="wpa"> -->
<!-- 				<td><font size="2"><b>재시도 간격:</b></font></td> -->
<!-- 				<td><font size="2"><input type="text" name="acct_intv" id="acct_intv" size="2" maxlength="2" value="5"></font></td> -->
<!-- 			</tr> -->
			<tr class="wpa">
				<td><font size="2"><b>계정 갱신:</b></font></td>
				<td><font size="2"><input type="checkbox" name="acct_retry_use" id="acct_retry_use" value="1"></font></td>
			</tr>
			<tr class="wpa">
				<td><font size="2"><b>갱신 지연시간:</b></font></td>
				<td><font size="2"><input type="text" name="acct_delay_time" id="acct_delay_time" value="60" size="4" maxlength="4"></font></td>
			</tr>
		</table>
		</fieldset>
		</td>
	</tr>
</table>
</form>
</blockquote>
</body>
</html>
