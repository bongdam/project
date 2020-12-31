<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$uci = new uci();
	
	$radio_ = dv_session("wlan_id");
	$wifi_enable1_ = dv_post("wlan_enable1");
	$wifi_enable2_ = dv_post("wlan_enable2");
	if(DEF_MODEL != "QCA_REF" && DEF_ANT == "4x4"){
		if($radio_ == "0"){
			$radio = "1";
		}else{
			$radio = "0";
		}
	}else{
		exit;
	}

	$wifi = "wifi".$radio;
	$vap1 = "vap".$radio."1";
	$vap2 = "vap".$radio."2";

	$band1_ = dv_post("band1");
	$band2_ = dv_post("band2");
	$ssid1_ = dv_post("ssid1");
	$ssid2_ = dv_post("ssid2");

	$hide_ssid1_ = dv_post("hide_ssid1");
	$hide_ssid2_ = dv_post("hide_ssid2");

	$wlan_max_conn1_ = dv_post("wlan_max_conn1");
	$wlan_max_conn2_ = dv_post("wlan_max_conn2");

	$tx_limit1_ = dv_post("tx_limit1");
	$tx_limit2_ = dv_post("tx_limit2");

	$rx_limit1_ = dv_post("rx_limit1");
	$rx_limit2_ = dv_post("rx_limit2");

	$wmm1_ = dv_post("wmm1");
	$wmm2_ = dv_post("wmm2");

	$rate1_ = dv_post("rate1");
	$rate2_ = dv_post("rate2");

	$uci->mode("set");
	if($wifi_enable1_ == "1"){
		$uci->set("wireless.".$vap1.".disabled","0");
	}else{
		$uci->set("wireless.".$vap1.".disabled","1");
	}
	if($wifi_enable2_ == "1"){
		$uci->set("wireless.".$vap2.".disabled","0");
	}else{
		$uci->set("wireless.".$vap2.".disabled","1");
	}

	if($band1_ != ""){
		$uci->set("wireless.".$wifi.".hwmode",$band1_);
	}
	if($band2_ != ""){
		$uci->set("wireless.".$wifi.".hwmode",$band2_);
	}
	
	if($ssid1_ != ""){
		$uci->set("wireless.".$vap1.".ssid",$ssid1_);
	}
	if($ssid2_ != ""){
		$uci->set("wireless.".$vap2.".ssid",$ssid2_);
	}
	if($hide_ssid1_ != ""){
		$uci->set("wireless.".$vap1.".hidden",$hide_ssid1_);
	}
	if($hide_ssid2_ != ""){
		$uci->set("wireless.".$vap2.".hidden",$hide_ssid2_);
	}
	if($wlan_max_conn1_ != ""){
		$uci->set("wireless.".$vap1.".maxsta",$wlan_max_conn1_);
	}
	if($wlan_max_conn2_ != ""){
		$uci->set("wireless.".$vap2.".maxsta",$wlan_max_conn2_);
	}
	if($tx_limit1_ != ""){
		$uci->set("wireless.".$vap1.".tx_limit",$tx_limit1_);
	}
	if($tx_limit2_ != ""){
		$uci->set("wireless.".$vap2.".tx_limit",$tx_limit2_);
	}
	if($rx_limit1_ != ""){
		$uci->set("wireless.".$vap1.".rx_limit",$rx_limit1_);
	}
	if($rx_limit2_ != ""){
		$uci->set("wireless.".$vap2.".rx_limit",$rx_limit2_);
	}
	if($wmm1_ != ""){
		$uci->set("wireless.".$vap1.".wmm",$wmm1_);
	}else{
		$uci->set("wireless.".$vap1.".wmm","1");
	}
	if($wmm2_ != ""){
		$uci->set("wireless.".$vap2.".wmm",$wmm2_);
	}else{
		$uci->set("wireless.".$vap2.".wmm","1");
	}
	if($rate1_ != ""){
		if($rate1_ != "auto"){
			$uci->mode("del");
			$uci->del("wireless.".$vap1.".setLegacyRates");
			$uci->del("wireless.".$vap1.".set11NRates");
			$uci->del("wireless.".$vap1.".nss");
			$uci->del("wireless.".$vap1.".vhtmcs");
			$uci->run();
			$uci->mode("set");
			if(preg_match("/^NSS(\d+)\-MCS(\d+)/",$rate1_,$d) == true) {
				//AC
				$uci->set("wireless.".$vap1.".nss",$d[1]);
				$uci->set("wireless.".$vap1.".vhtmcs",$d[2]);
			}elseif(preg_match("/^MCS(\d+)/",$rate1_,$d) == true){
				//MSC
				$base = hexdec("80");
				$base = $base + $d[1];
				$rate = (string)dechex($base);
				$rate = "0x".$rate.$rate.$rate.$rate;
				$uci->set("wireless.".$vap1.".set11NRates",$rate);
			}elseif(preg_match("/^([\d+\.]{1,})M/",$rate1_,$d) == true){
				//Legacy
				$uci->set("wireless.".$vap1.".setLegacyRates",$rate1_);
			}
		}else{
			$uci->mode("del");
			$uci->del("wireless.".$vap1.".setLegacyRates");
			$uci->del("wireless.".$vap1.".set11NRates");
			$uci->del("wireless.".$vap1.".nss");
			$uci->del("wireless.".$vap1.".vhtmcs");
			$uci->run();
			$uci->mode("set");
		}
	}
	if($rate2_ != ""){
		if($rate2_ != "auto"){
			$uci->mode("del");
			$uci->del("wireless.".$vap2.".setLegacyRates");
			$uci->del("wireless.".$vap2.".set11NRates");
			$uci->del("wireless.".$vap2.".nss");
			$uci->del("wireless.".$vap2.".vhtmcs");
			$uci->run();
			$uci->mode("set");
			if(preg_match("/^NSS(\d+)\-MCS(\d+)/",$rate2_,$d) == true) {
				//AC
				$uci->set("wireless.".$vap2.".nss",$d[1]);
				$uci->set("wireless.".$vap2.".vhtmcs",$d[2]);
			}elseif(preg_match("/^MCS(\d+)/",$rate2_,$d) == true){
				//MSC
				$base = hexdec("80");
				$base = $base + $d[1];
				$rate = (string)dechex($base);
				$rate = "0x".$rate.$rate.$rate.$rate;
				$uci->set("wireless.".$vap2.".set11NRates",$rate);
			}elseif(preg_match("/^([\d+\.]{1,})M/",$rate1_,$d) == true){
				//Legacy
				$uci->set("wireless.".$vap2.".setLegacyRates",$rate2_);
			}
		}else{
			$uci->mode("del");
			$uci->del("wireless.".$vap2.".setLegacyRates");
			$uci->del("wireless.".$vap2.".set11NRates");
			$uci->del("wireless.".$vap2.".nss");
			$uci->del("wireless.".$vap2.".vhtmcs");
			$uci->run();
			$uci->mode("set");
		}
	}
	$uci->run();
	$uci->result();
	$uci->commit();
	$uci->close();
	echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));
?>