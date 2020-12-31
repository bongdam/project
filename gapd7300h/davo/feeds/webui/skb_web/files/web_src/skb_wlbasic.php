<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$uci = new uci();
	$syscall = new dvcmd();

	$ssid = "";
	$wlan_id = dv_session("wlan_id");

	if(DEF_MODEL == "QCA_REF" && DEF_ANT == "4x4"){
		$syscall->add("uci_show","wireless | grep @wifi-iface | grep device","!");
		$syscall->run();
		$ifcnt = count(explode("\n",rtrim($syscall->result()[0])));
		if($ifcnt == 9){
			$uci->mode("del");
			$uci->del("wireless.@wifi-iface[4]");
			$uci->del("wireless.@wifi-iface[5]");
			$uci->del("wireless.@wifi-iface[6]");
			$uci->run();
			$uci->commit();
		}
	}
	$uci->mode("get");
	if(DEF_MODEL == "QCA_REF" && DEF_ANT == "4x4"){
		if($wlan_id == "0"){
			//2.4G
			$wifi2 = "ath2";
			//uci show wireless | grep @wifi-iface | grep device | sed "s/.device='wifi//" | sed "s/..$//" | sed -n "4,6p"
			$uci->get("wireless.wifi2");
			$syscall->add("uci_show","wireless | grep @wifi-iface | grep device | sed \"s/.device='wifi//\" | sed \"s/..$//\" | sed -n \"4,6p\"","!");
			$syscall->run();
			$pre = explode("\n",rtrim($syscall->result()[0]));
			$uci->mode("ck");
			for($i=0; $i < count($pre); $i++){
				$uci->ck($pre[$i]);
				$uci->get($pre[$i]);
			}
			$uci->run();
			$wifi_cfg = $uci->result();
			if($wifi_cfg == ""){
				$wifi_cfg = "null";
			}
			$uci->mode("get");
			$uci->run();
			$wifi_val = $uci->result();
			if($wifi_val == ""){
				$wifi_val = "null";
			}
		}else{
			//5G
			$wifi5 = "ath0";
			$uci->get("wireless.wifi0");
			//uci show wireless | grep @wifi-iface | grep device | sed "s/.device='wifi//" | sed "s/..$//" | sed -n "1,3p"
			$syscall->add("uci_show","wireless | grep @wifi-iface | grep device | sed \"s/.device='wifi//\" | sed \"s/..$//\" | sed -n \"1,3p\"","!");
			$syscall->run();
			$pre = explode("\n",rtrim($syscall->result()[0]));
			$uci->mode("ck");
			for($i=0; $i < count($pre); $i++){
				$uci->ck($pre[$i]);
				$uci->get($pre[$i]);
			}
			$uci->run();
			$wifi_cfg = $uci->result();
			if($wifi_cfg == ""){
				$wifi_cfg = "null";
			}
			$uci->mode("get");
			$uci->run();
			$wifi_val = $uci->result();
			if($wifi_val == ""){
				$wifi_val = "null";
			}
		}
	}elseif(DEF_MODEL != "QCA_REF" && DEF_ANT == "4x4"){
		if($wlan_id == "0"){
			//2.4G
			$wifi2 = "ath1";
			$uci->get("wireless.wifi1");
			$uci->get("wireless.vap10");
			$uci->get("dvmgmt.misc");
		}else{
			//5G
			$wifi5 = "ath0";
			$uci->get("wireless.wifi0");
			$uci->get("wireless.vap00");
		}
		$uci->run();
		$wifi_cfg = "null";
		$wifi_val = $uci->result();
		$wifiinfo = json_decode($wifi_val,true);
		$ssid_5 = get_array_val($wifiinfo,"wireless.vap00.ssid");
		$ssid_24 = get_array_val($wifiinfo,"wireless.vap10.ssid");
		$wifi_disabled = "";
		$band = "";
		$bandwidth = "";
		$sideband = "+";
		$channel = "auto";
		$ssid_hidden = "0";
		$tx_limit = "0";
		$rx_limit = "0";
		if($wlan_id == "0"){
			$ssid = $ssid_24;
			if(get_array_val($wifiinfo,"wireless.wifi1.disabled") == "1"){
				$wifi_disabled = "checked";
			}
			if(get_array_val($wifiinfo,"wireless.wifi1.hwmode") == ""){
				$band = "auto";
			}else{
				$band = get_array_val($wifiinfo,"wireless.wifi1.hwmode");
			}
			if($band == "11ng"){
				//N puren
				if(get_array_val($wifiinfo,"wireless.vap10.puren") == "1"){
					$band = "11n";
				}
				//GN pureg
				if(get_array_val($wifiinfo,"wireless.vap10.pureg") == "1"){
					$band = "11ng";
				}
				if(get_array_val($wifiinfo,"wireless.vap10.puren") != "1" && get_array_val($wifiinfo,"wireless.vap10.pureg") != "1"){
					$band = "11bgn";
				}
			}
			if(get_array_val($wifiinfo,"wireless.wifi1.htmode") == ""){
				$bandwidth = "HT40";
			}else{
				$bandwidth = preg_replace ("/[\+\-]/","",get_array_val($wifiinfo,"wireless.wifi1.htmode"));
				if(strlen($bandwidth) != strlen(get_array_val($wifiinfo,"wireless.wifi1.htmode"))){
					$sideband = preg_replace ("/[^\+\-]/","",get_array_val($wifiinfo,"wireless.wifi1.htmode"));
				}
				if(get_array_val($wifiinfo,"dvmgmt.misc.skb_2g_autobw") == "1"){
					$bandwidth = "dv_auto";
				}
			}
			if(get_array_val($wifiinfo,"wireless.wifi1.channel") == ""){
				$channel = "auto";
			}else{
				$channel = get_array_val($wifiinfo,"wireless.wifi1.channel");
			}
			if(get_array_val($wifiinfo,"wireless.vap10.hidden") != ""){
				$ssid_hidden = get_array_val($wifiinfo,"wireless.vap10.hidden");
			}
			$data_rate_ = "auto";
			if(get_array_val($wifiinfo,"wireless.vap10.set11NRates") != ""){
				$ori = hexdec(substr(get_array_val($wifiinfo,"wireless.vap10.set11NRates"),2,2)) - hexdec("80");
				$data_rate_ = "MCS".$ori;
			}else{
				if(get_array_val($wifiinfo,"wireless.vap10.setLegacyRates") != ""){
					$data_rate_ = get_array_val($wifiinfo,"wireless.vap10.setLegacyRates");
				}
			}
			if(get_array_val($wifiinfo,"wireless.vap10.maxsta") != ""){
				$max_conn = get_array_val($wifiinfo,"wireless.vap10.maxsta");
			}else{
				$max_conn = 127;
			}
			if(get_array_val($wifiinfo,"wireless.vap10.tx_limit") != ""){
				$tx_limit = get_array_val($wifiinfo,"wireless.vap10.tx_limit");
			}else{
				$tx_limit = 0;
			}
			if(get_array_val($wifiinfo,"wireless.vap10.rx_limit") != ""){
				$rx_limit = get_array_val($wifiinfo,"wireless.vap10.rx_limit");
			}else{
				$rx_limit = 0;
			}
			if(get_array_val($wifiinfo,"wireless.vap10.wds") != ""){
				$wds = get_array_val($wifiinfo,"wireless.vap10.wds");
			}else{
				$wds = 0;
			}
			if(get_array_val($wifiinfo,"wireless.vap10.wds") != ""){
				$wmm = get_array_val($wifiinfo,"wireless.vap10.wmm");
			}else{
				$wmm = 0;
			}
		}else{
			$ssid = $ssid_5;
			if(get_array_val($wifiinfo,"wireless.wifi0.disabled") == "1"){
				$wifi_disabled = "checked";
			}
			if(get_array_val($wifiinfo,"wireless.wifi0.hwmode") == ""){
				$band = "auto";
			}else{
				$band = get_array_val($wifiinfo,"wireless.wifi0.hwmode");
			}
			if($band == "11na"){
				//N puren
				if(get_array_val($wifiinfo,"wireless.vap00.puren") == "1"){
					$band = "11n";
				}
			}
			if($band == "11ac"){
				if(get_array_val($wifiinfo,"wireless.vap00.puren") == "1"){
					$band = "11nac";
				}
				if(get_array_val($wifiinfo,"wireless.vap00.pureac") == "1"){
					$band = "11ac_only";
				}
			}
			if(get_array_val($wifiinfo,"wireless.wifi0.htmode") == ""){
				$bandwidth = "HT160";
			}else{
				$bandwidth = preg_replace ("/[\+\-]/","",get_array_val($wifiinfo,"wireless.wifi0.htmode"));
				if(strlen($bandwidth) != strlen(get_array_val($wifiinfo,"wireless.wifi0.htmode"))){
					$sideband = preg_replace ("/[^\+\-]/","",get_array_val($wifiinfo,"wireless.wifi0.htmode"));
				}
			}
			if(get_array_val($wifiinfo,"wireless.wifi0.channel") == ""){
				$channel = "auto";
			}else{
				$channel = get_array_val($wifiinfo,"wireless.wifi0.channel");
			}
			if(get_array_val($wifiinfo,"wireless.vap00.cfreq2") == ""){
				$channel2 = "";
			}else{
				$channel2 = get_array_val($wifiinfo,"wireless.vap00.cfreq2");
			}
			
			if(get_array_val($wifiinfo,"wireless.vap00.hidden") != ""){
				$ssid_hidden = get_array_val($wifiinfo,"wireless.vap00.hidden");
			}
			$data_rate_ = "auto";
			if(get_array_val($wifiinfo,"wireless.vap00.nss") != ""){
				$data_rate_ = "NSS".get_array_val($wifiinfo,"wireless.vap00.nss")."-MCS".get_array_val($wifiinfo,"wireless.vap00.vhtmcs");
			}elseif(get_array_val($wifiinfo,"wireless.vap00.set11NRates") != ""){
				$ori = hexdec(substr(get_array_val($wifiinfo,"wireless.vap00.set11NRates"),2,2)) - hexdec("80");
				$data_rate_ = "MCS".$ori;
			}else{
				if(get_array_val($wifiinfo,"wireless.vap00.setLegacyRates") != ""){
					$data_rate_ = get_array_val($wifiinfo,"wireless.vap00.setLegacyRates");
				}
			}
			if(get_array_val($wifiinfo,"wireless.vap00.maxsta") != ""){
				$max_conn = get_array_val($wifiinfo,"wireless.vap00.maxsta");
			}else{
				$max_conn = 127;
			}
			if(get_array_val($wifiinfo,"wireless.vap00.tx_limit") != ""){
				$tx_limit = get_array_val($wifiinfo,"wireless.vap00.tx_limit");
			}else{
				$tx_limit = 0;
			}
			if(get_array_val($wifiinfo,"wireless.vap00.rx_limit") != ""){
				$rx_limit = get_array_val($wifiinfo,"wireless.vap00.rx_limit");
			}else{
				$rx_limit = 0;
			}
			if(get_array_val($wifiinfo,"wireless.vap00.wds") != ""){
				$wds = get_array_val($wifiinfo,"wireless.vap00.wds");
			}else{
				$wds = 0;
			}
		}
		
		
	}elseif(DEF_MODEL != "QCA_REF" && DEF_ANT == "2x2"){
		
	}
	//ls -p hostapd-wifi* | sed "s/://" | sed "s/hostapd-//" | sed "/^$/d"
	$uci->close();
	$syscall->close();
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>WLAN Basic Settings</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"></script>
<script type="text/javascript" src="js/wifihelper.js?q=<?=time();?>"></script>
<link href="style.css" rel="stylesheet" type="text/css">
<style>
.on {display:on}
.off {display:none}
</style>
<script type="text/javascript">
var wlan_idx = "<?=$wlan_id?>";
var proc = "/proc/skb_wlbasic_proc.php";


function page_change(selectObj)
{
	//wlan_redriect
	if (selectObj.value==1)
		location.href='wlan_redriect.php?redirect-url=skb_wlbasic.php&wlan_id=1';
	else
		location.href='wlan_redriect.php?redirect-url=skb_wlbasic.php&wlan_id=0';
}
function showMacClick(form, url)
{
	if (!form.elements["wlan_enable"].checked){
		openWindow(url, 'showWirelessClient', 820, 500 );
	}
}
function showMultipleAP(form, url)
{
	document.location.href = url;
}
var radio_control = function(type_){
	var type = type_ ? type_ : "0";
	switch(type){
		case "0":
			//ALL
			create_band();
			break;
		case "1":
			//
			break;
	}
}
var create_band = function(flag_){
	var flag = flag_ ? flag_ : "";
	var tobj = $("#band");
	var radio = $("#radio").val();
	tobj.children().remove();
	if(radio == "0"){
		for(var i=0; i < band_val["band24"].length; i++){
			tobj.append("<option value=\""+band["band24"][i].mode+"\">2.4 GHz ("+band_val["band24"][i].mode+")</option>");
		}
		if(flag == ""){
			tobj.val("<?=$band?>");
		}else{
			tobj.val("11bgn");
		}
	}else{
		for(var i=0; i < band_val["band5"].length; i++){
			tobj.append("<option value=\""+band["band5"][i].mode+"\">5 GHz ("+band_val["band5"][i].mode+")</option>");
		}
		if(flag == ""){
			tobj.val("<?=$band?>");
		}else{
			tobj.val("11ac");
		}
	}
	create_band_width();
	create_channel();
	create_data_rate();
}
var create_band_width = function(flag_){
	var flag = flag_ ? flag_ : "";
	var tobj = $("#band_width");
	var radio = $("#radio").val();
	var band = $("#band").children(":selected").val();
	tobj.children().remove();
	if(radio == "0"){
		if(band == "11n" || band == "11ng" || band == "11bgn"){
			$("#channel_bounding,#control_sideband").show();
			$("#sideband,#band_width").prop("disabled",false);
			for(var i=0; i < band_width["band24"].length; i++){
				tobj.append("<option value=\""+band_width["band24"][i].mode+"\">"+band_width_val["band24"][i].mode+"</option>");
			}
			if(flag == ""){
				tobj.val("<?=$bandwidth?>");
			}else{
				tobj.val("HT40");
			}
		}else{
			$("#channel_bounding,#control_sideband").hide();
			$("#sideband,#band_width").prop("disabled",true);
			for(var i=0; i < band_width["band24"].length; i++){
				tobj.append("<option value=\""+band_width["band24"][i].mode+"\">"+band_width_val["band24"][i].mode+"</option>");
			}
			if(flag == ""){
				tobj.val("<?=$bandwidth?>");
			}else{
				tobj.val("HT40");
			}
		}
	}else{
		for(var i=0; i < band_width["band5"].length; i++){
			tobj.append("<option value=\""+band_width["band5"][i].mode+"\">"+band_width_val["band5"][i].mode+"</option>");
		}
		if(flag == ""){
			tobj.val("<?=$bandwidth?>");
		}else{
			tobj.val("HT160");
		}
	}
}
var craete_sideband = function(flag_){
	var flag = flag_ ? flag_ : "";
	var tobj = $("#sideband");
	var radio = $("#radio").val();
	var band = $("#band").children(":selected").val();
	if(flag == ""){
		tobj.val("<?=$sideband?>");
	}else{
		tobj.val("+");
	}
}
var create_channel = function(flag_){
	var flag = flag_ ? flag_ : "";
	var tobj = $("#channel");
	var radio = $("#radio").val();
	var band_width = $("#band_width").children(":selected").val();
	
	tobj.children().remove();
	if(radio == "0"){
		for(var i=0; i < ch["band24"].length; i++){
			tobj.append("<option value=\""+ch["band24"][i].ch+"\">"+ch_val["band24"][i].ch+"</option>");
		}
		if(flag == ""){
			tobj.val("<?=$channel?>");
			$("#btn_ch_reset").hide();
			change_channel();
		}else{
			tobj.val("auto");
			$("#btn_ch_reset").show();
		}
	}else{
		for(var i=0; i < ch["band5"].length; i++){
			if(band_width == "HT40"){
				if(ch["band5"][i].ch % 8 != 0 && ch["band5"][i].ch  != "auto" && ch["band5"][i].ch  != "153" && ch["band5"][i].ch  != "161"){
					continue;
				}else{
					tobj.append("<option value=\""+ch["band5"][i].ch+"\" dfs=\""+ch["band5"][i].dfs+"\">"+ch_val["band5"][i].ch+"</option>");
				}
			}else if(band_width == "HT80" || band_width == "HT80_80"){
				if(ch["band5"][i].ht80 == false){
					continue;
				}else{
					tobj.append("<option value=\""+ch["band5"][i].ch+"\" dfs=\""+ch["band5"][i].dfs+"\">"+ch_val["band5"][i].ch+"</option>");
				}
			}else if(band_width == "HT160"){
				if(ch["band5"][i].ht160 == false){
					continue;
				}else{
					tobj.append("<option value=\""+ch["band5"][i].ch+"\" dfs=\""+ch["band5"][i].dfs+"\">"+ch_val["band5"][i].ch+"</option>");
				}
			}else{
				tobj.append("<option value=\""+ch["band5"][i].ch+"\" dfs=\""+ch["band5"][i].dfs+"\">"+ch_val["band5"][i].ch+"</option>");
			}
		}
		if(flag == ""){
			tobj.val("<?=$channel?>");
			$("#btn_ch_reset").hide();
			change_channel();
			
		}else{
			tobj.val("auto");
			$("#btn_ch_reset").show();
		}
	}
	change_channel();
	craete_sideband();
}
var create_data_rate = function(flag_){
	var flag = flag_ ? flag_ : "";
	var tempVal = "";
	var tobj = $("#data_rate");
	var radio = $("#radio").val();
	var band = $("#band").children(":selected").val();
	var band_width = $("#band_width").children(":selected").val();
	var rate_b = ["1M", "2M", "5.5M", "11M"];
	var rate_g = ["6M", "9M", "12M", "18M", "24M", "36M", "48M", "54M"];
	var rate_n = new Array();
	var rate_ac = new Array();
	for(var i=0; i < 32; i++){
		rate_n.push("MCS"+i);
	}
	if(band_width == "HT20"){
		for(var i=1; i <= 4; i++){
			for(var j=0; j <= 8; j++){
				rate_ac.push("NSS"+i+"-MCS"+j);
				if(i == 3 && j == 8){
					rate_ac.push("NSS"+i+"-MCS9");
				}
			}
		}
	}else if(band_width == "HT40"){
		for(var i=1; i <= 4; i++){
			for(var j=0; j <= 9; j++){
				rate_ac.push("NSS"+i+"-MCS"+j);
			}
		}
	}else if(band_width == "HT80"){
		for(var i=1; i <= 4; i++){
			for(var j=0; j <= 9; j++){
				if(i == 3 && j == 6){
					continue;
				}
				rate_ac.push("NSS"+i+"-MCS"+j);
			}
		}
	}else if(band_width == "HT160"){
		for(var i=1; i <= 4; i++){
			for(var j=0; j <= 9; j++){
				if(i == 3 && j == 9){
					continue;
				}
				rate_ac.push("NSS"+i+"-MCS"+j);
			}
		}
	}else if(band_width == "HT80_80"){
		for(var i=1; i <= 4; i++){
			for(var j=0; j <= 9; j++){
				if(i == 3 && j == 9){
					continue;
				}
				rate_ac.push("NSS"+i+"-MCS"+j);
			}
		}
	}

	var rate = new Array();
	//N MODE = MCS0 ~ MCS31
	//AC MODE = NSS1-MCS0 ~ MCS8, NSS2-MCS0 ~ MCS8, NSS3-MCS0 ~ MCS9, NSS4-MCS0 ~ MCS8
	tobj.children().remove();
	switch(band){
		case "11b":
			rate = rate.concat(rate_b);
			break;
		case "11g":
			rate = rate.concat(rate_g);
			break;
		case "11bg":
			rate = rate.concat(rate_b);
			rate = rate.concat(rate_g);
			break;
		case "11n":
			rate = rate.concat(rate_n);
			break;
		case "11ng":
			rate = rate.concat(rate_g);
			rate = rate.concat(rate_n);
			break;
		case "11bgn":
			rate = rate.concat(rate_b);
			rate = rate.concat(rate_g);
			rate = rate.concat(rate_n);
			break;
		case "11a":
			rate = rate.concat(rate_g);
			break;
		case "11na":
			rate = rate.concat(rate_g);
			rate = rate.concat(rate_n);
			break;
		case "11nac":
			rate = rate.concat(rate_n);
			rate = rate.concat(rate_ac);
			break;
		case "11ac_only":
			rate = rate.concat(rate_ac);
			break;
		case "11ac":
			rate = rate.concat(rate_g);
			rate = rate.concat(rate_n);
			rate = rate.concat(rate_ac);
			break;
	}
	tempVal += "<option value=\"auto\">Auto</option>";
	for (var i=0; i < rate.length ; i++ )
	{
		tempVal += "<option value=\""+rate[i]+"\">"+rate[i]+"</option>";
	}
	tobj.append(tempVal);
	if(flag == ""){
		tobj.val("<?=$data_rate_?>");
	}else{
		tobj.val("auto");
	}
}
var change_wifi_status = function(){
	if($("#wlan_enable").prop("checked") == true){
		$("#wlanSetup").find("input").prop("disabled",true);
		$("#wlanSetup").find("select").prop("disabled",true);
		$("#radio").prop("disabled",false);
		$("#wlan_enable").prop("disabled",false);
		$("#btn_save,#btn_reset").prop("disabled",false);
		$("#act").prop("disabled",false);
		$("#seq").prop("disabled",false);
		$("#wlan-url").prop("disabled",false);
	}else{
		$("#wlanSetup").find("input").prop("disabled",false);
		$("#wlanSetup").find("select").prop("disabled",false);
	}
}
var check_wifi_status = function(){
	var radio = $("#radio").val();
	var band = $("#band").children(":selected").val();
	var band_width_ = $("#band_width").children(":selected").val();
	var channel = $("#channel").children(":selected").val();
	if(radio == "0"){
		switch(band){
			case "11b":
			case "11g":
			case "11bg":
				$("#channel_bounding").hide();
				$("#control_sideband").hide();
				change_channel();
				$("#wmm").prop("disabled",false);
				break;
			case "11n":
			case "11ng":
			case "11bgn":
				$("#channel_bounding").show();
				$("#control_sideband").show();
				if(band_width_ == "HT20"){
					$("#control_sideband").hide();
				}
				$("#wmm").val("1");
				$("#wmm").prop("disabled",true);
				change_channel();
				break;
		}
	}else{
		switch(band){
			case "11a":
				$("#channel_bounding").hide();
				$("#control_sideband").hide();
				if($("#channel").children().length < 12){
					create_channel(1);
				}
				$("#wmm").prop("disabled",false);
				break;
			case "11n":
			case "11na":
			case "11ac":
			case "11nac":
			case "11ac_only":
				if(band == "11n" || band == "11na"){
					
					if($("#band_width").children().length > 2){
						$("#band_width").children().remove();
						for(var i=0; i < 2; i++){
							$("#band_width").append("<option value=\""+band_width["band5"][i].mode+"\">"+band_width_val["band5"][i].mode+"</option>");
						}
						$("#band_width").children().eq(1).prop("selected",true);
					}
					
				}else{
					if($("#band_width").children().length < 3){
						$("#band_width").children().remove();
						for(var i=0; i < band_width["band5"].length; i++){
							$("#band_width").append("<option value=\""+band_width["band5"][i].mode+"\">"+band_width_val["band5"][i].mode+"</option>");
						}
						$("#band_width").children().eq((band_width["band5"].length-1)).prop("selected",true);
					}
				}
				$("#channel_bounding").show();
				$("#control_sideband").show();
				if(band_width_ != "HT40"){
					$("#sideband").prop("disabled",true);
					if($("#channel").children().length < 12){
						create_channel(1);
					}
					if(band_width_ == "HT160"){
						if($("#channel").children().length > 9){
							create_channel(1);
						}
					}
				}else{
					if(band_width_ == "HT40" && $("#channel").children().length != 10){
						create_channel(1);
					}
				}
				$("#wmm").val("1");
				$("#wmm").prop("disabled",true);
				break;
		}
		change_channel();
	}
	create_data_rate();
}
var change_sideband = function(){
	var radio = $("#radio").val();
	var band_width = $("#band_width").children(":selected").val();
	var channel = $("#channel").children(":selected").val();
	var tobj = $("#channel");
	var sideband = $("#sideband").children(":selected").val();
	if(radio == "1" && band_width == "HT40"){
		tobj.children().remove();
		for(var i=0; i < ch["band5"].length; i++){
			if (sideband == "-")
			{
				if(ch["band5"][i].ch % 8 == 0 || ch["band5"][i].ch  == "124" || ch["band5"][i].ch == "153" || ch["band5"][i].ch  == "161"){
					continue;
				}else{
					tobj.append("<option value=\""+ch["band5"][i].ch+"\" dfs=\""+ch["band5"][i].dfs+"\">"+ch_val["band5"][i].ch+"</option>");
					if(channel == ch["band5"][i].ch){
						tobj.val(channel);
					}
				}
			}else{
				if(ch["band5"][i].ch % 8 != 0 && ch["band5"][i].ch  != "auto" && ch["band5"][i].ch  != "153" && ch["band5"][i].ch  != "161"){
					continue;
				}else{
					tobj.append("<option value=\""+ch["band5"][i].ch+"\" dfs=\""+ch["band5"][i].dfs+"\">"+ch_val["band5"][i].ch+"</option>");
					if(channel == ch["band5"][i].ch){
						tobj.val(channel);
					}
				}
			}
		}
		if($("#channel").children(":selected").val() == ""){
			$("#channel").val("auto");
			change_channel();
		}
	}
}
var change_channel = function(flag_){
	var flag = flag_ ? flag_ : "";
	var radio = $("#radio").val();
	var band_width = $("#band_width").children(":selected").val();
	var channel = $("#channel").children(":selected").val();
	var dfs = $("#channel").children(":selected").attr("dfs");
	$("#btn_ch_reset").hide();
	$("#second_channel").hide();
	if(radio == "0"){
		if(isNumVal(channel) == true){
			channel = parseInt(channel,10);
		}
		if(channel < 5){
			$("#sideband").prop("disabled",true);
			$("#sideband").val("-");
		}else if(channel > 9){
			$("#sideband").prop("disabled",true);
			$("#sideband").val("+");
		}else if(channel == "auto"){
			$("#sideband").prop("disabled",true);
			$("#btn_ch_reset").show();
		}else{
			$("#sideband").prop("disabled",false);
		}
	}else{
		
		if(dfs == true && flag == 1){
//			console.log(dfs);
			alert("선택 채널로 변경시 DFS에 의해 채널이 변경될 수 있습니다.");
		}
		if(band_width == "HT40"){
			if(channel == "auto"){
				$("#sideband").prop("disabled",true);
				$("#sideband").val("+");
				$("#btn_ch_reset").show();
			}else{
				$("#sideband").prop("disabled",false);
			}
		}else if(band_width == "HT80_80"){
			if(channel == "auto"){
				$("#btn_ch_reset").show();
			}else{
				$("#second_channel").show();
//				$("#cfreq2")
				$("#cfreq2").children().remove();
				if(parseInt(channel,10) >= 36 && parseInt(channel,10) <= 64){
					//class1
					$("#cfreq2").append("<option value=\"106\">100-112</option>");
					$("#cfreq2").append("<option value=\"155\">149-161</option>");
				}else if(parseInt(channel,10) >= 100 && parseInt(channel,10) <= 112){
					//class2
					$("#cfreq2").append("<option value=\"42\">36-48</option>");
					$("#cfreq2").append("<option value=\"58\">52-64</option>");
//					$("#cfreq2").append("<option value=\"106\">100-112</option>");
					$("#cfreq2").append("<option value=\"155\">149-161</option>");
				}else if(parseInt(channel,10) >= 149 && parseInt(channel,10) <= 161){
					//class3
					$("#cfreq2").append("<option value=\"42\">36-48</option>");
					$("#cfreq2").append("<option value=\"58\">52-64</option>");
					$("#cfreq2").append("<option value=\"106\">100-112</option>");
//					$("#cfreq2").append("<option value=\"155\">149-161</option>");
				}
				var channel2 = "<?=$channel2?>";
				$("#cfreq2").val(channel2);
				if($("#cfreq2").val() == null){
					$("#cfreq2").children().eq(0).prop("selected",true);
				}
			}
		}else{
			if(channel == "auto"){
				$("#btn_ch_reset").show();
			}
		}
	}
}
var run_ch_reset = function(){
	$("#btn_ch_reset").prop("disabled",true);
	var radio = $("#radio").val();
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'run_ch_reset';
	sobj['radio'] = radio;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			console.log(d);
		}
	});
	$("#btn_ch_reset").prop("disabled",false);
}
var save_form = function(){
	var ssid = $("#ssid").val();
	if(ssid == ""){
		alert("SSID를 입력해주세요.");
		$("#ssid").focus();
		return false;
	}
	if(!check_xss(ssid)){
		alert(xss_err_msg);
		$("#ssid").focus();
		return false;
	}
	if($("#wlan_max_conn").val() == ""){
		alert("동시접속 제한을 입력해주세요.");
		$("#wlan_max_conn").focus();
		return false;
	}
	if($("#wlan_max_conn").val() == ""){
		alert("동시접속 제한을 입력해주세요.");
		$("#wlan_max_conn").focus();
		return false;
	}
	if(isNumVal($("#wlan_max_conn").val()) == false){
		alert("동시접속은 1~250을 입력해주세요.");
		$("#wlan_max_conn").focus();
		return false;
	}
	if(check_min_max($("#wlan_max_conn").val(),1,250) == false){
		alert("동시접속은 1~250을 입력해주세요.");
		$("#wlan_max_conn").focus();
		return false;
	}
//	document.wlanSetup.submit();
}
$(document).ready(function(){
	$("#radio").val(wlan_idx);
	radio_control();
	change_wifi_status();
	check_wifi_status();
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
	}else{
		echo("Wireless Basic Settings");
	}
?>
</h2>
<form action="/proc/skb_wlbasic_proc.php" method="POST" name="wlanSetup" id="wlanSetup">
<input type="hidden" name="act" id="act" value="set_wifi">
<input type="hidden" name="seq" id="seq" value="0">
<!-- <input type="hidden" name="data_rate" id="data_rate" value=""> -->
<table border="0" width="500" cellspacing="4">
	<tr>
		<td colspan="2"><font size="2">무선 인터넷에 대한 기본적인 설정을 할 수 있는 페이지 입니다.</font></td>
	</tr>
	<tr>
		<td width="26%"><font size="2"><b>무선:</b></font></td>
		<td width="74%"><select name="radio" id="radio" onchange="page_change(this)">
			<option value="0">2.4 GHz</option>
			<option value="1">5 GHz</option>
		</select></td>
	</tr>
	<tr>
		<td width="100%" colspan="2"><font size="2"><b><input type="checkbox" name="wlan_enable" id="wlan_enable" value="1" onclick="change_wifi_status(document.wlanSetup, wlan_idx)" <?=$wifi_disabled?>>&nbsp;&nbsp;무선 인터넷 사용안함</b></font></td>
	</tr>
	<tr>
			<td width="26%"><font size="2"><b>Band:</b></td>
			<td width="74%"><font size="2"><select size="1" name="band" id="band" onchange="check_wifi_status();"></select></td>
	</tr>
	<tr>
		<td width="26%"><font size="2"><b>SSID:</b></font></td>
		<td width="74%"><font size="2"><input type="text" name="ssid" id="ssid" size="33" maxlength="32" value="<?=$ssid?>"></font></td>
	</tr>
	<tr id="channel_bounding">
		<td width="26%"><font size="2"><b>채널 폭:</b></font></td>
		<td width="74%"><font size="2"><select size="1" name="band_width" id="band_width" onchange="check_wifi_status();">
			<option value="5">자동</option>
			<option value="0">20MHz</option>
			<option value="1">20/40MHz</option>
		</select></font></td>
	</tr>
	
	<tr id="control_sideband">
		<td width="26%"><font size="2"><b>Control Sideband:</b></font></td>
		<td width="74%"><font size="2"><select size="1" name="sideband" id="sideband" onchange="change_sideband();">
			<option value="+">Upper</option>
			<option value="-">Lower</option>
		</select></font></td>
	</tr>
	<tr>
		<td width="26%"><font size="2"><b>채널 번호:</b></font></td>
		<td width="74%"><font size="2"><select size="1" name="channel" id="channel" onchange="change_channel(1);"></select> &nbsp;<input type="button" name="btn_ch_reset" id="btn_ch_reset" value="채널 재설정" onclick="run_ch_reset();"></font></td>
	</tr>
	<tr id="second_channel">
		<td width="26%"><font size="2"><b>2nd 채널 번호:</b></font></td>
		<td width="74%"><font size="2"><select size="1" name="cfreq2" id="cfreq2"></select></font></td>
	</tr>
	<tr>
		<td width="26%"><font size="2"><b>SSID 알림:</b></font></td>
		<td width="74%"><font size="2"><select size="1" name="hidden_ssid" id="hidden_ssid">
			<option value="1" <?php if($ssid_hidden == "1"){ echo("selected");}?>>사용안함</option>
			<option value="0" <?php if($ssid_hidden == "0"){ echo("selected");}?>>사용</option>
		</select></font></td>
	</tr>
	<tr id="wlan_wmm" style="display:">
		<td width="26%"><font size="2"><b>WMM:</b></font></td>
		<td ><font size="2"><select size="1" name="wmm" id="wmm" onchange="">
			<option value="0" <?php if($wmm == "0"){ echo("selected");}?>>사용안함</option>
			<option value="1" <?php if($wmm == "1"){ echo("selected");}?>>사용</option>
		</select><input type="button" value="WMM 매핑" name="showWMM" onClick="showMacClick(document.wlanSetup, '/skb_wlwmm.php#form')"></font></td>
	</tr>
	<tr>
		<td width="26%"><font size="2"><b>데이터 전송률:</b></font></td>
		<td width="74%"><font size="2"><select name="data_rate" id="data_rate"></select></font></td>
	</tr>
	<tr>
			<td width="26%"><font size="2"><b>TX 제한:</b></font></td>
			<td width="74%"><font size="2"><input type="text" name="tx_limit" id="tx_limit" size="5" maxlength="4" value="<?=$tx_limit;?>">&nbsp;Mbps&nbsp;(0: 제한없음)</font></td>
	</tr>

	<tr>
			<td width="26%"><font size="2"><b>RX 제한:</b></font></td>
			<td width="74%"><font size="2"><input type="text" name="rx_limit" id="rx_limit" size="5" maxlength="4" value="<?=$rx_limit;?>">&nbsp;Mbps&nbsp;(0: 제한없음)</font></td>
	</tr>
	<tr>
		<td width="26%"><font size="2"><b>Multi SSID	:</b></font></td>
		<td width="74%"><font size="2"><input type="button" value="설정" name="multipleAP" onClick="showMultipleAP(document.wlanSetup, '/skb_wlmultipleap.php')"></font></td>
	</tr>
	<tr>
		<td width="26%"><font size="2"><b>접속 리스트:</b></font></td>
		<td width="74%"><font size="2"><input type="button" value="접속 리스트" name="showMac" onClick="showMacClick(document.wlanSetup, '/skb_wlstatbl.php?seq=0#form')"></font></td>
	</tr>
	<tr>
		<td width="26%"><font size="2"><b>동시접속제한:</b></font></td>
		<td width="74%"><input type="text" style="ime-mode:disabled;" name="wlan_max_conn" id="wlan_max_conn" size="3" maxlength="3" value="<?=$max_conn?>">(1~250)</td>
	</tr>
	<tr>
		<td width="26%"><font size="2"><b>WDS AP:</b></font></td>
		<td width="74%"><select size="1" name="wds" id="wds" onchange="">
			<option value="0" <?php if($wds == "0"){echo "selected";}?>>사용안함</option>
			<option value="1" <?php if($wds == "1"){echo "selected";}?>>사용</option>
		</select></td>
	</tr>
</table>
<br>
 &nbsp;
<br>
<table border="0" width="500" cellspacing="0" cellpadding="0">
	<tr>
		<td>
		<input type="hidden" value="/skb_wlbasic.php" name="wlan-url" id="wlan-url">
		<input type="submit" value="적용" name="btn_save" id="btn_save" onclick="return save_form()">&nbsp;&nbsp;
		<input type="reset" value="취소" name="btn_reset" id="btn_reset">
	</tr>
</table>
</form>


</blockquote>
</body>

</html>
