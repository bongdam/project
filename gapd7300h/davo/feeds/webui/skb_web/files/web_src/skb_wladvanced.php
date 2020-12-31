<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$wlan_id = dv_session("wlan_id");
	$mcast_rate_ = "auto";
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>Wireless Advanced Setting</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/wifihelper.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var wlan_idx = "<?=$wlan_id?>";
var proc = "proc/skb_wladvanced_proc.php";
var wlan_id = "1";
if(wlan_idx == "0"){
	wlan_id = "1";
}else{
	wlan_id = "0";
}


function validateNum(str)
{
  for (var i=0; i<str.length; i++) {
   	if ( !(str.charAt(i) >='0' && str.charAt(i) <= '9')) {
		alert("Invalid value. It should be in decimal number (0-9).");
		return false;
  	}
  }
  return true;
}

function saveChanges()
{
  if ( validateNum(document.advanceSetup.fragThreshold.value) == 0 ) {
  	document.advanceSetup.fragThreshold.focus();
	return false;
  }
  num = parseInt(document.advanceSetup.fragThreshold.value);
  if (document.advanceSetup.fragThreshold.value == "" || num < 256 || num > 2346) {
  	alert('Invalid value of Fragment Threshold. Input value should be between 256-2346 in decimal.');
  	document.advanceSetup.fragThreshold.focus();
	return false;
  }

  if ( validateNum(document.advanceSetup.rtsThreshold.value) == 0 ) {
  	document.advanceSetup.rtsThreshold.focus();
	return false;
  }
  num = parseInt(document.advanceSetup.rtsThreshold.value);
  if (document.advanceSetup.rtsThreshold.value=="" || num > 2347) {
  	alert('Invalid value of RTS Threshold. Input value should be between 0-2347 in decimal.');
  	document.advanceSetup.rtsThreshold.focus();
	return false;
  }

  if ( validateNum(document.advanceSetup.beaconInterval.value) == 0 ) {
  	document.advanceSetup.beaconInterval.focus();
	return false;
  }
  num = parseInt(document.advanceSetup.beaconInterval.value);
  if (document.advanceSetup.beaconInterval.value=="" || num < 20 || num > 1024) {
  	alert('Invalid value of Beacon Interval. Input value should be between 20-1024 in decimal.');
  	document.advanceSetup.beaconInterval.focus();
	return false;
  }

/*if (document.advanceSetup.elements["cca_mode"][0].checked == true) {
  	document.advanceSetup.x_wlan_cca_mode.value = 0;
  } else {
  	var cca = document.advanceSetup.elements["cca_menual"];
  	document.advanceSetup.x_wlan_cca_mode.value = cca.options[cca.selectedIndex].value;
  }*/

  if (parseInt(0, 10) == 0) {
	num = parseInt(document.advanceSetup.x_bs_rssi_th.value);
	if (document.advanceSetup.x_bs_rssi_th.value =="" || (num < 0 || num > 100) ) {
	  	alert('HandOver RSSI Threshold의 값이 올바르지 않습니다. 0에서 100 사이의 숫자를 입력해야 합니다.');
	  	document.advanceSetup.x_bs_rssi_th.focus();
		return false;
	  }

    num = parseInt(document.advanceSetup.x_bs_probe_deny_rssi_th.value);
	if (document.advanceSetup.x_bs_probe_deny_rssi_th =="" || (num < 0 || num > 100) ) {
	  	alert('HandOver RSSI Threshold의 값이 올바르지 않습니다. 0에서 100 사이의 숫자를 입력해야 합니다.');
	  	document.advanceSetup.x_bs_probe_deny_rssi_th.focus();
		return false;
	  }

    num = parseInt(document.advanceSetup.x_bs_tcp_pps_check_time.value);
	if (document.advanceSetup.x_bs_tcp_pps_check_time =="" || (num < 0 || num > 100)) {
	  	alert('HandOver 패킷 감시 시간의 값이 올바르지 않습니다. 0에서 100 사이의 숫자를 입력해야 합니다.');
	  	document.advanceSetup.x_bs_tcp_pps_check_time.focus();
		return false;
	  }

    num = parseInt(document.advanceSetup.x_bs_tcp_pkts_threshold.value);
	if (document.advanceSetup.x_bs_tcp_pkts_threshold =="" || (num <= 0 || num > 100)) {
	  	alert('HandOver 초당 패킷 수 입력 값이 바르지 않습니다. 1에서 100 사이의 숫자를 입력해야 합니다.');
	  	document.advanceSetup.x_bs_tcp_pkts_threshold.focus();
		return false;
	  }

	  num = parseInt(document.advanceSetup.rssiThresh0.value);
	  if (document.advanceSetup.rssiThresh0.value =="" || ((num != 0)&&(num < 20 || num > 80)) ) {
	  	alert('RSSI Threshold의 값이 올바르지 않습니다. 0(제한없음) 아니면 20에서 80 사이의 숫자를 입력해야 합니다.');
	  	document.advanceSetup.rssiThresh0.focus();
		return false;
	  }
	  num = parseInt(document.advanceSetup.rssiThresh2.value);
	  if (document.advanceSetup.rssiThresh2.value =="" || (num < 20) || (num > 80) ) {
	  	alert('RSSI Threshold의 값이 올바르지 않습니다. 20에서 80 사이의 숫자를 입력해야 합니다.');
	  	document.advanceSetup.rssiThresh2.focus();
		return false;
	  }
	  num = parseInt(document.advanceSetup.rssiThresh3.value);
	  if (document.advanceSetup.rssiThresh3.value =="" || ((num != 0)&&(num < 20 || num > 80)) ) {
	  	alert('RSSI Threshold의 값이 올바르지 않습니다. 0(제한없음) 아니면 20에서 80 사이의 숫자를 입력해야 합니다.');
	  	document.advanceSetup.rssiThresh3.focus();
		return false;
	  }
  }
/*  num = parseInt(document.advanceSetup.rssiThresh4.value);
  if (document.advanceSetup.rssiThresh4.value =="" || ((num != 0)&&(num < 20 || num > 80)) ) {
  	alert('RSSI Threshold의 값이 올바르지 않습니다. 0(제한없음) 아니면 20에서 80 사이의 숫자를 입력해야 합니다.');
  	document.advanceSetup.rssiThresh4.focus();
	return false;
  }
*/
/*
  num = parseInt(document.advanceSetup.RFPower.value);
  if (document.advanceSetup.RFPower.value =="" || ((num != 0)&&(num < 10 || num > 100)) ) {
	  alert('무선 출력 세기의 값이 올바르지 않습니다. 10에서 100 사이의 숫자를 입력해야 합니다.');
	  document.advanceSetup.RFPower.focus();
	  return false;
  }
*/
  if (enabled1X != 1 && document.advanceSetup.elements["hs2"][0].checked == true) {
  	alert('Set Security Type to 802.1x before turn on HS2 Daemon');
	resetForm();
	return false;
  }

  return true;
}

/*
function checkTurboState()
{
	var txRate= 1;

	if (txRate == 1)
		enableRadioGroup(document.advanceSetup.turbo);
	else
		disableRadioGroup(document.advanceSetup.turbo);
}
*/



function onClick_func(enable)
{
	if(enable)
		enableRadioGroup(document.advanceSetup.sideBand0);
	else
		disableRadioGroup(document.advanceSetup.sideBand0);

}
function onclick_mc2u()
{
	if($("#mcastenhance2").prop("checked") == true)
		get_by_id("mlcsttxrate").style.display = "none";
	else
		get_by_id("mlcsttxrate").style.display = "";
}
function resetForm()
{
	window.location.reload();
}

function page_change(selectObj)
{
	if (selectObj.value==1)
		location.href='wlan_redriect.php?redirect-url=skb_wladvanced.php&wlan_id=1';
	else
		location.href='wlan_redriect.php?redirect-url=skb_wladvanced.php&wlan_id=0';
}
var create_data_rate = function(flag_){
	var flag = flag_ ? flag_ : "";
	var tempVal = "";
	var tobj = $("#mcast_rate");
	var radio = wlan_idx;
	var band = $("#band").children(":selected").val();
	var rate_b = ["1M", "2M", "5.5M", "11M"];
	var rate_g = ["6M", "9M", "12M", "18M", "24M", "36M", "48M", "54M"];
	var rate_n = new Array();
	var rate_ac = new Array();
	for(var i=0; i < 32; i++){
		rate_n.push("MCS"+i);
	}
	for(var i=1; i <= 4; i++){
		for(var j=0; j <= 8; j++){
			rate_ac.push("NSS"+i+"-MCS"+j);
			if(i == 3 && j == 8){
				rate_ac.push("NSS"+i+"-MCS9");
			}
		}
	}
	var rate = new Array();
	//N MODE = MCS0 ~ MCS31
	//AC MODE = NSS1-MCS0 ~ MCS8, NSS2-MCS0 ~ MCS8, NSS3-MCS0 ~ MCS9, NSS4-MCS0 ~ MCS8
	tobj.children().remove();
	if(radio == "0"){
		rate = rate.concat(rate_b);
		rate = rate.concat(rate_g);
		rate = rate.concat(rate_n);
	}else{
		rate = rate.concat(rate_g);
		rate = rate.concat(rate_n);
		rate = rate.concat(rate_ac);
	}
	tempVal += "<option value=\"auto\">Auto</option>";
	for (var i=0; i < rate.length ; i++ )
	{
		tempVal += "<option value=\""+rate[i]+"\">"+rate[i]+"</option>";
	}
	tobj.append(tempVal);
	if(flag == ""){
		tobj.val("<?=$mcast_rate_?>");
	}else{
		tobj.val("auto");
	}
}
var get_wl_config = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_wl_config';
	sobj['radio'] = wlan_idx;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			$("#frag").val(get_json_val(d,"wireless.vap"+wlan_id+"0.frag",2346));
			$("#rts").val(get_json_val(d,"wireless.vap"+wlan_id+"0.rts",2347));
			$("#beacon").val(get_json_val(d,"wireless.vap"+wlan_id+"0.intval",100));
			$("#inact").val(get_json_val(d,"wireless.vap"+wlan_id+"0.inact",300));
			$("#shpreamble"+get_json_val(d,"wireless.vap"+wlan_id+"0.shpreamble",0)).prop("checked",true);
			$("#iapp_enable"+get_json_val(d,"wireless.vap"+wlan_id+"0.iapp_enable",0)).prop("checked",true);
			$("#protmode"+get_json_val(d,"wireless.vap"+wlan_id+"0.protmode",0)).prop("checked",true);
			$("#ampdu"+get_json_val(d,"wireless.vap"+wlan_id+"0.ampdu",0)).prop("checked",true);
			$("#shortgi"+get_json_val(d,"wireless.vap"+wlan_id+"0.shortgi",0)).prop("checked",true);
			$("#isolate"+get_json_val(d,"wireless.vap"+wlan_id+"0.isolate",0)).prop("checked",true);
			$("#tx_stbc"+get_json_val(d,"wireless.vap"+wlan_id+"0.tx_stbc",0)).prop("checked",true);
			$("#ldpc"+get_json_val(d,"wireless.vap"+wlan_id+"0.ldpc",0)).prop("checked",true);
			$("#disablecoext"+get_json_val(d,"wireless.vap"+wlan_id+"0.disablecoext",1)).prop("checked",true);
			$("#mcastenhance"+get_json_val(d,"wireless.vap"+wlan_id+"0.mcastenhance",0)).prop("checked",true);
			$("#vhtsubfer"+get_json_val(d,"wireless.vap"+wlan_id+"0.vhtsubfer",0)).prop("checked",true);
			$("#vhtmubfer"+get_json_val(d,"wireless.vap"+wlan_id+"0.vhtmubfer",0)).prop("checked",true);
			if(wlan_id == "0"){
				if(get_json_val(d,"wireless.wifi"+wlan_id+".dfs","disable") == "enable"){
					$("#dfs_flag1").prop("checked",true);
				}else{
					$("#dfs_flag0").prop("checked",true);
				}
			}
			
			$("#min_rssi0").val(Math.abs(get_json_val(d,"wireless.vap"+wlan_id+"0.min_rssi",0)));
			$("#min_rssi1").val(Math.abs(get_json_val(d,"wireless.vap"+wlan_id+"1.min_rssi",75)));
			$("#min_rssi2").val(Math.abs(get_json_val(d,"wireless.vap"+wlan_id+"2.min_rssi",0)));
			$("#txpower").val(get_json_val(d,"wireless.wifi"+wlan_id+".txpower",20));
			$("#handover_rssi_thrshld").val(Math.abs(get_json_val(d,"wireless.vap04.handover_rssi_thrshld")));
			$("#handover_allow_rssi").val(Math.abs(get_json_val(d,"wireless.vap04.handover_allow_rssi")));
			$("#handover_check_intv_sec").val(Math.abs(get_json_val(d,"wireless.vap04.handover_check_intv_sec")));
			$("#handover_pps_trshld").val(Math.abs(get_json_val(d,"wireless.vap04.handover_pps_trshld")));
		},complete:function(){
			
		}
	});
}
var set_wl_config = function(){
	dummyVal = CreateDummy();
	var frag_ = $("#frag").val();
	var rts_ = $("#rts").val();
	var beacon_ = $("#beacon").val();
	var inact_ = $("#inact").val();
	var shpreamble_ = $("[name='shpreamble']:checked").val();
	var iapp_enable_ = $("[name='iapp_enable']:checked").val();
	var protmode_ = $("[name='protmode']:checked").val();
	var ampdu_ = $("[name='ampdu']:checked").val();
	var shortgi_ = $("[name='shortgi']:checked").val();
	var isolate_ = $("[name='isolate']:checked").val();
	var tx_stbc_ = $("[name='tx_stbc']:checked").val();
	var ldpc_ = $("[name='ldpc']:checked").val();
	var disablecoext_ = $("[name='disablecoext']:checked").val();
	var vhtsubfer_ = $("[name='vhtsubfer']:checked").val();
	var vhtmubfer_ = $("[name='vhtmubfer']:checked").val();
	var dfs_ = $("[name='dfs_flag']:checked").val();
	var mcastenhance_ = $("[name='mcastenhance']:checked").val();
	var mcast_rate_ = $("#mcast_rate").children(":selected").val();
	var min_rssi0_ = $("#min_rssi0").val();
	var min_rssi1_ = $("#min_rssi1").val();
	var min_rssi2_ = $("#min_rssi2").val();
	var txpower_ = $("#txpower").val();
	var handover_rssi_thrshld = $("#handover_rssi_thrshld").val();
	var handover_allow_rssi = $("#handover_allow_rssi").val();
	var handover_check_intv_sec = $("#handover_check_intv_sec").val();
	var handover_pps_trshld = $("#handover_pps_trshld").val();
	var sobj = new Object();
	if(isNumVal(frag_) == false){
		alert('Invalid value of Fragment Threshold. Input value should be between 256-2346 in decimal.');
		$("#frag").focus();
		return;
	}
	if(check_min_max(frag_,256,2346) == false){
		alert('Invalid value of Fragment Threshold. Input value should be between 256-2346 in decimal.');
		$("#frag").focus();
		return;
	}
	if(isNumVal(rts_) == false){
		alert('Invalid value of RTS Threshold. Input value should be between 0-2347 in decimal.');
		$("#rts").focus();
		return;
	}
	if(check_min_max(rts_,0,2347) == false){
		alert('Invalid value of RTS Threshold. Input value should be between 0-2347 in decimal.');
		$("#rts").focus();
		return;
	}
	if(isNumVal(beacon_) == false){
		alert("Invalid value of Beacon Interval. Input value should be between 20-1024 in decimal.");
		$("#beacon").focus();
		return;
	}
	if(check_min_max(beacon_,20,1024) == false){
		alert("Invalid value of Beacon Interval. Input value should be between 20-1024 in decimal.");
		$("#beacon").focus();
		return;
	}
	if(isNumVal(inact_) == false){
		alert("Invalid value of Idle Timeout. Input value should be between 5-65535 in decimal.");
		$("#inact").focus();
		return;
	}
	if(check_min_max(inact_,5,65535) == false){
		alert("Invalid value of Idle Timeout. Input value should be between 5-65535 in decimal.");
		$("#inact").focus();
		return;
	}
	
	if(isNumVal(min_rssi0_) == false){
		alert("RSSI Threshold의 값이 올바르지 않습니다. 0(제한없음) 아니면 20에서 80 사이의 숫자를 입력해야 합니다.");
		$("#min_rssi0").focus();
		return;
	}
	if(check_min_max(min_rssi0_,20,80) == false && min_rssi0_ != 0){
		alert("RSSI Threshold의 값이 올바르지 않습니다. 0(제한없음) 아니면 20에서 80 사이의 숫자를 입력해야 합니다.");
		$("#min_rssi0").focus();
		return;
	}
	if(isNumVal(min_rssi1_) == false){
		alert("RSSI Threshold의 값이 올바르지 않습니다. 0(제한없음) 아니면 20에서 80 사이의 숫자를 입력해야 합니다.");
		$("#min_rssi1").focus();
		return;
	}
	if(check_min_max(min_rssi1_,20,80) == false && min_rssi1_ != 0){
		alert("RSSI Threshold의 값이 올바르지 않습니다. 0(제한없음) 아니면 20에서 80 사이의 숫자를 입력해야 합니다.");
		$("#min_rssi1").focus();
		return;
	}
	if(isNumVal(min_rssi2_) == false){
		alert("RSSI Threshold의 값이 올바르지 않습니다. 0(제한없음) 아니면 20에서 80 사이의 숫자를 입력해야 합니다.");
		$("#min_rssi2").focus();
		return;
	}
	if(check_min_max(min_rssi2_,20,80) == false && min_rssi2_ != 0){
		alert("RSSI Threshold의 값이 올바르지 않습니다. 0(제한없음) 아니면 20에서 80 사이의 숫자를 입력해야 합니다.");
		$("#min_rssi2").focus();
		return;
	}
	if(wlan_idx == "1"){
		if(handover_rssi_thrshld == ""){
			alert("HandOver RSSI 접속제한의 값이 올바르지 않습니다. 0에서 100 사이의 숫자를 입력해야 합니다.");
			$("#handover_rssi_thrshld").focus();
			return;
		}
		if(isNumVal(handover_rssi_thrshld) == false){
			alert("HandOver RSSI 접속제한의 값이 올바르지 않습니다. 0에서 100 사이의 숫자를 입력해야 합니다.");
			$("#handover_rssi_thrshld").focus();
			return;
		}
		if(check_min_max(handover_rssi_thrshld,0,100) == false){
			alert("HandOver RSSI 접속제한의 값이 올바르지 않습니다. 0에서 100 사이의 숫자를 입력해야 합니다.");
			$("#handover_rssi_thrshld").focus();
			return;
		}
		if(handover_allow_rssi == ""){
			alert("HandOver 중 5G RSSI 접속제한 값이 올바르지 않습니다. 0에서 100 사이의 숫자를 입력해야 합니다.");
			$("#handover_allow_rssi").focus();
			return;
		}
		if(isNumVal(handover_allow_rssi) == false){
			alert("HandOver 중 5G RSSI 접속제한 값이 올바르지 않습니다. 0에서 100 사이의 숫자를 입력해야 합니다.");
			$("#handover_allow_rssi").focus();
			return;
		}
		if(check_min_max(handover_allow_rssi,0,100) == false){
			alert("HandOver 중 5G RSSI 접속제한 값이 올바르지 않습니다. 0에서 100 사이의 숫자를 입력해야 합니다.");
			$("#handover_allow_rssi").focus();
			return;
		}
		if(handover_check_intv_sec == ""){
			alert("HandOver 패킷 감시 시간(초) 값이 올바르지 않습니다. 0에서 100 사이의 숫자를 입력해야 합니다.");
			$("#handover_check_intv_sec").focus();
			return;
		}
		if(isNumVal(handover_check_intv_sec) == false){
			alert("HandOver 패킷 감시 시간(초) 값이 올바르지 않습니다. 0에서 100 사이의 숫자를 입력해야 합니다.");
			$("#handover_check_intv_sec").focus();
			return;
		}
		if(check_min_max(handover_check_intv_sec,0,100) == false){
			alert("HandOver 패킷 감시 시간(초) 값이 올바르지 않습니다.. 0에서 100 사이의 숫자를 입력해야 합니다.");
			$("#handover_check_intv_sec").focus();
			return;
		}
		if(handover_pps_trshld == ""){
			alert("HandOver 초당 발생 패킷 수 값이 올바르지 않습니다. 1에서 100 사이의 숫자를 입력해야 합니다.");
			$("#handover_pps_trshld").focus();
			return;
		}
		if(isNumVal(handover_pps_trshld) == false){
			alert("HandOver 초당 발생 패킷 수 값이 올바르지 않습니다. 1에서 100 사이의 숫자를 입력해야 합니다.");
			$("#handover_pps_trshld").focus();
			return;
		}
		if(check_min_max(handover_pps_trshld,1,100) == false){
			alert("HandOver 초당 발생 패킷 수 값이 올바르지 않습니다. 1에서 100 사이의 숫자를 입력해야 합니다.");
			$("#handover_pps_trshld").focus();
			return;
		}
		
	}

//	if(isNumVal(txpower_) == false){
//		alert("RF Output Power의 값이 올바르지 않습니다. 10에서 23 사이의 숫자를 입력해야 합니다.");
//		$("#txpower").focus();
//		return;
//	}
//	if(check_min_max(txpower_,10,23) == false){
//		alert("RF Output Power의 값이 올바르지 않습니다. 10에서 23 사이의 숫자를 입력해야 합니다.");
//		$("#txpower").focus();
//		return;
//	}
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'set_wl_config';
	sobj['radio'] = wlan_idx;
	sobj['frag'] = frag_;
	sobj['rts'] = rts_;
	sobj['beacon'] = beacon_;
	sobj['inact'] = inact_;
	sobj['shpreamble'] = shpreamble_;
	sobj['iapp_enable'] = iapp_enable_;
	sobj['protmode'] = protmode_;
	sobj['ampdu'] = ampdu_;
	sobj['shortgi'] = shortgi_;
	sobj['isolate'] = isolate_;
	sobj['tx_stbc'] = tx_stbc_;
	sobj['ldpc'] = ldpc_;
	sobj['disablecoext'] = disablecoext_;
	sobj['vhtsubfer'] = vhtsubfer_;
	sobj['vhtmubfer'] = vhtmubfer_;
	sobj['dfs'] = dfs_;
	sobj['mcastenhance'] = mcastenhance_;
	sobj['mcast_rate'] = mcast_rate_;
	sobj['min_rssi0'] = min_rssi0_;
	sobj['min_rssi1'] = min_rssi1_;
	sobj['min_rssi2'] = min_rssi2_;
	sobj['txpower'] = txpower_;
	sobj['handover_rssi_thrshld'] = handover_rssi_thrshld;
	sobj['handover_allow_rssi'] = handover_allow_rssi;
	sobj['handover_check_intv_sec'] = handover_check_intv_sec;
	sobj['handover_pps_trshld'] = handover_pps_trshld;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				document.formRestart.submit();
			}
		}
	});
}
$(document).ready(function(){
	$("#radio").val(wlan_idx);
	create_data_rate();
	get_wl_config();
//	wlan_adv_switch();
});
</script>
<blockquote>
<body onload="">
<h2>
<?php
	if(dv_session("wlan_id") == "1"){
		echo("무선 고급 설정 5G");
	}elseif(dv_session("wlan_id") == "0"){
		echo("무선 고급 설정 2.4G");
	}else{
		echo("Wireless Advanced Settings");
	}
?>
</h2>

<form action="proc/skb_wladvanced_proc.php" method="POST" name="advanceSetup">
<table border="0" width="500" cellspacing="4" cellpadding="0">
	<tr>
		<td><font size="2">무선 인터넷을 좀 더 전문적으로 사용하기 위한 설정으로, 충분한 지식을 가진 고급 유저를 위한 페이지 입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>
<table border="0" width="500" cellspacing="4" cellpadding="0">
	<tr>
  		<td width="35%"><font size="2"><b>무선:</b></font></td>
    	<td width="65%"><select name="radio" id="radio" onchange="page_change(this)">
			<option value="0">2.4 GHz</option>
			<option value="1">5 GHz</option>
		</select>
    	</td>
   </tr>
    <tr>
      <td><font size="2"><b>Fragment Threshold:</b></font></td>
      <td><font size="2"><input type="text" name="frag" id="frag" size="10" maxlength="4" value="">(256-2346)</font></td>
    </tr>
    <tr>
      <td><font size="2"><b>RTS Threshold:</b></font></td>
      <td><font size="2"><input type="text" name="rts" id="rts" size="10" maxlength="4" value="">(0-2347)</font></td>
    </tr>
    <tr>
      <td><font size="2"><b>Beacon Interval:</b></font></td>
      <td><font size="2"><input type="text" name="beacon" id="beacon" size="10" maxlength="4" value=""> (20-1024 ms)</font></td>
    </tr>
	<tr>
      <td><font size="2"><b>Idle Timeout:</b></font></td>
      <td><font size="2"><input type="text" name="inact" id="inact" size="10" maxlength="5" value=""> (5-65535 sec)</font></td>
    </tr>
    <tr id="preambleType" style="display:">
      <td><font size="2"><b>Preamble Type:</b></font></td>
      <td><font size="2">
      <input type="radio" name="shpreamble" id="shpreamble0" value="0">Long Preamble&nbsp;&nbsp;
      <input type="radio" name="shpreamble" id="shpreamble1" value="1">Short Preamble</font></td>
    </tr>

    <tr id="showIAPP" style="display:">
      <td><font size="2"><b>IAPP:</b></font></td>
      <td><font size="2">
      <input type="radio" name="iapp_enable" id="iapp_enable1" value="1">Enabled&nbsp;&nbsp;
      <input type="radio" name="iapp_enable" id="iapp_enable0" value="0">Disabled</font></td>
    </tr>
    <tr>
      <td><font size="2"><b>Protection:</b></font></td>
      <td><font size="2">
      <input type="radio" name="protmode" id="protmode1" value="1">Enabled&nbsp;&nbsp;
      <input type="radio" name="protmode" id="protmode0" value="0">Disabled</font></td>
    </tr>


   <tr id="Aggregation" style="display:">
      <td><font size="2"><b>Aggregation:</b></font></td>
      <td><font size="2">
      <input type="radio" name="ampdu" id="ampdu64" value="64">Enabled&nbsp;&nbsp;
      <input type="radio" name="ampdu" id="ampdu0" value="0">Disabled</font></td>
   </tr>

    <tr id="ShortGi" style="display:">
      <td><font size="2"><b>Short GI:</b></font></td>
      <td><font size="2">
      <input type="radio" name="shortgi" id="shortgi1" value="1">Enabled&nbsp;&nbsp;
      <input type="radio" name="shortgi" id="shortgi0" value="0">Disabled</font></td>
    </tr>
    <tr id="blockrelay" style="display:">
      <td><font size="2"><b>WLAN Partition:</b></font></td>
      <td><font size="2">
      <input type="radio" name="isolate" id="isolate1" value="1">Enabled&nbsp;&nbsp;
      <input type="radio" name="isolate" id="isolate0" value="0">Disabled</font></td>
    </tr>

     <tr id="stbctransmit" style="display:">
      <td><font size="2"><b>STBC:</b></font></td>
      <td><font size="2">
      <input type="radio" name="tx_stbc" id="tx_stbc1" value="1">Enabled&nbsp;&nbsp;
      <input type="radio" name="tx_stbc" id="tx_stbc0" value="0">Disabled</font></td>
    </tr>

	<tr id="ldpctransmit" style="display:">
      <td><font size="2"><b>LDPC:</b></font></td>
      <td><font size="2">
      <input type="radio" name="ldpc" id="ldpc3" value="3">Enabled&nbsp;&nbsp;
      <input type="radio" name="ldpc" id="ldpc0" value="0">Disabled</font></td>
    </tr>

     <tr id="coexist" style="display:">
      <td><font size="2"><b>20/40MHz Coexist:</b></font></td>
      <td><font size="2">
      <input type="radio" name="disablecoext" id="disablecoext0" value="0">Enabled&nbsp;&nbsp;
      <input type="radio" name="disablecoext" id="disablecoext1" value="1">Disabled</font></td>
    </tr>
    <tr id="tx_beamforming" style="display:">
      <td><font size="2"><b>Single-user TX Beamforming:</b></font></td>
      <td><font size="2">
      <input type="radio" name="vhtsubfer" id="vhtsubfer1" value="1">Enabled&nbsp;&nbsp;
      <input type="radio" name="vhtsubfer" id="vhtsubfer0" value="0">Disabled</font></td>
    </tr>
	<tr id="tx_beamforming" style="display:">
      <td><font size="2"><b>Multi-user TX Beamforming:</b></font></td>
      <td><font size="2">
      <input type="radio" name="vhtmubfer" id="vhtmubfer1" value="1">Enabled&nbsp;&nbsp;
      <input type="radio" name="vhtmubfer" id="vhtmubfer0" value="0">Disabled</font></td>
    </tr>
<?php
	if($wlan_id == "1"){
?>
	<tr>
		<td><font size="2"><b>DFS ENABLE:</b></font></td>
		<td><font size="2"><input type="radio" name="dfs_flag" id="dfs_flag1" value="enable">Enabled&nbsp;&nbsp;<input type="radio" name="dfs_flag" id="dfs_flag0" value="disable">Disabled</font></td>
	</tr>
<?php
	}
?>
    <tr id="mc2u_disable" style="display:">
      <td><font size="2"><b>Multicast to Unicast:</b></font></td>
      <td><font size="2">
      <input type="radio" name="mcastenhance" id="mcastenhance2" value="2" onclick="onclick_mc2u()" >Enabled&nbsp;&nbsp;
      <input type="radio" name="mcastenhance" id="mcastenhance0" value="0" onclick="onclick_mc2u()" >Disabled</font></td>
    </tr>
	<tr id="mlcsttxrate" style="display:">
		<td width="26%"><font size="2"><b>Multicast Rate:</b></font></td>
		<td width="74%"><font size="2"><select size="1" name="mcast_rate" id="mcast_rate"></select></font>
	</td>
  </tr>

	<tr id="rssi_threshold" style="display:">
		<td><font size="2" color="blue"><b>[ RSSI 접속 제한 ]</b></font></td>
		<td></td>
	</tr>
		<tr id="rssi_threshold0" style="display:">
		<td><font size="2"><b>AP-0:<br><font size="1">(Main)</font></b></font></td>
		<td><font size="2"><input type="text" name="min_rssi0" id="min_rssi0" size="5" maxlength="2" value=""> (0:제한없음, 20-80)</font></td>
	</tr>
	<tr id="rssi_threshold1" style="display:">
		<td><font size="2"><b>AP-1:<br><font size="1">(T wifi home)</font></b></font></td>
		<td><font size="2"><input type="text" name="min_rssi1" id="min_rssi1" size="5" maxlength="2" value=""> (20-80)</font></td>
	</tr>
	<tr id="rssi_threshold2" style="display:">
		<td><font size="2"><b>AP-2:<br><font size="1">(anyway)</font></b></font></td>
		<td><font size="2"><input type="text" name="min_rssi2" id="min_rssi2" size="5" maxlength="2" value=""> (0:제한없음, 20-80)</font></td>
	</tr>
<?php
	if($wlan_id == "1"){
?>
	<tr id="handover_rssi_th" style="display:">
      <td><font size="2"><b>HandOver RSSI 접속제한:</b></font></td>
      <td><font size="2"><input type="text" name="handover_rssi_thrshld" id="handover_rssi_thrshld" size="5" maxlength="3" value="">  (0:사용안함, 1-100)</td>
    </tr>
    <tr id="handover_rssi_th" style="display:">
      <td><font size="2"><b>HandOver 중 5G RSSI 접속제한:</b></font></td>
      <td><font size="2"><input type="text" name="handover_allow_rssi" id="handover_allow_rssi" size="5" maxlength="3" value="">  (0-100)</td>
    </tr>
    <tr id="handover_pps_checking_time" style="display:">
      <td><font size="2"><b>HandOver 패킷 감시 시간(초):</b></font></td>
      <td><font size="2"><input type="text" name="handover_check_intv_sec" id="handover_check_intv_sec" size="5" maxlength="3" value="">  (0-100)</td>
    </tr>
    <tr id="handover_pkts_threshold" style="display:">
      <td><font size="2"><b>HandOver 초당 발생 패킷 수:</b></font></td>
      <td><font size="2"><input type="text" name="handover_pps_trshld" id="handover_pps_trshld" size="5" maxlength="3" value="">  (1-100)</td>
    </tr>
<?php
	}
?>

	<!--tr id="rssi_threshold3" style="display:">
		<td><font size="2"><b>AP-3:<br><font size="1">(SK_WLAN_VAP3)</font></b></font></td>
		<td><font size="2"><input type="text" name="rssiThresh4" size="5" maxlength="2" value=0> (0:제한없음, 20-80)</font></td>
	</tr-->

	<tr>
		<td><font size="2"><b>RF Output Power:</b></font></td>
		<td><font size="2"><select name="txpower" id="txpower">
			<option value="23">100%</option>
			<option value="20">75%</option>
			<option value="17">50%</option>
			<option value="14">35%</option>
			<option value="11">15%</option>
		</select></font></td>
	</tr>
	  </table>
	  <p>
  <input type="button" value=" 적용 " name="save" onclick="set_wl_config();">&nbsp;&nbsp;
  <input type="reset" value=" 취소 " name="reset" onclick="resetForm();">&nbsp;&nbsp;&nbsp;
  <input type="hidden" value="/skb_wladvanced.php" name="submit-url">
  </p>
</form>
<form name="formRestart" id="formRestart" action="proc/skb_restart.php" method="POST">
<input type="hidden" name="act" id="act" value="network_restart">
<input type="hidden" name="submit-url" id="submit-url" value="/skb_wladvanced.php">
</form>
</blockquote>
</body>

</html>

