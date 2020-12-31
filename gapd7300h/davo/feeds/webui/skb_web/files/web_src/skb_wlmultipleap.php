<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$uci = new uci();
	$uci->mode("get");
	$wlan_id = dv_session("wlan_id");
	if(DEF_MODEL != "QCA_REF" && DEF_ANT == "4x4"){
		if($wlan_id == "0"){
			//2.4GHz
			$uci->get("wireless.wifi1");
			$uci->get("wireless.vap11");
			$uci->get("wireless.vap12");
			
		}else{
			//5GHz
			$uci->get("wireless.wifi0");
			$uci->get("wireless.vap01");
			$uci->get("wireless.vap02");
		}
		$uci->run();
		$wifi = json_decode($uci->result(),true);
		$wlan_disable = Array();
		$band = Array();
		$band_width = Array();
		$sideband = Array();

		$wlan_max_conn = Array();
		
		$ssid = Array();
		$ssid_hidden = Array();
		$tx_limit = Array();
		$rx_limit = Array();
		$wmm = Array();
		$rate = Array();
		if($wlan_id == "0"){
			//2.4GHz
			if(get_array_val($wifi,"wireless.vap11.disabled") != "1"){
				$wlan_disable[1] = "checked";
			}
			if(get_array_val($wifi,"wireless.vap12.disabled") != "1"){
				$wlan_disable[2] = "checked";
			}
			if(get_array_val($wifi,"wireless.wifi1.hwmode") == ""){
				$band[1] = "auto";
				$band[2] = "auto";
			}else{
				$band[1] = get_array_val($wifi,"wireless.wifi1.hwmode");
				$band[2] = get_array_val($wifi,"wireless.wifi1.hwmode");
			}
			if(get_array_val($wifi,"wireless.wifi1.htmode") == ""){
				$bandwidth[1] = "HT40";
				$bandwidth[2] = "HT40";
				$sidband[1] = "+";
				$sidband[2] = "+";
			}else{
				$band_width[1] = preg_replace ("/[\+\-]/","",get_array_val($wifi,"wireless.wifi1.htmode"));
				$band_width[2] = preg_replace ("/[\+\-]/","",get_array_val($wifi,"wireless.wifi1.htmode"));
				if(strlen($bandwidth) != strlen(get_array_val($wifi,"wireless.wifi1.htmode"))){
					$sideband[1] = preg_replace ("/[^\+\-]/","",get_array_val($wifi,"wireless.wifi1.htmode"));
					$sideband[2] = preg_replace ("/[^\+\-]/","",get_array_val($wifi,"wireless.wifi1.htmode"));
				}else{
					$sidband[1] = "+";
					$sidband[2] = "+";
				}
			}
			if(get_array_val($wifi,"wireless.vap11.hidden") == "1"){
				$ssid_hidden[1] = "1";
			}else{
				$ssid_hidden[1] = "0";
			}
			if(get_array_val($wifi,"wireless.vap12.hidden") == "1"){
				$ssid_hidden[2] = "1";
			}else{
				$ssid_hidden[2] = "0";
			}
			$ssid[1] = get_array_val($wifi,"wireless.vap11.ssid");
			$ssid[2] = get_array_val($wifi,"wireless.vap12.ssid");
			if(get_array_val($wifi,"wireless.vap11.maxsta") == ""){
				$wlan_max_conn[1] = 127;
			}else{
				$wlan_max_conn[1] = get_array_val($wifi,"wireless.vap11.maxsta");
			}
			if(get_array_val($wifi,"wireless.vap12.maxsta") == ""){
				$wlan_max_conn[2] = 127;
			}else{
				$wlan_max_conn[2] = get_array_val($wifi,"wireless.vap12.maxsta");
			}
			if(get_array_val($wifi,"wireless.vap11.tx_limit") == ""){
				$tx_limit[1] = 0;
			}else{
				$tx_limit[1] = get_array_val($wifi,"wireless.vap11.tx_limit");
			}
			if(get_array_val($wifi,"wireless.vap12.tx_limit") == ""){
				$tx_limit[2] = 0;
			}else{
				$tx_limit[2] = get_array_val($wifi,"wireless.vap12.tx_limit");
			}
			if(get_array_val($wifi,"wireless.vap11.rx_limit") == ""){
				$rx_limit[1] = 0;
			}else{
				$rx_limit[1] = get_array_val($wifi,"wireless.vap11.rx_limit");
			}
			if(get_array_val($wifi,"wireless.vap12.rx_limit") == ""){
				$rx_limit[2] = 0;
			}else{
				$rx_limit[2] = get_array_val($wifi,"wireless.vap12.rx_limit");
			}
			if(get_array_val($wifi,"wireless.vap11.wmm") == ""){
				$wmm[1] = "1";
			}else{
				$wmm[1] = get_array_val($wifi,"wireless.vap11.wmm");
			}
			if(get_array_val($wifi,"wireless.vap12.wmm") == ""){
				$wmm[2] = "1";
			}else{
				$wmm[2] = get_array_val($wifi,"wireless.vap12.wmm");
			}
			$rate[1] = "auto";
			if(get_array_val($wifi,"wireless.vap11.nss") != ""){
				$rate[1] = "NSS".get_array_val($wifi,"wireless.vap11.nss")."-MCS".get_array_val($wifi,"wireless.vap11.vhtmcs");
			}elseif(get_array_val($wifi,"wireless.vap11.set11NRates") != ""){
				$ori = hexdec(substr(get_array_val($wifi,"wireless.vap11.set11NRates"),2,2)) - hexdec("80");
				$rate[1] = "MCS".$ori;
			}else{
				if(get_array_val($wifi,"wireless.vap11.setLegacyRates") != ""){
					$rate[1] = get_array_val($wifi,"wireless.vap11.setLegacyRates");
				}
			}
			$rate[2] = "auto";
			if(get_array_val($wifi,"wireless.vap12.nss") != ""){
				$rate[2] = "NSS".get_array_val($wifi,"wireless.vap12.nss")."-MCS".get_array_val($wifi,"wireless.vap12.vhtmcs");
			}elseif(get_array_val($wifi,"wireless.vap12.set11NRates") != ""){
				$ori = hexdec(substr(get_array_val($wifi,"wireless.vap12.set11NRates"),2,2)) - hexdec("80");
				$rate[2] = "MCS".$ori;
			}else{
				if(get_array_val($wifi,"wireless.vap12.setLegacyRates") != ""){
					$rate[2] = get_array_val($wifi,"wireless.vap12.setLegacyRates");
				}
			}
		}else{
			//5GHz
			if(get_array_val($wifi,"wireless.vap01.disabled") != "1"){
				$wlan_disable[1] = "checked";
			}
			if(get_array_val($wifi,"wireless.vap02.disabled") != "1"){
				$wlan_disable[2] = "checked";
			}

			if(get_array_val($wifi,"wireless.wifi0.hwmode") == ""){
				$band[1] = "11ac";
				$band[2] = "11ac";
			}else{
				$band[1] = get_array_val($wifi,"wireless.wifi0.hwmode");
				$band[2] = get_array_val($wifi,"wireless.wifi0.hwmode");
			}
			if(get_array_val($wifi,"wireless.wifi1.htmode") == ""){
				$bandwidth[1] = "HT40";
				$bandwidth[2] = "HT40";
				$sidband[1] = "+";
				$sidband[2] = "+";
			}else{
				$band_width[1] = preg_replace ("/[\+\-]/","",get_array_val($wifi,"wireless.wifi0.htmode"));
				$band_width[2] = preg_replace ("/[\+\-]/","",get_array_val($wifi,"wireless.wifi0.htmode"));
				if(strlen($bandwidth) != strlen(get_array_val($wifi,"wireless.wifi0.htmode"))){
					$sideband[1] = preg_replace ("/[^\+\-]/","",get_array_val($wifi,"wireless.wifi0.htmode"));
					$sideband[2] = preg_replace ("/[^\+\-]/","",get_array_val($wifi,"wireless.wifi0.htmode"));
				}else{
					$sidband[1] = "+";
					$sidband[2] = "+";
				}
			}
			if(get_array_val($wifi,"wireless.vap01.hidden") == "1"){
				$ssid_hidden[1] = "1";
			}else{
				$ssid_hidden[1] = "0";
			}
			if(get_array_val($wifi,"wireless.vap02.hidden") == "1"){
				$ssid_hidden[2] = "1";
			}else{
				$ssid_hidden[2] = "0";
			}

			$ssid[1] = get_array_val($wifi,"wireless.vap01.ssid");
			$ssid[2] = get_array_val($wifi,"wireless.vap02.ssid");
			if(get_array_val($wifi,"wireless.vap01.maxsta") == ""){
				$wlan_max_conn[1] = 127;
			}else{
				$wlan_max_conn[1] = get_array_val($wifi,"wireless.vap01.maxsta");
			}
			if(get_array_val($wifi,"wireless.vap02.maxsta") == ""){
				$wlan_max_conn[2] = 127;
			}else{
				$wlan_max_conn[2] = get_array_val($wifi,"wireless.vap02.maxsta");
			}
			if(get_array_val($wifi,"wireless.vap01.tx_limit") == ""){
				$tx_limit[1] = 0;
			}else{
				$tx_limit[1] = get_array_val($wifi,"wireless.vap01.tx_limit");
			}
			if(get_array_val($wifi,"wireless.vap02.tx_limit") == ""){
				$tx_limit[2] = 0;
			}else{
				$tx_limit[2] = get_array_val($wifi,"wireless.vap02.tx_limit");
			}
			if(get_array_val($wifi,"wireless.vap01.rx_limit") == ""){
				$rx_limit[1] = 0;
			}else{
				$rx_limit[1] = get_array_val($wifi,"wireless.vap01.rx_limit");
			}
			if(get_array_val($wifi,"wireless.vap02.rx_limit") == ""){
				$rx_limit[2] = 0;
			}else{
				$rx_limit[2] = get_array_val($wifi,"wireless.vap02.rx_limit");
			}
			if(get_array_val($wifi,"wireless.vap01.wmm") == ""){
				$wmm[1] = "1";
			}else{
				$wmm[1] = get_array_val($wifi,"wireless.vap01.wmm");
			}
			if(get_array_val($wifi,"wireless.vap02.wmm") == ""){
				$wmm[2] = "1";
			}else{
				$wmm[2] = get_array_val($wifi,"wireless.vap02.wmm");
			}
			$rate[1] = "auto";
			if(get_array_val($wifi,"wireless.vap01.nss") != ""){
				$rate[1] = "NSS".get_array_val($wifi,"wireless.vap01.nss")."-MCS".get_array_val($wifi,"wireless.vap01.vhtmcs");
			}elseif(get_array_val($wifi,"wireless.vap01.set11NRates") != ""){
				$ori = hexdec(substr(get_array_val($wifi,"wireless.vap01.set11NRates"),2,2)) - hexdec("80");
				$rate[1] = "MCS".$ori;
			}else{
				if(get_array_val($wifi,"wireless.vap01.setLegacyRates") != ""){
					$rate[1] = get_array_val($wifi,"wireless.vap01.setLegacyRates");
				}
			}
			$rate[2] = "auto";
			if(get_array_val($wifi,"wireless.vap02.nss") != ""){
				$rate[2] = "NSS".get_array_val($wifi,"wireless.vap02.nss")."-MCS".get_array_val($wifi,"wireless.vap02.vhtmcs");
			}elseif(get_array_val($wifi,"wireless.vap02.set11NRates") != ""){
				$ori = hexdec(substr(get_array_val($wifi,"wireless.vap02.set11NRates"),2,2)) - hexdec("80");
				$rate[2] = "MCS".$ori;
			}else{
				if(get_array_val($wifi,"wireless.vap02.setLegacyRates") != ""){
					$rate[2] = get_array_val($wifi,"wireless.vap02.setLegacyRates");
				}
			}
		}
	}
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>Multiple AP</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/wifihelper.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<style>
.on {display:on}
.off {display:none}
</style>
<style type="text/css">
.MainTd {
	font-family: "Arial", "Helvetica", "sans-serif";
	font-size: 8pt;
	vertical-align: middle;
	background-position: center;
}
</style>
<script type="text/javascript">
var wlan_id = <?=$wlan_id?>;
function open_client_table(id)
{
	aclist_index = id;
	openWindow('/skb_wlstatbl.php?seq='+id+"#form", 'showWirelessClient', 820, 500);
}
var create_band = function(flag_){
	var flag = flag_ ? flag_ : "";
	var tobj = $("#band1,#band2");
	tobj.children().remove();
	if(wlan_id == "0"){
		for(var i=0; i < band_val["band24"].length; i++){
			tobj.append("<option value=\""+band["band24"][i].mode+"\">2.4 GHz ("+band_val["band24"][i].mode+")</option>");
		}
		if(flag == ""){
			$("#band1").val("<?=$band[1]?>");
			$("#band2").val("<?=$band[2]?>");
		}else{
			tobj.val("auto");
		}
	}else{
		for(var i=0; i < band_val["band5"].length; i++){
			tobj.append("<option value=\""+band["band5"][i].mode+"\">5 GHz ("+band_val["band5"][i].mode+")</option>");
		}
		if(flag == ""){
			$("#band1").val("<?=$band[1]?>");
			$("#band2").val("<?=$band[2]?>");
		}else{
			tobj.val("11ac");
		}
	}
}
var create_data_rate = function(seq_, flag_){
	var flag = flag_ ? flag_ : "";
	var seq = seq_ ? seq_ : 1;
	var tempVal = "";
	var tobj = $("#rate"+seq);
	var radio = wlan_id;
	var band = $("#band"+seq).children(":selected").val();
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
	switch(band){
		case "11b":
			rate = rate.concat(rate_b);
			$("#wmm"+seq).prop("disabled",false);
			break;
		case "11g":
			rate = rate.concat(rate_g);
			$("#wmm"+seq).prop("disabled",false);
			break;
		case "11bg":
			rate = rate.concat(rate_b);
			rate = rate.concat(rate_g);
			$("#wmm"+seq).prop("disabled",false);
			break;
		case "11ng":
			rate = rate.concat(rate_g);
			rate = rate.concat(rate_n);
			$("#wmm"+seq).val("1");
			$("#wmm"+seq).prop("disabled",true);
			break;
		case "11a":
			rate = rate.concat(rate_g);
			break;
		case "11na":
			rate = rate.concat(rate_g);
			rate = rate.concat(rate_n);
			$("#wmm"+seq).val("1");
			$("#wmm"+seq).prop("disabled",true);
			break;
		case "11ac":
			rate = rate.concat(rate_g);
			rate = rate.concat(rate_n);
			rate = rate.concat(rate_ac);
			$("#wmm"+seq).val("1");
			$("#wmm"+seq).prop("disabled",true);
			break;
		case "auto":
			if(radio == "0"){
				rate = rate.concat(rate_b);
				rate = rate.concat(rate_g);
				rate = rate.concat(rate_n);
			}else{
				rate = rate.concat(rate_g);
				rate = rate.concat(rate_n);
				rate = rate.concat(rate_ac);
			}
			$("#wmm"+seq).val("1");
			$("#wmm"+seq).prop("disabled",true);
			break;
	}
	tempVal += "<option value=\"auto\">Auto</option>";
	for (var i=0; i < rate.length ; i++ )
	{
		tempVal += "<option value=\""+rate[i]+"\">"+rate[i]+"</option>";
	}
	tobj.append(tempVal);
	if(flag != ""){
		tobj.val(flag);
	}
}
var click_reset = function(){
//	window.location.reload();
	location.href='wlan_redriect.php?redirect-url=skb_wlbasic.php&wlan_id='+wlan_id;
}
var form_save = function(){
	var ssid1 = $("#ssid1").val();
	var ssid2 = $("#ssid2").val();
	var ssid = $("#ssid").val();
	if($("#wlan_enable1").prop("checked") == true){
		if(ssid1 == ""){
			alert("SSID를 입력해주세요.");
			$("#ssid1").focus();
			return false;
		}
		if(!check_xss(ssid1)){
			alert(xss_err_msg);
			$("#ssid1").focus();
			return;
		}
		if($("#wlan_max_conn1").val() == ""){
			alert("동시접속 제한을 입력해주세요.");
			$("#wlan_max_conn1").focus();
			return false;
		}
		if(isNumVal($("#wlan_max_conn1").val()) == false){
			alert("동시접속은 1~250을 입력해주세요.");
			$("#wlan_max_conn1").focus();
			return false;
		}
		if(check_min_max($("#wlan_max_conn1").val(),1,250) == false){
			alert("동시접속은 1~250을 입력해주세요.");
			$("#wlan_max_conn1").focus();
			return false;
		}
	}
	if($("#wlan_enable2").prop("checked") == true){
		if(ssid2 == ""){
			alert("SSID를 입력해주세요.");
			$("#ssid2").focus();
			return false;
		}
		if(!check_xss(ssid2)){
			alert(xss_err_msg);
			$("#ssid2").focus();
			return;
		}
		if($("#wlan_max_conn2").val() == ""){
			alert("동시접속 제한을 입력해주세요.");
			$("#wlan_max_conn2").focus();
			return false;
		}
		if(isNumVal($("#wlan_max_conn2").val()) == false){
			alert("동시접속은 1~250을 입력해주세요.");
			$("#wlan_max_conn2").focus();
			return false;
		}
		if(check_min_max($("#wlan_max_conn2").val(),1,250) == false){
			alert("동시접속은 1~250을 입력해주세요.");
			$("#wlan_max_conn2").focus();
			return false;
		}
	}
}
var change_mode_change = function(x_){
	var x = x_ ? x_ : "1";
	var flag_ = true;
	if($("#wlan_enable"+x).prop("checked") == false){
		flag_ = true;
	}else{
		flag_ = false;
	}
	$("#band"+x).prop("disabled",flag_);
	$("#ssid"+x).prop("disabled",flag_);
	$("#hide_ssid"+x).prop("disabled",flag_);
	$("#wlan_max_conn"+x).prop("disabled",flag_);
	$("#aclient"+x).prop("disabled",flag_);
	$("#tx_limit"+x).prop("disabled",flag_);
	$("#rx_limit"+x).prop("disabled",flag_);
	$("#wmm"+x).prop("disabled",flag_);
	$("#rate"+x).prop("disabled",flag_);
}
var change_band = function(seq_, val_){
	var val = val_ ? val_ : "";
	create_data_rate(seq_,val);
}
$(document).ready(function(){
//	create_band();
	change_mode_change("1");
	change_mode_change("2");
//	change_band("1","<?=$rate[1]?>");
//	change_band("2","<?=$rate[2]?>");
});
</script>
</head>
<body>
<blockquote>
<h2>
<?php
	if(dv_session("wlan_id") == "1"){
		echo("Multiple APs 설정 5G");
	}elseif(dv_session("wlan_id") == "0"){
		echo("Multiple APs 설정 2.4G");
	}
?>
</h2>
<table border="0" width="800" cellspacing="0" cellpadding="0">
	<tr>
		<td><font size="2">Multiple AP 설정을 위한 페이지입니다.</td>
	</tr>
	<tr>
		<td><hr size=1 noshade align="top"></td>
	</tr>
</table>
<form action="proc/skb_wlmultipleap_proc.php" method="POST" name="MultipleAP">
<table border='1' width="800">
<tr class="tbl_head">
	<td align="center"><font size="2"><b>No.</b></font></td>
	<td align="center"><font size="2"><b>사용</b></font></td>
<!-- 	<td align="center"><font size="2"><b>Band</b></font></td> -->
	<td align="center"><font size="2"><b>SSID</b></font></td>
<!-- 	<td align="center"><font size="2"><b>전송률</b></font></td> -->
	<td align="center"><font size="2"><b>SSID 알림</b></font></td>
	<td align="center"><font size="2"><b>WMM</b></font></td>
	<!--td align="center"><font size="2"><b>Access</b></td-->
	<td align="center"><font size="2"><b>Tx 제한(Mbps)</b></font></td>
	<td align="center"><font size="2"><b>Rx 제한(Mbps)</b></font></td>
	<td align="center"><font size="2"><b>동시접속제한</b></font></td>
	<td align="center"><font size="2"><b>접속리스트</b></font></td>
	<!--td align="center"><font size="2"><b>WLAN mode</b></td-->
</tr>
<?php
	for($i=1; $i <= 2; $i++){
?>
<tr>
	<td height="25"  align="center" class="MainTd">AP<?=$i?></td>
	<td height="25" align="center" ><input type="checkbox" name="wlan_enable<?=$i?>" id="wlan_enable<?=$i?>" value="1" onchange="change_mode_change('<?=$i?>')" <?=$wlan_disable[$i]?>></td>
<!-- 	<td height="25" align="center"  class="MainTd"> -->
<!-- 		<select name="band<?=$i?>" id="band<?=$i?>" onchange="change_band('<?=$i?>');"></select> -->
<!-- 	</td> -->
	<td height="25" align="center"  class="MainTd">
		<input type="text" name="ssid<?=$i?>" id="ssid<?=$i?>" maxlength="32" value="<?=$ssid[$i]?>" style="width:95%;">
	</td>
<!-- 	<td height="25" align="center"  class="MainTd"> -->
<!-- 		<select name="rate<?=$i?>" id="rate<?=$i?>"> -->
<!-- 		</select> -->
<!-- 	</td> -->
	<td height="25" align="center"  class="MainTd">
		<select name="hide_ssid<?=$i?>" id="hide_ssid<?=$i?>">
			<option value="1" <?php if($ssid_hidden[$i] == "1"){ echo("selected"); } ?>>사용안함</option>
			<option value="0" <?php if($ssid_hidden[$i] == "0"){ echo("selected"); } ?>>사용</option>
		</select>
	</td>
	<td height="25" align="center"  class="MainTd">
		<select name="wmm<?=$i;?>" id="wmm<?=$i;?>">
			<option value="0" <?php if($wmm[$i] == "0"){ echo("selected");}?>>사용안함</option>
			<option value="1" <?php if($wmm[$i] == "1"){ echo("selected");}?>>사용</option>
		</select>
	</td>
	<!--td height="25" align="center"  class="MainTd">
		<select name=wl_access2>
			<option value="0">LAN+WAN</option>
			<option value="1">WAN</option>
			<script>
				if (virtual_access[2])
					document.MultipleAP.elements["wl_access2"].selectedIndex=1;
				else
					document.MultipleAP.elements["wl_access2"].selectedIndex=0;
			</script>
		</select>
	</td-->
	<td height="25" align="center"  class="MainTd">
		<input type="text" name="tx_limit<?=$i?>" id="tx_limit<?=$i?>" size="4" maxlength="4" value="<?=$tx_limit[$i]?>">
	</td>
	<td height="25" align="center"  class="MainTd">
		<input type="text" name="rx_limit<?=$i?>" id="rx_limit<?=$i?>" size="4" maxlength="4" value="<?=$rx_limit[$i]?>">
	</td>
	<td height="25" align="center"  class="MainTd">
		<input type="text" size="3" maxlength="3" value="<?=$wlan_max_conn[$i]?>" name="wlan_max_conn<?=$i?>"  id="wlan_max_conn<?=$i?>">
    </td>
	<td height="25" align="center"  class="MainTd">
		<input type="button" value="Show" name="aclient<?=$i?>" id="aclient<?=$i?>" onClick="open_client_table(<?=$i?>);">
    </td>
	<!--td height="25" align="center"  class="MainTd">
		<input type="text" name="vap2_wlan_mode" size="4" maxlength="3" value="AP">
	</td-->


</tr>
<?php
	}
?>
</table>
<p></p>
<input type="hidden" value="/skb_wlmultipleap.php" name="submit-url">
<br>
<input type="submit" value="적용" name="save" onClick="return form_save();">&nbsp;&nbsp;
<input type="button" value="취소" name="reset1" onClick="click_reset();">&nbsp;&nbsp;

  <!-- <input type="button" value=" Close " name="close" onClick="javascript: window.close();"> -->
</form>
</blockquote>
</body>

</html>
