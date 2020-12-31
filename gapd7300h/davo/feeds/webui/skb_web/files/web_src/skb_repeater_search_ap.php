<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$wlan_id = dv_session("wlan_id");
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>무선 AP 검색</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<style type="text/css">
.on {
	display:on;
}
.off {
	display:none;
}
</style>
<script type="text/javascript">
var wlan_idx= <?=$wlan_id?>;
var proc = "proc/skb_ap_scan_proc.php";
function page_change(selectObj)
{
	if (selectObj.value==1)
		location.href='wlan_redriect.php?redirect-url=skb_repeater_search.php&wlan_id=1';
	else
		location.href='wlan_redriect.php?redirect-url=skb_repeater_search.php&wlan_id=0';
}
function check_ssid(ssid, methed)
{
	ap_ssid = ssid;
	security_method=trim(methed);
	wpa = trim(wpa_tkip_aes);
	wpa2 = trim(wpa2_tkip_aes);
	//WAP2-802.1x
	//WAP-802.1x/WAP2-802.1x	
	if (security_method != "WPA-PSK/WPA2-PSK" && security_method != "WPA2-PSK" &&
		security_method != "WPA-PSK" && security_method != "WEP" && security_method != "OPEN") {
		alert(security_method+" 암호화에서는  Repeater Mode를 설정할 수 없습니다.");
	}
}
function select_SSID(){

	if (ap_ssid=="" || security_method=="") {
		alert("선택된 SSID가 없습니다.");
		return;
	}
	if (security_method != "WPA-PSK/WPA2-PSK" && security_method != "WPA2-PSK" &&
		security_method != "WPA-PSK" && security_method != "WEP" && security_method != "OPEN") {
		alert(security_method+" 암호화에서는  Repeater Mode를 설정할 수 없습니다.");
		return;
	}

	if (window.opener.document.forms[0].page.value == "/skb_operate_mode.php" ) {
		$("#ssid",opener.document).val(ap_ssid);
		if(security_method == "WPA-PSK/WPA2-PSK"){
			$("#method",opener.document).val("wpa-mixed");
			$("#cipher0",opener.document).prop("checked",true);
			$("#cipher1",opener.document).prop("checked",true);
			$("#psk_type",opener.document).val("ascii");
			$("#psk_key",opener.document).val("");
			$("#psk_key_con",opener.document).val("");
		}else if(security_method == "WPA2-PSK"){
			$("#method",opener.document).val("wpa2");
			$("#cipher0",opener.document).prop("checked",true);
			$("#cipher1",opener.document).prop("checked",true);
			$("#psk_type",opener.document).val("ascii");
			$("#psk_key",opener.document).val("");
			$("#psk_key_con",opener.document).val("");
		}else if(security_method == "WPA-PSK"){
			$("#method",opener.document).val("wpa");
			$("#cipher0",opener.document).prop("checked",true);
			$("#cipher1",opener.document).prop("checked",true);
			$("#psk_type",opener.document).val("ascii");
			$("#psk_key",opener.document).val("");
			$("#psk_key_con",opener.document).val("");
		}else if(security_method == "WEP"){
			$("#method",opener.document).val("wep");
		}else if(security_method == "OPEN"){
			$("#method",opener.document).val("none");
		}
		window.opener.change_authentication();
		window.close();
		return;
//		var ssid_obj = window.opener.document.forms[0].repeater_ssid;
		var method_obj = window.opener.document.forms[0].method;
		var method_type = trim(security_method);
		ssid_obj.value = trim(ap_ssid);
		if (method_type == "WPA-PSK/WPA2-PSK") {
			method_obj.selectedIndex=0;
			window.opener.document.forms[0].pskValue.value="";
			window.opener.document.forms[0].check_pskValue.value="";
			if (wpa == "aes/tkip" || wpa == "aes") {
				window.opener.document.forms[0].ciphersuite[0].checked = false;
				window.opener.document.forms[0].ciphersuite[1].checked = true;
			} else if (wpa == "aes") {
				window.opener.document.forms[0].ciphersuite[0].checked = true;
				window.opener.document.forms[0].ciphersuite[1].checked = false;
			}
			if (wpa2 == "aes/tkip" || wpa2 == "aes") {
				window.opener.document.forms[0].wpa2ciphersuite[0].checked = false;
				window.opener.document.forms[0].wpa2ciphersuite[1].checked = true;
			} else if (wpa == "aes") {
				window.opener.document.forms[0].wpa2ciphersuite[0].checked = true;
				window.opener.document.forms[0].wpa2ciphersuite[1].checked = false;
			}

		} else if (method_type == "WPA2-PSK") {
			method_obj.selectedIndex=1;
			window.opener.document.forms[0].pskValue.value="";
			window.opener.document.forms[0].check_pskValue.value="";

			if (wpa2 == "aes/tkip" || wpa2 == "aes") {
				window.opener.document.forms[0].wpa2ciphersuite[0].checked = false;
				window.opener.document.forms[0].wpa2ciphersuite[1].checked = true;
			} else if (wpa == "aes") {
				window.opener.document.forms[0].wpa2ciphersuite[0].checked = true;
				window.opener.document.forms[0].wpa2ciphersuite[1].checked = false;
			}
		} else if (method_type == "WPA-PSK") {
			method_obj.selectedIndex=2;
			window.opener.document.forms[0].pskValue.value="";
			window.opener.document.forms[0].check_pskValue.value="";

			if (wpa == "aes/tkip" || wpa == "aes") {
				window.opener.document.forms[0].ciphersuite[0].checked = false;
				window.opener.document.forms[0].ciphersuite[1].checked = true;
			} else if (wpa == "aes") {
				window.opener.document.forms[0].ciphersuite[0].checked = true;
				window.opener.document.forms[0].ciphersuite[1].checked = false;
			}
		} else if (method_type == "WEP") {
			method_obj.selectedIndex=3;
			window.opener.document.forms[0].key1.value="";
			window.opener.document.forms[0].key2.value="";
			window.opener.document.forms[0].key3.value="";
			window.opener.document.forms[0].key4.value="";
			window.opener.document.forms[0].select_key.selectedIndex=0;
			window.opener.document.forms[0].wep_key.value="";
			window.opener.document.forms[0].check_wep_key.value="";
		} else if (method_type == "no") {
			method_obj.selectedIndex=4;
		} else {
			alert(method_type+" 암호화에서는  Repeater Mode를 설정할 수 없습니다.");
			return;
		}
		 window.opener.change_authentication();
	}
	window.close();
}
var run_ap_search = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'repeater_ap_scan';
	$("#tbdy").children().remove();
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			var tempVal = "";
			for (var i=0; i < d.length ;  i++)
			{
				tempVal += "<tr class=\"tbl_body\">\n";
				tempVal += "\t<td align=\"center\" width=\"20%\" ><font size=\"2\">"+d[i].ssid+"</td>\n"
				tempVal += "\t<td align=\"center\" width=\"20%\" ><font size=\"2\">"+d[i].mac+"</td>\n";
				tempVal += "\t<td align=\"center\" width=\"10%\" ><font size=\"2\">"+d[i].channel+"</td>\n";
				tempVal += "\t<td align=\"center\" width=\"20%\" ><font size=\"2\">"+d[i].ap_mode+"</td>\n";
				tempVal += "\t<td align=\"center\" width=\"10%\" ><font size=\"2\">"+d[i].security+"</td>\n";
				tempVal += "\t<td align=\"center\" width=\"10%\" ><font size=\"2\">"+d[i].rssi+"</td>\n";
				tempVal += "\t<td align=\"center\" width=\"10%\" ><input type='radio' name='checkSSID' value='"+d[i].ssid+"' enc=\""+d[i].security+"\" onclick=\"check_ssid('"+d[i].ssid+"','"+d[i].security+"');\"></td>\n";
				tempVal +="</tr>";
			}
			$("#tbdy").append(tempVal);
		},complete:function(){
			
		}
	});
}
$(document).ready(function(){
	
	run_ap_search();
});
</script>
</head>
<body>
<blockquote>
<h2>
<?php
	if(dv_session("wlan_id") == "1"){
		echo("AP 검색 5G ");
	}elseif(dv_session("wlan_id") == "0"){
		echo("AP 검색 2.4G");
	}else{
		echo("Wireless Site Survey");
	}
?>
</h2>
<table border="0" width="500" cellspacing="0" cellpadding="0">
	<tr>
		<td><font size="2">주변에 있는 AP들에 대한 정보를 보여주는 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>
<form action="" method="POST" name="wizardPocket">
<table border="0" width="800">
	<tr>
		<td align="right">
			<input type="button" value="선택" name="select_ap" onclick="select_SSID()">&nbsp;
			<!--input type="button" value="다시 보기" name="refresh" onclick="resetForm()">&nbsp;-->
			<input type="button" value=" 닫기 " name="close" onClick="javascript: window.close();"></p>
		</td>
	</tr>
</table>
<span id="top_div" class="on">
<div id="SSIDSiteSurvey">
<table border="0" width="800">
	<thead>
	<tr class="tbl_head">
		<td align="center" width="25%" ><font size="2"><b>SSID</b></font></td>
		<td align="center" width="20%" ><font size="2"><b>BSSID</b></font></td>
		<td align="center" width="10%" ><font size="2"><b>채널</b></font></td>
		<td align="center" width="20%" ><font size="2"><b>종류</b></font></td>
		<td align="center" width="10%" ><font size="2"><b>암호화</b></font></td>
		<td align="center" width="10%" ><font size="2"><b>RSSI<br>(dbm)</b></font></td>
		<td align="center" width="5%" ><font size="2"><b>선택</b></font></td>
	</tr>
	</thead>
	<tbody id="tbdy">
		<tr class="tbl_body">
			<td align="center" width="20%" ><font size="2">SK_WiFiGIGA1208</td>
			<td align="center" width="20%" ><font size="2">06:23:aa:ff:12:08</td>
			<td align="center" width="10%" ><font size="2">6 -75-</td>
			<td align="center" width="20%" ><font size="2">AP</td>
			<td align="center" width="10%" ><font size="2">WPA-PSK/WPA2-PSK</td>
			<td align="center" width="10%" ><font size="2">0</td>
			<td align="center" width="10%" ><input type='radio' name='checkSSID' value='SK_WiFiGIGA1208' onclick="check_ssid('SK_WiFiGIGA1208','WPA-PSK/WPA2-PSK','aes/tkip','aes/tkip');"></td>
		</tr>
	</tbody>
</table>
</div>
<br>
</span>


<input type="hidden" value="/skb_wlsurvey.php" name="submit-url">
</form>

</blockquote>
</body>
</html>
