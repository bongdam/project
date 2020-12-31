<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$uci = new uci();
	$uci->mode("get");
	$uci->get("firewall.dmz");
	$uci->run();
	$dmz = json_encode(json_decode($uci->result(),true));
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>DMZ 호스트</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script>
var mode = document.getElementsByName('dmzMode');
var dmz = <?=$dmz?>;
function macTblClick(url) {
	openWindow(url, 'macTbl', 600, 400);
}

function saveClick()
{
	if (mode[0].checked) {
		if (document.formDMZ.ip.value=="")
			return false;

		if ( checkIpAddr(document.formDMZ.ip, '유효하지 않은 IP 주소입니다.') == false )
			return false;
	} else if (mode[1].checked) {
		return true;
	} else {
		str = document.formDMZ.mac.value;
		var tmp = "";
		var org_mac = "";
		for (var i=0; i<str.length; i++) {
			if ((str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
					(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
					(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') || 
					(str.charAt(i) == ':')){

				org_mac += str.charAt(i);
				if(str.charAt(i) != ':')
					tmp += str.charAt(i);
				continue;   
			}
		}
		document.formDMZ.mac.value = tmp;
		if ( !checkMacAddr(document.formDMZ.mac, '유효하지 않은 MAC 주소입니다.') ) {
			return false;
		}
	} 
}

function updateState()
{
	if (mode[0].checked) {
		mode[0].checked = true;
		mode[1].checked = false;
		enableTextField(document.formDMZ.ip);
		document.formDMZ.ip.value = '';
		document.formDMZ.ip.style.backgroundColor = 'white';
	}
	else if (mode[1].checked) {
		mode[0].checked = false;
		mode[1].checked = true;
		disableTextField(document.formDMZ.ip);
		document.formDMZ.ip.style.backgroundColor = '#DCDCDC';
	}
	else {
		mode[0].checked = false;
		mode[1].checked = false;
		disableTextField(document.formDMZ.ip);
		document.formDMZ.ip.style.backgroundColor = '#DCDCDC';
	}
}

function resetForm()
{
	document.location.assign("skb_dmz.php");
}

function Load_Setting()
{
	if(dmz.length == 0){
		mode[1].checked = true;
		disableTextField(document.formDMZ.ip);
		document.formDMZ.ip.style.backgroundColor = '#DCDCDC';
	}else{
		mode[0].checked = true;
		enableTextField(document.formDMZ.ip);
		document.formDMZ.ip.style.backgroundColor = 'white';
		document.formDMZ.ip.value = dmz["firewall.dmz.dest_ip"];
	}
//	updateState();
}
</script>
</head>

<body onload="Load_Setting();">
<blockquote>
<h2>DMZ</h2>
<form action="proc/skb_dmz_proc.php" method="POST" name="formDMZ">
<!-- <input type="hidden" name="current_ip" value="192.168.35.1"> -->
<!-- <input type="hidden" name="subnet" value="255.255.255.0"> -->
<input type="hidden" name="page" value="skb_dmz.php">
<table border="0" width="500" cellspacing="4" cellpadding="0">
	<tr>
		<td><font size="2">DMZ를 설정할 수 있는 페이지 입니다. DMZ란 로컬 개인 네트워크로의 권한없는 접근을 제한하지 않는 것을 말합니다.</font></td>
	</tr>
	<tr>
		<td><hr size="2" noshade align="top"></td>
	</tr>
	<tr>
		<td><font size="2"><b><input type="radio" name="dmzMode" value="dmz" onclick="updateState()">&nbsp;&nbsp;DMZ
		<input type="radio" name="dmzMode" value="disable" onclick="updateState()">&nbsp;&nbsp;disable
		</b></td>
	</tr>
	<tr>
		<td><font size=2><b>DMZ 호스트 IP 주소 : </b><input type="text" name="ip" size="15" maxlength="15" value="" ></td>
	</tr>
	<tr>
		<td><br><input type="submit" value="적용" name="save" onclick="return saveClick()">&nbsp;&nbsp;
        <input type="reset" value="초기화" name="reset" onclick="resetForm()">
        <input type="hidden" value="/skb_dmz.php" name="submit-url">
		</td>
	</tr>
</table>
</form>
</blockquote>
</body>
</html>
