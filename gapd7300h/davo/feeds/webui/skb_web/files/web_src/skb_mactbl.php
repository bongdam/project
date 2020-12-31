<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$param = null;
	$sock = new rcqm();
	$sock->connect();
	if($sock->con()){
	}else{
		return "0";
	}
	$sock->write("dhcp_list",$param);
	$dhcpinfo = $sock->read();
	$dhcpinfo = json_decode($dhcpinfo,true)["data"];
	$dhcpinfo = explode("\n",rtrim($dhcpinfo));
	$devicelist = Array();
	for($i=0; $i < count($dhcpinfo);$i++){
		//1482816279 00:05:1b:a2:c6:77 192.168.35.61 take99-PC 01:00:05:1b:a2:c6:77 
		if(preg_match("/^(\d+)\s+(\w+:\w+:\w+:\w+:\w+:\w+)\s+(\d+.\d+.\d+.\d+)\s+([\w+\-\*]{1,})\s+([\w:\*]{1,})\s+(\w+)/",$dhcpinfo[$i],$d) == true) {
			//ifname mac
//			print_r($d);
			$tmp = Array(
				"time"=> $d[1],
				"mac"=> $d[2],
				"ip"=>$d[3],
				"device_name"=>$d[4],
				"contype"=>$d[6]
			);
			$devicelist[] = $tmp;
		}
	}
	$nowtime = ceil(getTimestamp()/1000);
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>Active DHCP Client Table</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">

function macReload()
{
	console.log('aaa');
//	window.location.assign("skb_mactbl.php#form");
	window.location.reload();
}

function macInput(macSelectValue)
{
//	document.forms[0].macValue.value = macSelectValue;
	document.forms[0].macValue.value = $("[name=mac]:checked").val();
}

function macSelect()
{
	with ( document.forms[0] ) {
		if (macValue.value=="") {
			alert('MAC 주소가 없습니다!');
			return false;
		}

		str = document.forms[0].macValue.value;
		var tmp = "";

		if ( str.length != 12 && str.length != 17) {
			alert("MAC 주소가 올바르지 않습니다. 16진수 12개 또는 콜론(:)을 포함한 17개의 16진수를 입력하십시오. ");
			macValue.focus();
			return false;
		}

		for (var i=0; i<str.length; i++) {
			if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
				(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
				(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') ||
				(str.charAt(i) == ':')) {
				if(str.charAt(i) != ':')
					tmp += str.charAt(i);
				continue;
			}
			alert("MAC 주소가 올바르지 않습니다. 16진수를 입력하십시오. ( 0-9 또는 a-f 또는 : ) ");
			macValue.focus();
			return false;
		}
		if (window.opener.document.forms[0].page.value == "skb_tcpip_staticdhcp.php" ) {
			obj = window.opener.document.getElementsByName('mac_addr');
			obj[0].value = macValue.value;
		} else if (window.opener.document.forms[0].page.value == "skb_macfilter.php" ) {
			obj = window.opener.document.getElementsByName('mac');
			obj[0].value = macValue.value;
		} else if (window.opener.document.forms[0].page.value == "skb_dmz.php" ) {
			obj = window.opener.document.getElementsByName('mac');
			obj[0].value = macValue.value;
		} else if (window.opener.document.forms[0].page.value == "skb_tcpipwan.php" ) {
			obj = window.opener.document.getElementsByName('wan_macAddr');
			obj[0].value = macValue.value;
		}

	}
	window.close();
}

</script>
</head>

<body>
<blockquote>
<h2>MAC Address 테이블</h2>

<table border="0" width="480" cellspacing="0" cellpadding="0">
  <tr><font size="2">
  	접속된 단말의 IP와 MAC 주소 그리고 남은 시간을 보여주는 페이지입니다.
  </tr>
  <tr><hr size=1 noshade align=top></tr>
</table>


<form>
<table border='1' width="100%">
	<tr class="tbl_head" align="center">
		<td width="29%"><font size=2><b>IP 주소</b></td>
		<td width="34%"><font size=2><b>MAC 주소</b></td>
		<td width="27%"><font size=2><b>사용가능한 시간(s)</b></td>
		<td width="10%"><font size=2><b>선택</b></td>
	</tr>
<?php
	if(count($devicelist) > 0){
		for($i=0; $i < count($devicelist); $i++){
?>
	<tr class="tbl_body" align="center">
		<td><font size="2"><?=$devicelist[$i]["ip"]?></font></td>
		<td><font size="2"><?=$devicelist[$i]["mac"]?></font></td>
		<td><font size="2"><?=$devicelist[$i]["time"]-$nowtime?></font></td>
		<td><input type="radio" name="mac" id="mac<?$i?>" value="<?=$devicelist[$i]["mac"]?>" onchange="macInput();" ></td>
	</tr>
<?php
		}
	}else{
?>
	<tr class="tbl_body" align="center">
		<td><font size="2">None</font></td>
		<td><font size="2">----</font></td>
		<td><font size="2">----</font></td>
		<td>&nbsp;</td>
	</tr>
<?php
	}
?>
</table>

<table border='0' width="100%">
	<tr class="tbl_head" align="center">
		<td width="50%"><font size="2"><b>사용할 MAC 주소</b></font></td>
	</tr>
	<tr class="tbl_body" align="center">
		<td><font size="2"><input type='text' size="30" maxlength="17" name='macValue' value='' readonly></font></td>
	</tr>
	<tr bgcolor="#f0f0f0">
		<td align="center">
			<input type="hidden" value="/skb_mactbl.php" name="submit-url">
			<input type="button" value=" 선택 " name="select" onclick="macSelect()">&nbsp;&nbsp;
			<input type="button" value="다시 보기" name="refresh" onclick="macReload();">&nbsp;&nbsp;
			<input type="button" value=" 닫기 " name="close" onclick="javascript: window.close();">
		</td>
	</tr>
</table>
</form>
</blockquote>
</body>

</html>
