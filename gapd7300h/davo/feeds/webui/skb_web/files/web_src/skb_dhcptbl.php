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
	$dd = switch_port_status(" | grep lan1");
	for($i=0; $i < count($dd); $i++){
		if($dd[$i]["name"] == "lan1"){
			$lan_no = $dd[$i]["port"];
		}else{
			continue;
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
<title>Active DHCP Client Table</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<link href="/style.css" rel="stylesheet" type="text/css">
</head>

<body>
<blockquote>
<h2>접속 리스트</h2>

<table border=0 width="480" cellspacing=0 cellpadding=0>
	<tr>
		<td><font size="2">접속된 단말의 IP와 MAC 주소 그리고 남은 시간을 보여주는 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>
<form action="" method="POST" name="formClientTbl">
<table border='1' width="100%">
	<tr class="tbl_head">
		<td width="20%" align="center"><font size=2><b>연결상태</b></td>
		<td width="25%" align="center"><font size=2><b>IP Address</b></td>
		<td width="35%" align="center"><font size=2><b>MAC Address</b></td>
		<td width="20%" align="center"><font size=2><b>Time Expired(s)</b></td>
	</tr>
<?php
	if(count($devicelist) == 0){
?>
	<tr class="tbl_body" align="center">
		<td><font size="2">--</font></td>
		<td><font size="2">--</font></td>
		<td><font size="2">--</font></td>
		<td><font size="2">--</font></td>
	</tr>
<?php
	}else{
		for($i=0; $i < count($devicelist); $i++){
			if($devicelist[$i]["contype"] == "0" || $devicelist[$i]["contype"] == "6"){
				$devicelist[$i]["contype"] = "무선";
			}else{
				$devicelist[$i]["contype"] = "LAN".($devicelist[$i]["contype"]-($lan_no-1));
			}
?>
	<tr class="tbl_body" align="center">
		<td><font size="2"><?=$devicelist[$i]["contype"]?></font></td>
		<td><font size="2"><?=$devicelist[$i]["ip"]?></font></td>
		<td><font size="2"><?=$devicelist[$i]["mac"]?></font></td>
		<td><font size="2"><?=$devicelist[$i]["time"] - $nowtime?></font></td>
	</tr>
<?php
		}
	}
?>
</table>
<input type="hidden" value="/skb_dhcptbl.php" name="submit-url">
<p><input type="button" value="다시보기" name="refresh" onclick="window.location.reload();">&nbsp;&nbsp;
<input type="button" value=" 닫기 " name="close" onclick="javascript: window.close();"></p>
</form>
</blockquote>
</body>

</html>
