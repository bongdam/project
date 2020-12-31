<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$lan_no = dv_session("lan_no");
	$info = dv_get("info");
	$port_no = dv_get("port");
	
//	$dhcpfile = @fopen("/root/igmp", "r");
//	$dhcpinfo = fread($dhcpfile,filesize("/root/igmp"));
//	fclose($dhcpfile);
	$cmd = new dvcmd();
	$cmd->add("igmpshow");
	$cmd->run();
	$dhcpinfo = $cmd->result()[0];
	$cmd->close();
	
	$igmp = explode("\n",rtrim($dhcpinfo));
	$igmp_list = Array();
	$group_no = 0;
	$group_name = "";
	$sub_cnt = 0;
	for($i=0; $i < count($igmp);$i++){
		if(preg_match("/^(\d+)\s+(\d+\.\d+\.\d+\.\d+)/",$igmp[$i],$d) == true) {
			$sub_cnt = 0;
//			echo $d[1]."<br>";
//			echo $d[2];
			$igmp_list[$d[1]] = Array();
			$group_no = $d[1];
			$group_name = $d[2];
		}
		if(preg_match("/^\s+(\d+\.\d+\.\d+\.\d+)\s+(\w+\:\w+\:\w+\:\w+\:\w+\:\w+)\s+(\d+)\s+(\d+)/",$igmp[$i],$d) == true) {
			$igmp_list[$group_no][$sub_cnt]["no"] = $group_no;
			$igmp_list[$group_no][$sub_cnt]["group"] = $group_name;
			$igmp_list[$group_no][$sub_cnt]["user"] = $d[1];
			$igmp_list[$group_no][$sub_cnt]["mac"] = $d[2];
			$igmp_list[$group_no][$sub_cnt]["port"] = $d[3];
			$igmp_list[$group_no][$sub_cnt]["age"] = $d[4];
			$sub_cnt+=1;
		}
	}
	$group_list = $igmp_list[$info];
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>IGMP JOIN 상태</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<link href="/style.css" rel="stylesheet" type="text/css">
</head>

<body>
<blockquote>
<h2>IGMP Group Join</h2>

<table border=0 width="480" cellspacing=0 cellpadding=0>
	<tr>
		<td><font size="2">LAN-<?=$port_no?> JOIN 상태 페이지 입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>
<form action="" method="POST" name="formClientTbl">
<table border='1' width="100%">
	<tr class="tbl_head">
		<td width="30%" align="center"><font size="2"><b>Group Address</b></font></td>
		<td width="30%" align="center"><font size="2"><b>Joiner Address</b></font></td>
		<td width="40%" align="center"><font size="2"><b>MAC Address</b></font></td>
	</tr>
<?php
	if(count($group_list) == 0){
?>
	<tr class="tbl_body" align="center">
		<td><font size="2">--</font></td>
		<td><font size="2">--</font></td>
		<td><font size="2">--</font></td>
	</tr>
<?php
	}else{
		for($i=0; $i < count($group_list); $i++){
		if($group_list[$i]["port"] != $port_no){
			continue;
		}
?>
	<tr class="tbl_body" align="center">
		<td><font size="2"><?=$group_list[$i]["group"]?></font></td>
		<td><font size="2"><?=$group_list[$i]["mac"]?></font></td>
		<td><font size="2"><?=$group_list[$i]["user"]?></font></td>
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
