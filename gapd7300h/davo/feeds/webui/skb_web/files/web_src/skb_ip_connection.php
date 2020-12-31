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
	$sock->write("connection_stats",$param);
	$dhcpinfo = $sock->read();
	$stats = json_decode($dhcpinfo,true)["data"];
	$stats = json_encode($stats,JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK );
	$sock->disconnect();
	$cmd = new dvcmd();
	$cmd->add("netstat");
	$cmd->run();
	$arp = explode("\n",rtrim($cmd->result()[0]));
	$cmd->close();
	$result = Array();
//	print_r($arp);
	for($i=0; $i < count($arp); $i++){
		if(strpos($arp[$i],"127.0.0.1") === false){
			$result[] = $arp[$i];
		}
	}
	$result = array_splice($result,2);
	$netstat = Array();
	/*
	Array
(
    [0] => tcp        0      0 :::445                  :::*                    LISTEN
    [1] => tcp
    [2] => 0
    [3] => 0
    [4] => :::445
    [5] => :::*
    [6] => LISTEN
)
	*/
	for($i=0; $i < count($result); $i++){
//		echo $result[$i];
//		echo("<br>");
		if(preg_match("/^(\w+)\s+(\d+)\s+(\d+)\s+([\w+\:\.\*]{1,})\s+([\w+\:\.\*]{1,})\s+(\w+)/",$result[$i],$d) == true) {
			$netstat[] = Array(
				"type" => $d[1],
				"recv" => $d[2],
				"send" => $d[3],
				"local" => $d[4],
				"remote" => $d[5],
				"state" => $d[6]
			);
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
<title>커넥션 통계</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"></script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var stats = <?=$stats?>;
$(document).ready(function(){
	$("#total_connection").text(stats["connections"]["total_connection"]);
	$("#tcp_connection").text(stats["connections"]["tcp_connection"]);
	$("#udp_connection").text(stats["connections"]["udp_connection"]);
	$("#igmp_connection").text(stats["connections"]["icmp_connection"]);
	$("#other_connection").text(stats["connections"]["other_connection"]);
	$("#rx_packet").text(stats["connections"]["rx_packets"].toLocaleString());
	$("#tx_packet").text(stats["connections"]["tx_packets"].toLocaleString());

	$("#rx_byte").text(byteConvertor(stats["connections"]["rx_bytes"]));
	$("#tx_byte").text(byteConvertor(stats["connections"]["tx_bytes"]));
});
</script>
</head>
<body>
<form action="proc/skb_ip_connection_proc.php" method="POST" name="IpConnection">
<input type="hidden" value="/skb_ip_connection.php" name="submit-url">
<blockquote>
	<h2>커넥션 통계</h2>
	<table border=0 width="600" cellspacing="4" cellpadding="0">
		<tr><td><font size="2">
			전체 및 IP 별 커넥션 정보를 확인 할 수 있는 페이지입니다.<br>
			전체 커넥션 정보는 WAN구간의 정보를 의미합니다
		</font></td></tr>
		<tr><td><hr size="1" align="top" noshade="noshade"></td></tr>
	</table>
	<br>
	<table width="600" border="0">
		<tr>
			<td width="30%"><font size="3"><b>전체 커넥션 정보</b></font></td>
			<td width="40%">
				<!--새로고침 버튼, 패킷 카운트 초기화 버튼 ,-->
				<input type="button" value="새로 고침" onclick="window.location.reload();" />
<!-- 				<input type="submit" name="count_init" value="패킷 카운트 초기화" /> -->

			</td>
			<td align="right" width="30%">
				<!--timer-->
				<input name="conn_init_timer" type="text" style="background-color:#EEEEEE;border:none;text-align:right;" readonly onfocus="this.blur" name="show_timer" size="20" value=""></span>
			</td>
		</tr>
	</table>
	<table width="600" border="0" cellpadding="2" cellspacing="1">
		<tr><td colspan="9">&nbsp;</td></tr>
		<tr class="tbl_head">
			<td align="center"><b>전체 커넥션</b></td>
			<td align="center"><b>TCP</b></td>
			<td align="center"><b>UDP</b></td>
			<td align="center"><b>ICMP</b></td>
			<td align="center"><b>Other</b></td>
			<td align="center"><b>송신<br>패킷</b></td>
			<td align="center"><b>수신<br>패킷</b></td>
			<td align="center"><b>송신<br>바이트</b></td>
			<td align="center"><b>수신<br>바이트</b></td>
		</tr>
		<tr>
			<td align="center"><span id="total_connection"></span></td>
			<td align="center"><span id="tcp_connection"></span></td>
			<td align="center"><span id="udp_connection"></span></td>
			<td align="center"><span id="igmp_connection"></span></td>
			<td align="center"><span id="other_connection"></span></td>
			<td align="center"><span id="rx_packet"></span></td>
			<td align="center"><span id="tx_packet"></span></td>
			<td align="center"><span id="rx_byte"></span></td>
			<td align="center"><span id="tx_byte"></span></td>
		</tr>
	</table>
<!-- 	<br><br> -->
<!-- 	<table width="600" border="0"> -->
<!-- 		<tr> -->
<!-- 			<td ><font size="3"><b>IP별 커넥션 정보</b></font></td> -->
<!-- 		</tr> -->
<!-- 	</table> -->
<!-- 	<table width="600" border="0" cellpadding="2" cellspacing="1"> -->
<!-- 		<tr><td colspan="9">&nbsp;</td></tr> -->
<!-- 		<tr class="tbl_head"> -->
<!-- 			<td align="center"><b>IP 주소</b></td> -->
<!-- 			<td align="center"><b>호스트 정보</b></td> -->
<!-- 			<td align="center"><b>유/무선</b></td> -->
<!-- 			<td align="center"><b>커넥션<br>수</b></td> -->
<!-- 			<td align="center"><b>송신<br>패킷</b></td> -->
<!-- 			<td align="center"><b>수신<br>패킷</b></td> -->
<!-- 			<td align="center"><b>송신<br>바이트</b></td> -->
<!-- 			<td align="center"><b>수신<br>바이트</b></td> -->
<!-- 		</tr> -->
<!-- 		 -->
<!--  -->
<!-- 	</table> -->
	<br><br>
	
	<div id="net_viewer_title"> 
	<table width="600" border="0">
		<tr>
			<td ><font size="3"><b>AP 시스템 커넥션 정보</b></font></td>
		</tr>
	</table>
	</div>
	<br>	
	<div id="net_viewer" style="width:620px; height:300px; overflow:auto"> 
  	<table name="conn_info" border="1" rules="none" width="600" cellpadding="0" cellspacing="1" style='color:white; background-color:black;'>
		<tr>
			<td><center>Proto</center></td>
			<td><center>Recv-Q</center></td>
			<td><center>Send-Q</center></td>
			<td><center>Local Address</center></td>
			<td><center>Foreign Address</center></td>
			<td><center>State</center></td>
		</tr>
<?php
	for($i=0; $i < count($netstat); $i++){
?>
		<tr>
			<td align="center"><?=$netstat[$i]["type"]?></td>
			<td align="center"><?=$netstat[$i]["recv"]?></td>
			<td align="center"><?=$netstat[$i]["send"]?></td>
			<td align="center"><?=$netstat[$i]["local"]?></td>
			<td align="center"><?=$netstat[$i]["remote"]?></td>
			<td align="center"><?=$netstat[$i]["state"]?></td>
		</tr>
<?php
	}
?>
	</table>
</div>
</blockquote>
</form>
</body>
</html>
