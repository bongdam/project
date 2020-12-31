<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$param = null;
	$sock = new rcqm();
	$sock->connect();
	if($sock->con()){
	}else{
		echo "dvmgmt error";
	}
	$sock->write("traffic_stats",$param);
	$dhcpinfo = $sock->read();
	$stats = json_decode($dhcpinfo,true)["data"];
	$sock->disconnect();
//	$stats = json_encode($stats,JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK );
	$cfg = new dvcfg();
	$cfg->read("wireless");
	$cfg->result_remove("wireless.vap00.key");
	$cfg->result_remove("wireless.vap01.key");
	$cfg->result_remove("wireless.vap02.key");
	$cfg->result_remove("wireless.vap10.key");
	$cfg->result_remove("wireless.vap11.key");
	$cfg->result_remove("wireless.vap12.key");
	$arr_wifi = $cfg->result("array");
	$wifi = array_to_json($cfg->search("wireless"));
	
//	print_r($arr_wifi);
	$wifi5_disable = Array();
	$wifi5_ssid = Array();
	$wifi24_disable = Array();
	$wifi24_ssid = Array();
	$wifi24_disable_cnt = 3;
	$wifi5_disable_cnt = 3;
	for($i=0; $i < 3; $i++){
		if($i == 0){
			if($cfg->search("wireless.wifi0.disabled") == "1"){
				$wifi5_disable_cnt -= 1;
				$wifi5_disable[] = false;
			}else{
				$wifi5_disable[] = true;
			}
			if($cfg->search("wireless.wifi1.disabled") == "1"){
				$wifi24_disable_cnt -= 1;
				$wifi24_disable[] = false;
			}else{
				$wifi24_disable[] = true;
			}
		}else{
			if($cfg->search("wireless.vap0".$i.".disabled") == "1"){
				$wifi5_disable_cnt -= 1;
				$wifi5_disable[] = false;
			}else{
				$wifi5_disable[] = true;
			}
			if($cfg->search("wireless.vap1".$i.".disabled") == "1"){
				$wifi24_disable_cnt -= 1;
				$wifi24_disable[] = false;
			}else{
				$wifi24_disable[] = true;
			}
			
		}
		$wifi5_ssid[] = $cfg->search("wireless.vap0".$i.".ssid");
		$wifi24_ssid[] = $cfg->search("wireless.vap1".$i.".ssid");
	}
	$wifi24_disable_cnt *= 2;
	$wifi5_disable_cnt *= 2;
	$cfg->close();
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>Statisitcs</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"></script>
<script type="text/javascript">
var stats = <?= json_encode($stats,JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK );?>;
$(document).ready(function(){
//	$("#wlan5_tx").text(byteConvertor(stats["radio_0"]["tx_bytes"]));
//	$("#wlan5_rx").text(byteConvertor(stats["radio_0"]["rx_bytes"]));
//	$("#wlan24_tx").text(byteConvertor(stats["radio_1"]["tx_bytes"]));
//	$("#wlan24_rx").text(byteConvertor(stats["radio_1"]["rx_bytes"]));

	$("#lan_tx").text(byteConvertor(stats["lan"]["tx_bytes"]));
	$("#lan_rx").text(byteConvertor(stats["lan"]["rx_bytes"]));
	$("#wan_tx").text(byteConvertor(stats["wan"]["tx_bytes"]));
	$("#wan_rx").text(byteConvertor(stats["wan"]["rx_bytes"]));

	$("#crc_wan").text(stats["crc"]["wan_rx_crc_error"]);
	$("#crc_lan1").text(stats["crc"]["lan_0_rx_crc_error"]);
	$("#crc_lan2").text(stats["crc"]["lan_1_rx_crc_error"]);
	$("#crc_lan3").text(stats["crc"]["lan_2_rx_crc_error"]);
	$("#crc_lan4").text(stats["crc"]["lan_3_rx_crc_error"]);
});
</script>
<link href="/style.css" rel="stylesheet" type="text/css">
</head>
<body>
<blockquote>
<h2>트래픽 통계</h2>

<table border="0" width="600" cellpadding="0">
	<tr>
		<td><font size="2">유무선 네트워크에 관한 데이터 송수신량을 보여주는 페이지 입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>
<form name="traffic" method="post" action="skb_stats.php">
<table border="1" width="600">
<?php
	if($wifi5_disable[0] == true){
?>
	<tr>
		<td align="center" valign="middle" width="20%" rowspan="<?=$wifi5_disable_cnt?>"><font size="2"><b>무선 5G</b></font></td>
		<td valign="middle" rowspan="2" align="center"><font size="2"><?=$wifi5_ssid[0]?></font></td>
		<td align="center" valign="middle" width="20%"><font size="2">보낸 데이터</font></td>
		<td align="center" valign="middle" width="25%"><font size="2"><?=byteConvert($stats["ath0"]["tx_bytes"]);?></font></td>
	</tr>
	<tr>
		<td align="center" valign="middle"><font size="2">받은 데이터</font></td>
		<td align="center" valign="middle"><font size="2"><?=byteConvert($stats["ath0"]["rx_bytes"]);?></font></td>
	</tr>
<?php
		for($i=1;$i < 3; $i++){
			if($wifi5_disable[$i] == true){
?>
	<tr>
		<td valign="middle" rowspan="2" align="center"><font size="2"><?=$wifi5_ssid[$i]?></font></td>
		<td align="center" valign="middle"><font size="2">보낸 데이터</font></td>
		<td align="center" valign="middle"><font size="2"><?=byteConvert($stats["ath0".$i]["tx_bytes"]);?></font></td>
	</tr>
	<tr>
		<td align="center" valign="middle"><font size="2">받은 데이터</font></td>
		<td align="center" valign="middle"><font size="2"><?=byteConvert($stats["ath0".$i]["rx_bytes"]);?></font></td>
	</tr>
<?
			}
		}
	}
	if($wifi24_disable[0] == true){
?>

	<tr>
		<td align="center" valign="middle" width="20%" rowspan="<?=$wifi24_disable_cnt?>"><font size="2"><b>무선 2.4G</b></font></td>
		<td valign="middle" rowspan="2" align="center"><font size="2"><?=$wifi24_ssid[0]?></font></td>
		<td align="center" valign="middle" width="20%"><font size="2">보낸 데이터</font></td>
		<td align="center" valign="middle" width="25%"><font size="2"><?=byteConvert($stats["ath1"]["tx_bytes"]);?></font></td>
	</tr>
	<tr>
		<td align="center" valign="middle"><font size="2">받은 데이터</font></td>
		<td align="center" valign="middle"><font size="2"><?=byteConvert($stats["ath1"]["rx_bytes"]);?></font></td>
	</tr>
<?php
	
		for($i=1;$i < 3; $i++){
			if($wifi24_disable[$i] == true){
?>
	<tr>
		<td valign="middle" rowspan="2" align="center"><font size="2"><?=$wifi24_ssid[$i]?></font></td>
		<td align="center" valign="middle"><font size="2">보낸 데이터</font></td>
		<td align="center" valign="middle"><font size="2"><?=byteConvert($stats["ath1".$i]["tx_bytes"]);?></font></td>
	</tr>
	<tr>
		<td align="center" valign="middle"><font size="2">받은 데이터</font></td>
		<td align="center" valign="middle"><font size="2"><?=byteConvert($stats["ath1".$i]["rx_bytes"]);?></font></td>
	</tr>
<?
			}
		}
	}
?>

	<tr>
		<td align="center" valign="middle" rowspan="2" colspan="2"><font size="2"><b>로컬 랜</b></font></td>
		<td align="center" valign="middle"><font size="2">보낸 데이터</font></td>
		<td align="center" valign="middle"><font size="2"><span id="lan_tx"></span></font></td>
	</tr>
	<tr>
		<td align="center" valign="middle" ><font size="2">받은 데이터</font></td>
		<td align="center" valign="middle"><font size="2"><span id="lan_rx"></span></font></td>
	</tr>
	<tr>
		<td align="center" valign="middle"  rowspan="2" colspan="2"><font size="2"><b>인터넷</b></font></td>
		<td align="center" valign="middle" ><font size="2">보낸 데이터</font></td>
		<td align="center" valign="middle" ><font size="2"><span id="wan_tx"></span></font></td>
	</tr>
	
	<tr>
		<td align="center" valign="middle" ><font size="2">받은 데이터</font></td>
		<td align="center" valign="middle"><font size="2"><span id="wan_rx"></span></font></td>
	</tr>
	<tr>
		<td align="center" valign="middle" rowspan="5" colspan="2"><font size="2"><b>CRC</b></font></td>
		<td align="center" valign="middle" width="20%" ><font size="2">WAN</font></td>
		<td align="center" valign="middle" width="25%"><font size="2"><span id="crc_wan"></span></font></td>
	</tr>
	<tr>
		<td align="center" valign="middle" ><font size="2">LAN-2</font></td>
		<td align="center" valign="middle"><font size="2"><span id="crc_lan1"></span></font></td>
	</tr>
	<tr>
		<td align="center" valign="middle" ><font size="2">LAN-2</font></td>
		<td align="center" valign="middle"><font size="2"><span id="crc_lan2"></span></font></td>
	</tr>
	<tr>
		<td align="center" valign="middle" ><font size="2">LAN-3</font></td>
		<td align="center" valign="middle"><font size="2"><span id="crc_lan3"></span></font></td>
	</tr>
	<tr>
		<td align="center" valign="middle" ><font size="2">LAN-4</font></td>
		<td align="center" valign="middle"><font size="2"><span id="crc_lan4"></span></font></td>
	</tr>
</table>

<br>
<br>
<br>
<input type="hidden" value="/skb_stats.php" name="submit-url">
<input type="button" value="새로고침" name="Refresh" onclick="window.location.reload();">
</form>
</blockquote>
</body>

</html>
