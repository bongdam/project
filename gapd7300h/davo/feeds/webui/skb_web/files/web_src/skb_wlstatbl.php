<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	//ls -p hostapd-wifi* | sed "s/://" | sed "s/hostapd-//" | sed "/^$/d"
//	DEF_MODEL
//	DEF_ANT
	$seq = dv_get("seq");
	$wno = "1";
	$wifi2 = "";
	$wifi5 = "";
	$ifname = "";
	if($seq == "4"){
		dv_set_session("wlan_id","1");
	}
//	echo DEF_MODEL.DEF_ANT;
	if(DEF_MODEL == "QCA_REF" && DEF_ANT == "4x4"){
		if(dv_session("wlan_id") == "0"){
			//2.4G
			$wifi2 = "ath2";
		}else{
			//5G
			$wifi5 = "ath0";
		}
	}elseif(DEF_MODEL != "QCA_REF" && DEF_ANT == "4x4"){
		if(dv_session("wlan_id") == "0"){
			//2.4G
			$wifi2 = "ath1";
			$ifname = "ath1";
		}else{
			//5G
			$wifi5 = "ath0";
			$ifname = "ath0";
		}
	}elseif(DEF_MODEL == "QCA_REF" && DEF_ANT == "2x2"){
		
	}elseif(DEF_MODEL != "QCA_REF" && DEF_ANT == "2x2"){
		
	}
	if($seq != "0"){
		$ifname = $ifname.$seq;
	}
	$ifface = Array();
	array_push($ifface,$ifname);
	if($ifname == "ath0"){
		array_push($ifface,"ath04");
	}
	$syscall = new dvcmd();
	$syscall->add("sta_list");
	$syscall->run();
	$syscall->result();
	$syscall->close();
	$sta_list = "";
	if(file_exists("/tmp/station.txt") == true){
		$handle = fopen("/tmp/station.txt", "r");
		$contents = fread($handle, filesize("/tmp/station.txt"));
		fclose($handle);
		$sta_list = explode("\n",rtrim($contents));
	}
	
//	print_r($sta_list);
//	echo "<br>";
	$sta = array();
	for($i=0 ; $i < count($sta_list); $i++){
		if(preg_match("/^[\s+]{0,}\[\s+(\S+)\s+([\w+\:]{6,})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+[\s+\S+]{0,}\]$/",$sta_list[$i],$d) == true) {
//			print_r($d);
			$rssi = $d[7];
			if(preg_match("/[\s+]{0,}\d+\((\-\d+)\)/",$rssi,$s) == true){
				$rssi = $s[1];
			}
			$tmp = Array(
				"ifname"	=> $d[1],
				"mac"		=> $d[2],
				"mode"		=> $d[3],
				"tx_kb"		=> (int)$d[4],
				"rx_kb"		=> (int)$d[5],
				"link_rate"	=> $d[6],
				"rssi"		=> $rssi,
				"time"		=> $d[8],
				"scmode"	=> $d[9],
				"use_time"	=> $d[10]
			);
			
			array_push($sta,$tmp);
		}
	}
//	print_r($sta);
	$json = json_encode($sta);
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>무선 인터넷 접속 리스트</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
//	var sta = <?=$json?>;
	$(document).ready(function(){
//		console.log("ready");
//		$("#tbdy").children().remove();
//		if(sta.length > 0){
//			var tmp = "";
//			for (var i=0; i < sta.length ; i++ )
//			{
//				console.log(sta[i]);
//				tmp += "<tr>";
//				tmp += "<td>"+sta[i].mac+"</td>";
//				tmp += "<td>"+sta[i].ch+"</td>";
//				tmp += "<td>"+sta[i].ch+"</td>";
//				tmp += "<td>"+sta[i].ch+"</td>";
//				tmp += "<td>"+sta[i].txrate+"</td>";
//				tmp += "<td>"+sta[i].ch+"</td>";
//				tmp += "<td>"+sta[i].ch+"</td>";
//				tmp += "<td>"+sta[i].assoctime+"</td>";
//				tmp += "</tr>";
//			}
//			$("tbdy").append(tmp);
//		}else{
//			var nodata = "<tr align=\"center\" class=\"tbl_body\"><td><font size="2">없음</font></td><td><font size="2">---</font></td><td><font size="2">---</font></td><td><font size="2">---</font></td><td><font size=\"2\">---</font></td><td><font size=\"2\">---</font></td><td><font size=\"2\">---</font></td><td><font size=\"2\">---</font></td></tr>"
//			$("#tbdy").append(nodata);
//		}
	});
</script>
</head>
<body>
<blockquote>
<h2>
<?php
	if(dv_session("wlan_id") == "1"){
		echo("무선 인터넷 접속 리스트 5G");
	}elseif(dv_session("wlan_id") == "0"){
		echo("무선 인터넷 접속 리스트 2.4G");
	}else{
		echo("Wireless Basic Settings");
	}
	if($seq != "0"){
		if($seq == "4"){
			$seq = "3";
		}
		echo(" AP-".$seq);
	}
?>
</h2>
<table border="0" width="750" cellspacing="0" cellpadding="0">
	<tr>
		<td><font size="2">무선 인터넷에 접속된 호스트들의 각종 정보를 보여주는 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></hr></td>
	</tr>
</table>
<form action="skb_wlstatbl.php" method="POST" name="formWirelessTbl">
<table border='1' width="750">
<thead style="text-align:center">
<tr class="tbl_head"><td><font size="2"><b>MAC 주소</b></font></td>
	<td width="50"><font size="2"><b>RSSI</b></font></td>
	<td width="90"><font size="2"><b>모드</b></font></td>
	<td width="70"><font size="2"><b>송신<br>kByte</b></font></td>
	<td width="70"><font size="2"><b>수신<br>kByte</b></font></td>
	<td width="70"><font size="2"><b>전송률 (Mbps)</b></font></td>
	<td width="50"><font size="2"><b>전원<br>절약</b></font></td>
	<td width="70"><font size="2"><b>남은시간</b></td></font></td>
	<td width="80"><font size="2"><b>경과시간</b></td></font>
</tr>
</thead>
<tbody id="tbdy" style="text-align:center;">
<?php
	$stacnt = 0;
	if(count($sta) > 0 ){
		
		for($i=0; $i < count($sta); $i++){
//			print_r($sta[$i]);
			if(array_search($sta[$i]["ifname"],$ifface) !== false){
?>
	<tr class="tbl_body">
		<td><font size="2"><?=strtoupper($sta[$i]["mac"])?></font></td>
		<td><font size="2"><?=$sta[$i]["rssi"]?></font></td>
		<td><font size="2"><?=$sta[$i]["mode"]?></font></td>
		<td><font size="2"><?=$sta[$i]["rx_kb"]?></font></td>
		<td><font size="2"><?=$sta[$i]["tx_kb"]?></font></td>
		<td><font size="2"><?=$sta[$i]["link_rate"]?></font></td>
		<td><font size="2"><?=strtoupper($sta[$i]["scmode"])?></font></td>
		<td><font size="2"><?=$sta[$i]["time"]?></font></td>
		<td><font size="2"><?=$sta[$i]["use_time"]?></font></td>
	</tr>
<?
			$stacnt++;
			}
		}
	}else{
		$stacnt++;
?>
	<tr align="center" class="tbl_body">
		<td><font size="2">없음</td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
	</tr>
<?php
	}
	if($stacnt == 0){
?>
	<tr align="center" class="tbl_body">
		<td><font size="2">없음</td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
		<td><font size="2">---</font></td>
	</tr>
<?php
	}
?>
</tbody>
</table>

<input type="hidden" value="/skb_wlstatbl.php" name="submit-url">
  <p><input type="button" value="다시 보기" name="refresh" onclick="window.location.reload();">&nbsp;&nbsp;
  <input type="button" value=" 닫기 " name="close" onClick="javascript: window.close();"></p>
</form>
</blockquote>
</body>

</html>
