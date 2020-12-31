<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$flag =  dv_post("flag");
//	$syscall = new dvcmd();
//	$syscall->add("wlanconfig", "","!");
//	$syscall->run();
	$scan = "";
	if(dv_session("wlan_id") == "1"){
		if(file_exists("/tmp/ath0_scan.txt") == false){
			run_wifi_scan("ath0");
		}else{
			if($flag == "rescan"){
				run_wifi_scan("ath0");
			}
		}
		$scanfile = "/tmp/ath0_scan.txt";
	}else{
		if(file_exists("/tmp/ath1_scan.txt") == false){
			run_wifi_scan("ath1");
		}else{
			if($flag == "rescan"){
				run_wifi_scan("ath1");
			}
		}
		$scanfile = "/tmp/ath1_scan.txt";
	}
	$handle = fopen($scanfile, "r");
	$contents = fread($handle, filesize($scanfile));
	fclose($handle);
	$scan = explode("\n",rtrim($contents));
	$result = Array();
	for($i=0; $i < count($scan); $i++){
//		echo $scan[$i]."<br>";
		if(preg_match("/^\[\s+([\w+\:]{6,})\s+(\d+)\s+([\d\-]{1,})\s+([\w+\-\/]{1,})\s+([\w+\-\/\.]{1,})\s+(\w+)\s+\"([\s+\S]{0,})\"\s+[\s+\S+]{0,}\]$/",$scan[$i],$d) == true) {
			$tmp = Array(
				"mac" => $d[1],
				"channel" => $d[2],
				"rssi" => $d[3],
				"mode" => $d[4],
				"security" => str_replace("open","OPEN",str_replace("wep","WEP",str_replace("WAP","WPA",$d[5]))),
				"ap_mode" => $d[6],
				"ssid" => $d[7]
			);
			$result[] = $tmp;
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
<title>Wireless Site Survey</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var connectEnabled=0, autoconf=0;


function opera()
{
	if(top.location != self.location){
		var a = window.parent.document.getElementsByTagName('iframe');
		for (var i=0; i<a.length; i++){
			if (a[i].name == self.name) {
				a[i].height = document.body.scrollHeight; return;
			}
		}
	}
	window.parent.button_color_active()
}
function siteSurvey()
{
	//alert("SSIDSiteSurvey wlan"+ifname);
//	document.formWlSiteSurvey.ifname.value = "wlan"+ifname;
	document.formWlSiteSurvey.submit();

}
</script>
</head>
<body onload="opera()">


<form action="skb_pocket_sitesurvey.php#form" method="POST" name="formWlSiteSurvey">
<input type="hidden" value="Site Survey" name="refresh">&nbsp;&nbsp;
<input type="hidden" value="/skb_pocket_sitesurvey.php" name="submit-url">
<input type="hidden" name="flag" id="flag" value="rescan">
<table border="1" width="500">

	<tr class="tbl_head"><td align="center" width="30%" ><font size="2"><b>SSID</b></font></td>
		<td align="center" width="20%" ><font size="2"><b>BSSID</b></font></td>
		<td align="center" width="10%" ><font size="2"><b>채널</b></font></td>
		<td align="center" width="20%" ><font size="2"><b>종류</b></font></td>
		<td align="center" width="10%" ><font size="2"><b>암호화</b></font></td>
		<td align="center" width="10%" ><font size="2"><b>RSSI<br>(dbm)</b></font></td>
	</tr>
<?php
	for($i=0; $i < count($result); $i++){
?>
	<tr class="tbl_body"><td align="center" width="20%" ><font size="2"><?=$result[$i]["ssid"]?></font></td>
		<td align="center" width="20%" ><font size="2"><?=$result[$i]["mac"]?></font></td>
		<td align="center" width="10%" ><font size="2"><?=$result[$i]["channel"]?> (<?=$result[$i]["mode"]?>)</td>
		<td align="center" width="20%" ><font size="2"><?=$result[$i]["ap_mode"]?></td>
		<td align="center" width="10%" ><font size="2"><?=$result[$i]["security"]?></td>
		<td align="center" width="10%" ><font size="2"><?=$result[$i]["rssi"]?></td>
	</tr>
<?php
	}
?>
</table>
<script type="text/javascript">
	parent.button_color_active();
</script>
<br>
</form>
</body>
</html>
