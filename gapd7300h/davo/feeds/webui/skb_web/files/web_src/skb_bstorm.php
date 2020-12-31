<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	function port_convert($port_){
		$portstr = "";
		if($port_[4] == "1"){
			$portstr .= ",1";
		}else{
			$portstr .= ",0";
		}
		if($port_[3] == "1"){
			$portstr .= ",1";
		}else{
			$portstr .= ",0";
		}
		if($port_[2] == "1"){
			$portstr .= ",1";
		}else{
			$portstr .= ",0";
		}
		if($port_[1] == "1"){
			$portstr .= ",1";
		}else{
			$portstr .= ",0";
		}
		if($port_[0] == "1"){
			$portstr .= ",1";
		}else{
			$portstr .= ",0";
		}
		$portstr = substr($portstr,1,strlen($portstr));
		return $portstr;
	}
	$uci = new uci();
	$uci->mode("get");
	$uci->get("network.bstorm_ctrl_acl");
	$uci->get("network.bstorm_ctrl_rule");
	$uci->run();
	$bstorm = json_decode($uci->result(),true);
	if($bstorm["network.bstorm_ctrl_acl.device"] == ""){
		$bstorm_enable = "0";
	}else{
		$bstorm_enable = "1";
	}
	$bstorm_cir = $bstorm["network.bstorm_ctrl_acl.cir"];
	if($bstorm_cir == ""){
		$bstorm_cir = 0;
	}
	$port = $bstorm["network.bstorm_ctrl_rule.port_bitmap"];
	$port = port_convert(substr("000000".decbin(hexdec($port)),-6));
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>브로드캐스트 스톰 제어</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var port = "<?=$port?>";
function updateState()
{
  if (document.formBroadcastStormCtrl.broadcast_storm_ctrl_enable.checked) {
	document.formBroadcastStormCtrl.wan_port.disabled = false;
	document.formBroadcastStormCtrl.lan1_port.disabled = false;
	document.formBroadcastStormCtrl.lan2_port.disabled = false;
	document.formBroadcastStormCtrl.lan3_port.disabled = false;
	document.formBroadcastStormCtrl.lan4_port.disabled = false;
	enableTextField(document.formBroadcastStormCtrl.rate);
 	enableTextField(document.formBroadcastStormCtrl.wan_port);
 	enableTextField(document.formBroadcastStormCtrl.lan1_port);
 	enableTextField(document.formBroadcastStormCtrl.lan2_port);
 	enableTextField(document.formBroadcastStormCtrl.lan3_port);
 	enableTextField(document.formBroadcastStormCtrl.lan4_port);
  }
  else {
	document.formBroadcastStormCtrl.wan_port.disabled = true;
	document.formBroadcastStormCtrl.lan1_port.disabled = true;
	document.formBroadcastStormCtrl.lan2_port.disabled = true;
	document.formBroadcastStormCtrl.lan3_port.disabled = true;
	document.formBroadcastStormCtrl.lan4_port.disabled = true;
 	disableTextField(document.formBroadcastStormCtrl.rate);
 	disableTextField(document.formBroadcastStormCtrl.wan_port);
 	disableTextField(document.formBroadcastStormCtrl.lan1_port);
 	disableTextField(document.formBroadcastStormCtrl.lan2_port);
 	disableTextField(document.formBroadcastStormCtrl.lan3_port);
 	disableTextField(document.formBroadcastStormCtrl.lan4_port);
  }
}

function saveChanges()
{
	if (!document.formBroadcastStormCtrl.broadcast_storm_ctrl_enable.checked) {
		return true;
	}
	if ( isNaN(document.formBroadcastStormCtrl.rate.value) ==true || document.formBroadcastStormCtrl.rate.value < 1 || document.formBroadcastStormCtrl.rate.value > 1048544 ) {
		alert("전송률 설정은 숫자(1~1048544) 범위로 설정해 주세요..");
		return false;
	}
	document.formBroadcastStormCtrl.port.value = port_to_bit();
	return true;
}
var port_to_bit = function(){
	var wan = $("#wan_port").prop("checked") ? "1" : "0";
	var lan1 = $("#lan1_port").prop("checked") ? "1" : "0";
	var lan2 = $("#lan2_port").prop("checked") ? "1" : "0";
	var lan3 = $("#lan3_port").prop("checked") ? "1" : "0";
	var lan4 = $("#lan4_port").prop("checked") ? "1" : "0";
//	111110
	var bin = lan4 + lan3 + lan2 + lan1 + wan + "0";
	var hex = "0x"+parseInt(bin,2).toString(16);
	return hex;
}
var port_setting = function(){
	var portlist = port.split(",");
	for(var i=0; i < 5; i++){
		if(i == 0){
			//wan
			if(portlist[i] == "1"){
				$("#wan_port").prop("checked",true);
			}
		}else{
			if(portlist[i] == "1"){
				$("#lan"+i+"_port").prop("checked",true);
			}
		}
	}
}
function LoadSetting()
{
	port_setting();
	var bstorm_enabled = <?=$bstorm_enable?>;
	var rate_bps = <?=$bstorm_cir?>;
	
	if (bstorm_enabled) {
		enableTextField(document.formBroadcastStormCtrl.rate);
		document.formBroadcastStormCtrl.wan_port.disabled = false;
		document.formBroadcastStormCtrl.lan1_port.disabled = false;
		document.formBroadcastStormCtrl.lan2_port.disabled = false;
		document.formBroadcastStormCtrl.lan3_port.disabled = false;
		document.formBroadcastStormCtrl.lan4_port.disabled = false;
		document.formBroadcastStormCtrl.broadcast_storm_ctrl_enable.checked = true;
	} else {
 		disableTextField(document.formBroadcastStormCtrl.rate);
		document.formBroadcastStormCtrl.wan_port.disabled = true;
		document.formBroadcastStormCtrl.lan1_port.disabled = true;
		document.formBroadcastStormCtrl.lan2_port.disabled = true;
		document.formBroadcastStormCtrl.lan3_port.disabled = true;
		document.formBroadcastStormCtrl.lan4_port.disabled = true;
		document.formBroadcastStormCtrl.broadcast_storm_ctrl_enable.checked = false;
	}

	if (rate_bps == 0){
		rate_bps = 0;
	}
	$("#rate").val(rate_bps);
	updateState();
}

</script>
</head>

<body onLoad="LoadSetting()">
<blockquote>
<h2>브로드캐스트 스톰 제어</h2>
<table border="0" width="500" cellspacing="0" cellpadding="0">
	<tr>
		<td><font size="2">브로드캐스트 스톰에 대한 설정을 할 수 있는 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>

<form action="proc/skb_bstorm_proc.php" method="POST" name="formBroadcastStormCtrl">
<input type="hidden" name="port" id="port" value="">
<table border="0" width="500" cellspacing="0" cellpadding="0">
	<tr>
		<td><font size=2><b><input type="checkbox" name="broadcast_storm_ctrl_enable" id="broadcast_storm_ctrl_enable" value="1"  onclick="updateState()">&nbsp;&nbsp;브로드캐스트 스톰 제어 사용</b></td>
	</tr>
	<tr>
		<td><font size=2><b>&nbsp;&nbsp;&nbsp;&nbsp;전송률: </b><input type="text" name="rate" id="rate" value="<?=$bstorm_cbs?>" size="7" maxlength="7">kbps/s </td>
	</tr>
	<tr>
		<td><font size="2"><?php
			for($i=1; $i < 5;$i++){
		?>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="lan<?=$i?>_port" id="lan<?=$i?>_port" value="1" onclick="port_to_bit()">LAN <?=$i?><br><br><?}?>
		&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="wan_port" id="wan_port" value="1">WAN</font></td>
	</tr>

</table>
<br>
<input type="submit" value="적용" name="apply" onclick="return saveChanges()">&nbsp;&nbsp;
<input type="button" value="취소" name="reset" onclick="LoadSetting()" >
<input type="hidden" value="/skb_bstorm.php" name="submit-url">
</form>

</blockquote>
</body>
</html>
