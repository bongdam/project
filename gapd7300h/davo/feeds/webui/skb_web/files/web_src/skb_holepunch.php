<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	check_admin($isAdmin );
	$holepunch_enable = "";
	$uci = new uci();
	$uci->mode("get");
	$uci->get("holepunch.opts");
	$uci->run();
	$hole = json_decode($uci->result(),true);
	if($hole["holepunch.opts.holepunch_enabled"] == "1"){
		$holepunch_enable = " checked";
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
<title>홀펀치 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">

var hole_server_flag = 0;
var hole_port_flag = 0;

function click_field(selectObj) {
	if( (selectObj == "holepunch_server") && (hole_server_flag == 0) ){
		document.holepunch.holepunch_server.value  = "";
		hole_server_flag = 1;
	} else if( (selectObj == "holepunch_port") && (hole_port_flag == 0) ){
		document.holepunch.holepunch_port.value = "";
		hole_port_flag = 1;
	}
}

function presskey_field(selectObj) {
	if( (selectObj == "holepunch_port") && (hole_port_flag == 0) ){
		hole_port_flag = 1;
	}
}

function update() {
	var server = document.getElementById('holepunch_server');
	var ports = document.getElementById('holepunch_port');

	if(document.holepunch.holepunch_enabled.checked == true) {
		server.disabled = false;
		ports.disabled = false;
	} else {
		server.disabled = true;
		ports.disabled = true;
	}
}

function init() {

	document.holepunch.holepunch_server.value = "*************************";
	document.holepunch.holepunch_port.value = "*****";

	update();
}

function resetClick()
{
	document.location.reload();
}

function valid_check(formholepunch) {
	var hole_url = formholepunch.holepunch_server.value;
	var hole_port = formholepunch.holepunch_port.value;
	var i;
	if(hole_url =="") {
		alert("Control Server 가 비어있습니다. 주소를 입력해 주세요");
		return false;
	}
	if(!check_xss(hole_url)){
		alert(xss_err_msg);
		$("#holepunch_server").focus();
		return false;
	}

	if(hole_port =="") {
		alert("Control Port 가 비어있습니다. 주소를 입력해 주세요");
		return false;
	}

	if (hole_port_flag == 1) {
		if (i != hole_port.length) {
			if(!IsDigit(hole_port)) {
				alert("Control Port 에는 숫자만 입력가능합니다.");
				return false;
			}
		}
	}

	if(parseInt(hole_port) < 1 ||  parseInt(hole_port) > 65535) {
		alert("포트 번호가 올바르지 않습니다! 1에서 65535 사이의 숫자를 입력해야 합니다.");
		return false;
	}

	alert("설정되었습니다.");
	formholepunch.submit();
}

</script>
</head>
<body onload="init();">
<blockquote>
<h2>Holepunch 설정</h2>
<table border=0 width="540" cellspacing="4" cellpadding="0">
	<tr>
		<td><font size="2">Holepunch 설정 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size=1 noshade align=top></td>
	</tr>
</table>
<form action="proc/skb_holepunch_proc.php" method="POST" name="holepunch">
<br>
<fieldset style="border-right: #000000 1px solid; padding-right: 10px; border-top: #000000 1px solid; padding-left: 10px; padding-bottom: 5px; border-left: #000000 1px solid; width: 480px; padding-top: 0px; border-bottom: #000000 1px solid; "><legend>holepunch 서비스</legend>
	<table border="0" width=540>
		<tr>
			<td width="100%"><font size="2"><b><input type="checkbox" name="holepunch_enabled" id="holepunch_enabled" value="1" onclick="update();" <?=$holepunch_enable?>>&nbsp;holepunch 사용</b></font></td>
		</tr>
		<tr>
			<td width="100%"><font size="2"><b>&nbsp;&nbsp;Control Server : </b>&nbsp;&nbsp;<input type="text" name="holepunch_server" id="holepunch_server" value="" size="45" maxlength="127" onclick="click_field('holepunch_server')"></font></td>
		</tr>

		<tr>
			<td width="100%"><font size="2"><b>&nbsp;&nbsp;Control Port : </b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="text" id="cport" name="holepunch_port" value=""  size="5" maxlength="5" onclick="click_field('holepunch_port')" onkeypress="presskey_field('holepunch_port');"></font></td>
		</tr>
	</table>
</fieldset>

<table>
	<tr>
		<td><br>&nbsp;&nbsp;<input type="button" value="적용" name="save" onclick="valid_check(this.form);">
		&nbsp;&nbsp;<input type='reset' name='reset' value='취소' onClick="resetClick()"></td>
	</tr>
</table>
<input type="hidden" value="/skb_holepunch.php" name="submit-url">
</form>
</blockquote>
</body>
</html>
