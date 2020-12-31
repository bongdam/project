<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	check_admin($isAdmin );
	$wan_no = dv_session("wan_no");
	$lan1_no = dv_session("lan_no");
	$uci = new uci();
	$uci->mode("get");
	$uci->get("network.mirroranalypt");
	$uci->get("network.mirrorptingress");
	$uci->get("network.mirrorptegress");
	$uci->run();
	$get = json_decode($uci->result(),true);
	$port_mirror_enable = 0;
	$start_no = 0;
	$end_no = 0;
	if($get["network.mirrorptingress.status"] == "enable"){
		$port_mirror_enable = 1;
		$start_no = $get["network.mirroranalypt.analyst_port"];
		$end_no = $get["network.mirrorptingress.ingress_port"];
	}
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">

<title>포트 미러링</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script>

var portMirrorEnable = "<?=$port_mirror_enable?>";
var portMirrorFrom = "<?=$end_no?>";
var portMirrorTo = "<?=$start_no?>";
var portMirrorMode = document.getElementsByName('portMirrorMode');

function saveClick()
{
//	if ( portMirrorMode[0].checked == true )
//    	alert('미러링 설정이 적용되었습니다.\n\n단말 웹 접속 위해서는 현재 사용중인 LAN 포트를 \n다른 포트로 옮긴 후, 접속 하시면 됩니다.\n\n');
//	else
//		alert('미러링 설정이 적용되었습니다.\n\n');	
	enableTextField(document.formPortMirror.port_from);
 	enableTextField(document.formPortMirror.port_to);
	return true;
}

function loading()
{
	if(portMirrorEnable == "1") {
		portMirrorMode[0].checked = true;
		portMirrorMode[1].checked = false;
		$("#port_from").val(portMirrorFrom);
		$("#port_to").val(portMirrorTo);
	} else {
		portMirrorMode[0].checked = false;
		portMirrorMode[1].checked = true;
		document.formPortMirror.port_from.selectedIndex = 0;
		document.formPortMirror.port_to.selectedIndex = 3;
	}
	updateState();
}


function updateState()
{
  if(portMirrorMode[0].checked) {	
 	enableTextField(document.formPortMirror.port_from);
 	enableTextField(document.formPortMirror.port_to);
  }
  else {
 	disableTextField(document.formPortMirror.port_from);
 	disableTextField(document.formPortMirror.port_to);
  }  
}


</script>
</head>

<body onload="loading()">
<blockquote>
<h2>포트 미러링</h2>
<table border="0" width="500" cellspacing="0" cellpadding="0">
<tr><td><font size="2"><br>
 특정 포트로 들어오는 네트워크 데이터를 해당 포트로 보내주는 설정을 할 수 있는 페이지입니다. 
</font></td></tr>
<tr><td><hr size="1" noshade align="top"></td></tr>
</table>

<form action="proc/skb_port_mirror_proc.php" method="POST" name="formPortMirror">
<input type="hidden" name="page" value="skb_port_mirror.php">
<table border="0" width="550">
<tr><td colspan="2"><font size=2><b>
   	<input type="radio" name="portMirrorMode" value="1"  onclick="updateState()" >&nbsp;사용&nbsp;&nbsp;
	<input type="radio" name="portMirrorMode" value="0" onclick="updateState()" >&nbsp;사용안함&nbsp;&nbsp;</b><br>
</td></tr>
<tr>
	<td><font size="2"><b>출발지</b>&nbsp;&nbsp;&nbsp;&nbsp;</font>
		<select name="port_from" id="port_from">
			<option value="<?=$wan_no?>">WAN</option>
			<option value="<?=$lan1_no?>" >LAN1</option>
			<option value="<?=$lan1_no+1?>" >LAN2</option>
			<option value="<?=$lan1_no+2?>" >LAN3</option>
			<option value="<?=$lan1_no+3?>" >LAN4</option>
		</select> &nbsp;&nbsp;&nbsp;&nbsp;
		<font size="2"><b>목적지</b>&nbsp;&nbsp;&nbsp;&nbsp;</font>
		<select name="port_to" id="port_to">
			<option value="<?=$lan1_no?>" >LAN1</option>
			<option value="<?=$lan1_no+1?>" >LAN2</option>
			<option value="<?=$lan1_no+2?>" >LAN3</option>
			<option value="<?=$lan1_no+3?>" >LAN4</option>
		</select>
	</td>
</tr>
<tr>
	<td><br>
	<input type="submit" value=" 적용 " name="save" onClick="return saveClick()">&nbsp;&nbsp;
	<input type="hidden" value="/skb_port_mirror.php" name="submit-url"></td>
</tr>
<script type="text/javascript"> updateState(); </script>
</table>
</form>
</blockquote>
</body>
</html>
