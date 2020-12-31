<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$uci = new uci();
	$uci->mode("get");
	$uci->get("network.miscframemaxsize");
	$uci->run();
	$jumbo = 0;
	$jumbo_size = 0;
	$get = json_decode($uci->result(),true);
	if(count($get) != 0){
		$jumbo = 1;
		$jumbo_size = $get["network.miscframemaxsize.frame_max_size"];
		if($jumbo_size == ""){
			$jumbo_size = 0;
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
<title>점보 프레임 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">

function init_load()
{
	var enable = parseInt(<?=$jumbo?>, 10);
	var frmsize = parseInt(<?=$jumbo_size?>, 10);
	if (enable == 0) {
		document.formJumbo.jumbo_size.selectedIndex=0;
	} else if (enable == 1 && frmsize == 2290){
		document.formJumbo.jumbo_size.selectedIndex=1;
	}
	/* else if (enable == 1 && frmsize == 16000){
		document.formJumbo.jumbo_size.selectedIndex=2;
	}*/
}

function save_valid()
{
	if (document.formJumbo.jumbo_size.selectedIndex == 0) {
		document.formJumbo.jumbo_enable.value = 0;
	} else {
		document.formJumbo.jumbo_enable.value = 1;
	}
	document.formJumbo.submit();
}

function resetClick()
{
	document.location.assign("skb_jumbo.php");
}

</script>
</head>
<blockquote>
<body onload="init_load();">
<b><font size=3 face="arial" color="#3c7A95">점보 프레임</font></b>
<table border=0 width="650" cellspacing="4" cellpadding="0">
<tr><td><font size="2"><br>
 Jumbo frame (2000byte 이상 L2-overhead포함)을 처리를 위한 설정 페이지입니다.
</font></td></tr>
<tr><td><hr size=1 noshade align="top"></td></tr>
</table>

<form name="formJumbo" action="proc/skb_jumbo_proc.php" method="POST">
	<input type="hidden" name="jumbo_enable" value="" >
	<table border="0" width="650" cellspacing="0" cellpadding="0">
		<tr>
			<td width="15%" align="center">
				&nbsp;선택 :
			</td>
			<td align="left">&nbsp;&nbsp;&nbsp;
				<select name="jumbo_size" id="jumbo_size" >
    			<option value="1500">Disable</option>
    			<option value="2290">2290 Byte</option>
    			<!--option value=16000>16000 Byte</option-->
    		</select>
				<!--input type="checkbox" name="jumbo_check" value="1" -->
			</td>
		</tr>
	</table>
	<br>
	<input type="button" value="적용" name="save" onclick="save_valid();">
	<input type="hidden" value="/skb_jumbo.php" name="submit-url" >
	<input type="reset" value="취소" name="reset" onclick="resetClick();">
</form>
</blockquote>

</body>
</html>
