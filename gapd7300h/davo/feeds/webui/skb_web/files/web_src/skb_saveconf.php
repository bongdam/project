<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$act = dv_post("act");
	if($act == "reboot"){
		$syscall = new dvcmd();
		$syscall->add("reboot");
		$syscall->run("fast");
		$syscall->close();
	}elseif($act == "factory"){
		$syscall = new dvcmd();
		$syscall->add("restore"," factory","!");
		$syscall->run("fast");
		$syscall->close();
	}
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">

<title>Save/Reload Setting</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var proc = "proc/skb_saveconf_proc.php";
function resetClick()
{
	$("#act").val("factory");
	document.saveConfig.submit();
}
function rebootClick()
{
	$("#act").val("reboot");
	document.saveConfig.submit();
}

</script>

</head>
<body>
<blockquote>
<h2>재부팅/초기화</h2>
<form action="proc/skb_saveconf_proc.php" method="POST" name="saveConfig">
  <table border="0" cellspacing="4" width="500">
  <tr><font size="2">
장비를 재부팅하거나 초기화 설정을 할 수 있는 페이지 입니다.
  </tr>
  <tr><hr size=1 noshade align="top"></tr>
   
  <input type="hidden" name="act" id="act" value="">
  <tr>
    <td width="32%"><font size="2"><b>기본 설정으로 초기화:</b></td>
    <td width="30%"><font size="2"><input type="submit" id="btn_reset" name="btn_reset" value="초기화" onclick="resetClick()">
  </td></tr>
  <tr>
	 <td width="32%"><font size="2"><b>재부팅 하기:</b></td>
	 <td width="30%"><font size="2"><input type="submit" id="btn_reboot" name="btn_reboot" value="재시작" onclick="rebootClick()">
	 </td></tr>

</table>
</form>
</blockquote>
</body>
</html>
