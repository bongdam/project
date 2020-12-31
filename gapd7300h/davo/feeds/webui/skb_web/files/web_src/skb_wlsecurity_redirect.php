<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	check_admin($isAdmin );
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>무선 인터넷 웹 리디렉션 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<style>
.on {display:on}
.off {display:none}
.bggrey {
	BACKGROUND: #FFFFFF
}
</style>
<script>

var wlan_idx=1;
var wlan_mode = 0;
//autoconf[wlan_idx]= 0;

function ValidateForm(passForm, reset)
{
	if (reset) {
		passForm.reset();
	}
	else {
		passForm.submit();
	}
}

function RedirectSelected()
{

	var redir_enable = document.getElementsByName('redirect_enable');
	var redir_enable_value = "0";

	if(wlan_idx)
		document.formRedirEncrypt.Wlanintf.options[0].selected = true;
	else
		document.formRedirEncrypt.Wlanintf.options[1].selected = true;

	if(redir_enable_value.indexOf("1",0)>-1){
		redir_enable[0].checked = true;
		redir_enable[1].checked = false;
	}
	else {
		redir_enable[0].checked = false;
		redir_enable[1].checked = true;
	}

	get_by_id("redirection_host").value = "wing.skbroadband.com";

	get_by_id("allowed_list_0").value = "cs.skbroadband.com";
	get_by_id("allowed_list_1").value = "service.skbroadband.com";
	get_by_id("allowed_list_2").value = "log.skbroadband.com";
	get_by_id("allowed_list_3").value = "www.skbroadband.com";
	get_by_id("allowed_list_4").value = "";
}
function page_change(selectObj)
{
	if (selectObj.value==1)
		location.href='wlan_redriect.php?redirect-url=skb_wlsecurity_redirect.php&wlan_id=1';
	else
		location.href='wlan_redriect.php?redirect-url=skb_wlsecurity_redirect.php&wlan_id=0';
}
function resetForm()
{
	document.location.assign("skb_wlsecurity_redirect.php");
}
</script>
</head>

<body onload="RedirectSelected();">
<blockquote>
<b><font size=3 face="arial" color="#3c7A95">웹 리디렉션 설정 -
<script>
	 if (1 == 1)
	 	document.write(" 2.4G");
	 else
	 	document.write(" 5G");
</script></font></b>
<table border=0 width="540" cellspacing=4 cellpadding=0>
<tr><td><font size=2><br>
 무선 인터넷에 연결 실패시 보여줄 사이트를 설정하는 페이지입니다.
</font></td></tr>
<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<form action=/boafrm/formRedirWlEncrypt method=POST name="formRedirEncrypt">
<table width="400" border="0">
 <tr>
	<td width="30%"><font size="2"><b>무선:</b></font></td>
	<td width="70%">
		<select name="Wlanintf" id="Wlanintf" onChange="page_change(this)">
			<option value=1>2.4 GHz</option>
			<option value=0>5 GHz</option>
		</select>
	</td>
</tr>
<tr><td colspan="2" id="redirection_enable">
	<font size=2 face="arial" > <input type="radio"  name="redirect_enable" value="ON">사용</font> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
	<font size=2 face="arial" > <input type="radio"  name="redirect_enable" value="OFF">사용안함</font><br></td></tr>
<tr><td width="110"><font size=2 face="arial" >연결 URL:</font></td>
	<td><input id="redirection_host" name="redirect_host" type="text" size="30" maxlength="50" value=""></td></tr>
<tr><td valign="top" width="110">
	<font size="2" face="arial" >허용 URL:</font></td>
	<td valign="top">
	<input  id="allowed_list_0" name="allow_list_0" type="text" size="30" maxlength="50" value="">
	<input  id="allowed_list_1" name="allow_list_1" type="text" size="30" maxlength="50" value="">
	<input  id="allowed_list_2" name="allow_list_2" type="text" size="30" maxlength="50" value="">
	<input  id="allowed_list_3" name="allow_list_3" type="text" size="30" maxlength="50" value="">
	<input  id="allowed_list_4" name="allow_list_4" type="text" size="30" maxlength="50" value="">
	</td></tr>
<tr><td colspan="2"><br>
	<input type="button" value="적용" name="save" onClick="ValidateForm(document.formRedirEncrypt, 0);">&nbsp;&nbsp;&nbsp;
	<input type="button" value="취소" name="reset" onclick="resetForm();"></td></tr>
</table>

<input type="hidden" value="/skb_wlsecurity_redirect.php" name="submit-url">

</form>
</blockquote>
</body>
</html>
