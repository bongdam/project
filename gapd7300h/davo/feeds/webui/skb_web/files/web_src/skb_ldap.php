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
<title>LDAP CFG 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"></script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script language="javascript">

var ldap_url_flag=0;
var server_url_flag=0;
var server_file_flag=0;
var pre_flag=0;

function click_field(selectObj) {
	if( (selectObj == "ldap_url") && (ldap_url_flag == 0) ){
		document.aupform.ldap_url.value = "";
		ldap_url_flag = 1;
	} else if( (selectObj == "server_url") && (server_url_flag == 0) ){
		document.aupform.server_url.value = "";
		server_url_flag = 1;
	} else if( (selectObj == "server_file") && (server_file_flag == 0) ){
		document.aupform.server_file.value = "";
		server_file_flag = 1;
	} else if( (selectObj == "pre") && (pre_flag == 0) ){
		document.aupform.pre.value = "";
		pre_flag = 1;
	}

}

function toggle() {
	if ( document.aupform.UseAutoup[0].checked == true) {
		document.aupform.UseAutoup[1].checked = false;
		document.aupform.UseAutoup[2].checked = false;
	}
	else if ( document.aupform.UseAutoup[1].checked == true) {
		document.aupform.UseAutoup[0].checked = false;
		document.aupform.UseAutoup[2].checked = false;
	}
	else {
		document.aupform.UseAutoup[0].checked == false;
		document.aupform.UseAutoup[1].checked = false;
	}
}

function toggle2() {
	if ( document.aupform.preUse.checked == true) {
		document.aupform.pre.disabled = false;
	} else {
		document.aupform.pre.disabled = true;
	}
}

function frmOnload() {
	var swms_enable = 1;
	var ldap_enable = 0;

	var UseAutoup = "1";

	if (UseAutoup == "2")
		document.aupform.UseAutoup[0].checked = true;
	else if (UseAutoup == "0")
		document.aupform.UseAutoup[1].checked = true;
	else
		document.aupform.UseAutoup[2].checked = true;

	document.aupform.ldap_url.value = "******************************";
	document.aupform.server_url.value = "******************************";
	document.aupform.server_file.value = "********************";
	document.aupform.preUse.checked = false;
	document.aupform.pre.value = "**********";

	if ( swms_enable == 1 || ldap_enable == 0 )
		alert("LDAP CFG는 자동 업그레이드에서 활성화 시켜야 정상 동작합니다");
}

function check_form() {

	return true;
}

function apply_set()
{
	var f=document.aupform;

	f.apply.disabled = true;

	f.submit();
	alert("설정이 적용되었습니다");
}

</script>
</head>
<body onload="frmOnload();">
<blockquote>
<b><font size=3 face="arial" color="#3c7A95">자동 업그레이드</font></b>
<table border=0 width="540" cellspacing=4 cellpadding=0>
<tr><td><font size=2><br><br>
 LDAP CFG 사용자 설정 페이지입니다.
</font></td></tr>
<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<form method=POST action=/boafrm/formLdap name="aupform" onSubmit="return check_form();">
	<table class="content">
		<tr>
			<td>LDAP CFG 서버 URL</td>
			<td><input type="text" name="ldap_url" size="50" maxlength="127" onclick="click_field('ldap_url')"></td>
		</tr>

		<tr>
			<td colspan=2>
				[사용자 설정]
			</td>
		</tr>
		<tr>
			<td>
				단말 업그레이드 실행여부:
			</td>
			<td>
				<input type="radio" name="UseAutoup" value="2" 2 onClick="toggle();"> 사용(수동설정)
				<input type="radio" name="UseAutoup" value="0" onClick="toggle();"> 사용안함
				<input type="radio" name="UseAutoup" value="1" onClick="toggle();"> LDAP CFG 설정
			</td>
		</tr>

		<tr>
			<td>펌웨어 URL</td>
			<td><input type="text" name="server_url" size="50" maxlength="127" onclick="click_field('server_url')"></td>
		</tr>

		<tr>
			<td>펌웨어 파일</td>
			<td><input type="text" name="server_file" size="50" maxlength="127" onclick="click_field('server_file')"></td>
		</tr>

		<tr>
			<td class="title">상대 경로 사용
				<input type="checkbox" name="preUse" value="1" onClick="toggle2();">
			</td>
			<td>
			<input type="text" name="pre" size="50" maxlength="127" onclick="click_field('pre')">(ex:"firmware?name=")
			</td>
		</tr>

	</table>
	<br><br>
	<input type="button" name="apply" value="적용" onClick="apply_set();">
</form>
</blockquote>
</body>
</html>
