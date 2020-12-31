<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	check_admin($isAdmin );
	$cfg = new dvcfg();
	$cfg->read("swms");
	$atup_info = $cfg->result("object");
?>
<html>
<head>
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>자동 업그레이드</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script>

var server_url_flag = 0;
var pre_flag = 0;
var datafile_flag = 0;

function click_field(selectObj) {
	if( (selectObj == "server_url") && (server_url_flag == 0) ){
		document.formAutoup.server_url.value = "";
		server_url_flag = 1;
	} else if( (selectObj == "datafile") && (datafile_flag == 0) ){
		document.formAutoup.datafile.value = "";
		datafile_flag = 1;
	} 
//	else if( (selectObj == "pre") && (pre_flag == 0) ){
//		document.formAutoup.pre.value = "";
//		pre_flag = 1;
//	}
}

function toggle() {
	if (document.formAutoup.UseAutoup[0].checked == true) {
		document.formAutoup.server_url.disabled = false;
//		document.formAutoup.pre.disabled = false;
		document.formAutoup.datafile.disabled = false;
		document.formAutoup.server_url.style.backgroundColor = 'white';
//		document.formAutoup.pre.style.backgroundColor = 'white';
		document.formAutoup.datafile.style.backgroundColor = 'white';

		document.formAutoup.server_url.value = "******************************";
//		document.formAutoup.pre.value = "**********";
		document.formAutoup.datafile.value = "********************";

	} else {
		document.formAutoup.server_url.disabled = true;
//		document.formAutoup.pre.disabled = true;
		document.formAutoup.datafile.disabled = true;
		document.formAutoup.server_url.style.backgroundColor = '#DCDCDC';
//		document.formAutoup.pre.style.backgroundColor = '#DCDCDC';
		document.formAutoup.datafile.style.backgroundColor = '#DCDCDC';
		server_url_flag = 0;
		pre_flag = 0;
		datafile_flag = 0;
	}
}


function check_form() {
	var server_url_ = $("#server_url").val();
	var datafile_ = $("#datafile").val();
	if(!check_xss(server_url_)){
		alert(xss_err_msg);
		$("#server_url").focus();
		return false;
	}
	if(!check_xss(datafile_)){
		alert(xss_err_msg);
		$("#datafile").focus();
		return false;
	}
	return true;
}

function change_type()
{
	toggle();
}
function resetForm()
{
	location=location;
}
$(document).ready(function(){
	var enable = "<?=get_json_val($atup_info,"swms.config.enable")?>";
	if(enable == "1"){
		$("#UseAutoup1").prop("checked",true);
	}else if(enable == "0"){
		$("#UseAutoup0").prop("checked",true);
	}else{
		$("#UseAutoup2").prop("checked",true);
	}
	toggle();
});
</script>
</head>
<body>
<blockquote>
<h2>자동 업그레이드</h2>
<table border="0" width="500" cellspacing="0" cellpadding="0">
	<tr>
		<td><font size="2">서버로부터 자동으로 업그레이드 할 수 있도록 설정하는 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>

<form action="proc/skb_auto_upgrade_proc.php" method="post" name="formAutoup" onSubmit="return check_form();">
	<table class="content">
		<tr>
			<td colspan="2">
			<font size=2>
				<input type="radio" name="UseAutoup" id="UseAutoup1" value="swms" onclick="change_type()"> SWMS
<!-- 				<input type="radio" name="UseAutoup" id="UseAutoup2" value="ldap" onclick="change_type()"> LDAP CFG -->
				<input type="radio" name="UseAutoup" id="UseAutoup0" value="disable" onclick="change_type()"> 사용안함
			</font>
			</td>
		</tr>
		<tr>
			<td><font size=2>서버 URL</td>
			<td><input type="text" name="server_url" id="server_url" size="60" maxlength="127" onclick="click_field('server_url');"></td>
		</tr>

<!-- 		<tr> -->
<!-- 			<td><font size=2>상대 경로</td> -->
<!-- 			<td><input type="text" name="pre" id="pre" size="50" maxlength="127" onclick="click_field('pre');"></td> -->
<!-- 		</tr> -->

		<tr>
			<td><font size=2>파일명</td>
			<td><input type="text" name="datafile" id="datafile" size="60" maxlength="63" onclick="click_field('datafile')"></td>
		</tr>

	</table>
	<input type="hidden" value="/skb_auto_upgrade.php" name="submit-url">
	<p><input type="submit" value="저장" name="save">&nbsp;&nbsp;
	<input type="reset" value="초기화" name="set"  onclick="resetForm()">
</form>
</blockquote>
</body>
</html>
