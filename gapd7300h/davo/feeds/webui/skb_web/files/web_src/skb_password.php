<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>패스워드 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var proc = "proc/skb_password_proc.php";
function encode(sr)
{
   var cb64 = ''+ 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
   var out = '';
   var sub_len,len;
   var out_len;
   var src_len = sr.length;
   var sr_index=0;
   var len=0;
   out_len=0;
   if (src_len < 1 ) return '';
   if (sr=='') return '';

   for (len=0;len < src_len;sr_index+=3, len+=3)
   {

       sub_len = ( ( len + 3  < src_len ) ? 3: src_len - len);

       switch(sub_len)
       {
           case 3:
               out += cb64.charAt(sr.charCodeAt(sr_index)>>2);
               out += cb64.charAt(((sr.charCodeAt(sr_index) & 0x03) << 4) | ((sr.charCodeAt(sr_index+1) & 0xf0) >> 4));
               out += cb64.charAt(((sr.charCodeAt(sr_index+1) & 0x0f) << 2) | ((sr.charCodeAt(sr_index+2) & 0xc0) >> 6));
               out += cb64.charAt(sr.charCodeAt(sr_index+2) & 0x3f);
               break;
           case 2:
               out += cb64.charAt(sr.charCodeAt(sr_index)>>2);
               out += cb64.charAt(((sr.charCodeAt(sr_index) & 0x03) << 4) | ((sr.charCodeAt(sr_index+1) & 0xf0) >> 4));
               out += cb64.charAt((sr.charCodeAt(sr_index+1) & 0x0f) << 2);
               out += '=';
               break;
           case 1:
               out += cb64.charAt(sr.charCodeAt(sr_index)>>2);
               out += cb64.charAt((sr.charCodeAt(sr_index) & 0x03) << 4);
               out += '=';
               out += '=';
               break;
           default:
               break;
               /* do nothing*/
       }
   }
   return out;
}

function includeSpace(str)
{
  for (var i=0; i<str.length; i++) {
  	if ( str.charAt(i) == ' ' ) {
	  return true;
	}
  }
  return false;
}

function inputChanges()
{
  if ( document.password.newpass.value.length > 30){
    alert('비밀번호는 최대 30자까지 입력 가능합니다. 다시 입력하여 주십시오.');
    strLen = document.password.newpass.value.length;
    tmpStr = document.password.newpass.value;
    tmpStr = tmpStr.substr(0,strLen-1);
	document.password.newpass.value = tmpStr;
	document.password.newpass.focus();
	return;
  }
  if( document.password.confpass.value.length > 30){
    alert('비밀번호는 최대 30자까지 입력 가능합니다. 다시 입력하여 주십시오.');
    strLen = document.password.confpass.value.length;
    tmpStr = document.password.confpass.value;
    tmpStr = tmpStr.substr(0,strLen-1);
	document.password.confpass.value = tmpStr;
    document.password.confpass.focus();
	return;
  }
}

function saveChanges()
{
	var regPwd = /^.*(?=.*\d)(?=.*[a-zA-Z])(?=.*[^a-zA-Z0-9]).*$/;
	var ret;

	if ( document.password.newpass.value.length < 10 || document.password.newpass.value.length > 30 ||
		document.password.confpass.value.length < 10 || document.password.confpass.value.length > 30) {
		alert('비밀번호는 최소 10자 ~ 최대 30자까지 입력 가능합니다. 다시 입력하여 주십시오.');
		document.password.newpass.focus();
		return false;
	}
/*
	if ( includeSpace(document.password.newpass.value)) {
		alert('비밀번호에는 공백을 입력할 수 없습니다. 다시 입력하여 주십시오.');
		document.password.newpass.focus();
		return false;
	}
*/
	ret = saveChanges_passwd(document.password);
	if(ret == false)
		return false;

	ret = check_to_passwd(document.password.newpass.value);
  	if(!regPwd.test(document.password.newpass.value) ||  !(ret) ) {
  		alert('비밀번호는 영문, 숫자, 특수문자가 조합 되어야 합니다.\n특수문자는 `,~,!,@,#,$,%,^,&,*,(,),-,_,+,=,공백 만 사용 가능합니다.');
    	document.password.newpass.focus();
		return false;
  	}

	if ( document.password.newpass.value != document.password.confpass.value) {
		alert('비밀번호가 일치하지 않습니다. 확인하고 다시 입력하여 주십시오');
		document.password.newpass.focus();
		return false;
	}

	if (IsHtmlComment(document.password.newpass.value)) {
		alert('비밀번호에는 Html 주석문을 입력할 수 없습니다.!');
		document.password.newpass.focus();
		return false;
	}
	if (document.password.newpass.value.length == 0 ) {
		alert('비밀번호가 비어있습니다. 다시 입력하여 주십시오');
		document.password.newpass.focus();
		return false;
	}
	if(!check_xss(document.password.newpass.value)){
		alert(xss_err_msg);
		document.password.newpass.focus();
		return;
	}
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = "set_user_password";
	sobj['newpass'] = encode(document.password.newpass.value);
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				alert("적용되었습니다.");
				window.location.reload();
			}else{
				alert("적용되지 않았습니다.");
				return;
			}
		}
	});
	return true;

}

</script>
</head>

<BODY>
<blockquote>
<h2>비밀번호 설정</h2>

<form action="proc/skb_password_proc.php" method="POST" name="password">
<table border="0" cellspacing="4" width="500">
	<tr>
		<td colspan="2"><font size="2">웹서버 접속시 필요한 비밀번호를 설정하는 페이지입니다.</font></td>
	</tr>
	<tr>
		<td colspan="2"><hr size="1" noshade align="top"></td>
	</tr>
	<tr>
		<td width="100%" colspan="2"><font size="2">비밀 번호 설정 시 <b><font color="red">영문·숫자·특수문자를  포함  최소 10자 이상</font></b>으로 설정 바랍니다.</font></td>
	</tr>
	<tr>
		<td width="20%"><font size="2"><b>사용자 이름:</b></font></td>
		<td width="50%"><font size="2"><input type="text" name="username_" size="20" maxlength="31" value='admin' disabled></td>
	</tr>
	<tr>
		<td width="20%"><font size="2"><b>새 비밀번호:</b></font></td>
		<td width="50%"><font size="2"><input type="password" name="newpass" size="20" maxlength="31" onKeyup="inputChanges()"></td>
	</tr>
	<tr>
		<td width="20%"><font size="2"><b>새 비밀번호 확인:</b></font></td>
		<td width="50%"><font size="2"><input type="password" name="confpass" size="20" maxlength="31" onKeyup="inputChanges()"></td>
	</tr>
</table>
<input type="hidden" value="/skb_password.php" name="submit-url">
<p><input type="button" value="적용" name="save" onClick="return saveChanges()">&nbsp;&nbsp;
<input type="reset" value="  취소  " name="reset"></p>
</form>
<blockquote>
</body>
</html>


