<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$user_id_ = dv_session("user_id");
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>Login</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<link href="inc/css/font-awesome.min.css" rel="stylesheet" type="text/css">
<style type='text/css'>
.mn24 {
	font-family: verdana, 돋움;
	font-size: 12px; color:285077;
}
</style>

<script language='javascript'>
var auto_up_flag = parseInt("0", 10);
var nowCount=0;
var ipv6_mode = 0;

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
var proc = "proc/skb_passwd_change_proc.php";

var change_passwd = function(){
	var regPwd = /^.*(?=.*\d)(?=.*[a-zA-Z])(?=.*[^a-zA-Z0-9]).*$/;
	document.forms[0].password.value = encode(document.forms[0].tmp_passwd.value);
	var user_id_ = $("#user_id").val();
	var user_pass_enc = $("#password").val();
	var user_pwd_ = $("#tmp_passwd").val();
	var user_pwd2_ = $("#tmp_passwd2").val();
	
	if(user_pwd_ == ""){
		alert("사용자 암호를 입력해주세요.");
		$("#tmp_passwd").focus();
		return;
	}
	if(user_pwd2_ == ""){
		alert("사용자 암호 확인을 입력해주세요.");
		$("#tmp_passwd2").focus();
		return;
	}
	if ( user_pwd_.length < 10 || user_pwd_.length > 30 ) {
		alert('비밀번호는 최소 10자 ~ 최대 30자까지 입력 가능합니다. 다시 입력하여 주십시오.');
		$("#tmp_passwd").focus();
		return false;
	}
	if(!regPwd.test(user_pwd_) ) {
  		alert('비밀번호는 영문, 숫자, 특수문자가 조합 되어야 합니다.\n특수문자는 `,~,!,@,#,$,%,^,&,*,(,),-,_,+,=,공백 만 사용 가능합니다.');
    	$("#tmp_passwd").focus();
		return false;
  	}
	if (IsHtmlComment(user_pwd_)) {
		alert('비밀번호에는 Html 주석문을 입력할 수 없습니다.!');
		$("#tmp_passwd").focus();
		return false;
	}
	document.forms[0].tmp_passwd.value = '';
	document.forms[0].tmp_passwd2.value = '';
	if(user_pwd_ != user_pwd2_){
		alert("사용자 암호가 일치하지 않습니다.");
		$("#tmp_passwd").focus();
		return;
	}
	if(check_xss(user_pwd_) == false){
		alert(xss_err_msg);
		return;
	}
	if(check_xss(user_pwd2_) == false){
		alert(xss_err_msg);
		return;
	}
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'change_password';
	sobj["user_id"] = user_id_;
	sobj["user_pwd"] = user_pass_enc;
//	sobj['dellist'] = dellist;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				alert("적용되었습니다.");
				$.cookie("magickey",parseInt(get_timestamp(),10));
				location.assign("/index.php");
			}else{
				alert("적용되지 않았습니다.");
				$("#tmp_passwd").focus();
				return;
			}
//			location.reload();
		}
	});
}
$(document).ready(function(){
	$("#tmp_passwd").focus();
});
</script>
</head>
<body bgcolor="#E6E6E6" text="black" marginwidth="0" marginheight="0">
<form method="POST" name="Login">
<table border="0" cellpadding="0" cellspacing="0" width="100%" height="100%">
	<tr>
		<td width="100%" height="100%" align="center" valign="middle">
		    <table border="0" cellpadding="0" cellspacing="0" width="480" bgcolor="#A7A7A7">
		        <tr>
					<td width="400" align="center" bgcolor="white"><p>&nbsp;</p>
					</td>
				</tr>
				<tr>
					<td width="400" align="center" class="tbl_title" height="50">
					    <font color="white">
					        <b> 패스워드 변경 </b><br>
					    </font>
					</td>
				</tr>
				<tr height="10" bgcolor="white" ><td> &nbsp; </td></tr>
				<tr>
				    <td width="400"  bgcolor="white">
				        <p style="margin-left: 16pt;">
                        <label class='mn24'><span style="color:red;">초기 사용자 암호를 변경 후 설정 페이지로 이동 할 수 있습니다.<br>
						비밀 번호 설정 시 영문·숫자·특수문자를 포함 최소 10자 이상으로 설정 바랍니다.</span></label>
    					<table border="0" cellpadding="0" cellspacing="1" width="360" bgcolor="#CCCCCC">
	    					<tr>
		    					<td width="360" bgcolor="white">
			    					<table border="0" cellpadding="0" cellspacing="1" width="360">
										<tr height="22">
											<td width="120" bgcolor="#e2e7ed" class='mn24'><p>&nbsp;&nbsp;사용자 계정</p></td>
											<td width="160" bgcolor="#F8F8F8" ><p>&nbsp;
											<input type="text" style="width:120px;" name="user_id" id="user_id" value="<?=$user_id_?>" maxlength="30" readonly>
											</p></td>
											<td width="80" bgcolor="#F8F8F8" ></td>
										</tr>
										<tr height="22">
											<td width="120" bgcolor="#e2e7ed" class='mn24'><p>&nbsp;&nbsp;사용자 암호</p></td>
											<td width="160" bgcolor="#F8F8F8" ><p>&nbsp;
											<input type="password" style="width:120px;" name="tmp_passwd" id="tmp_passwd" maxlength="30" tabindex="1" autofocus onkeypress='document.forms[0].password.value = encode(document.forms[0].tmp_passwd.value);if(event.keyCode  == 13){change_passwd();}'>
											</p></td>
											<td width="80" bgcolor="#F8F8F8" ></td>
										</tr>
										<tr height="22">
											<td width="120" bgcolor="#e2e7ed" class='mn24'><p>&nbsp;&nbsp;사용자 암호 확인</p></td>
											<td width="160" bgcolor="#F8F8F8" ><p>&nbsp;
											<input type="password" style="width:120px;" name="tmp_passwd2" id="tmp_passwd2" maxlength="30" tabindex="2">
											</p></td>
											<td width="80" bgcolor="#F8F8F8" >
											<p align="center">
												<input type="hidden" name="hidden_action" value="login">
												<input type="button" name='login' value='적용' style="width:50px;" onclick='change_passwd();'>
											</p>
											</td>
										</tr>
									</table>
								</td>
							</tr>
						</table>
						</p>
					</td>
				</tr>
            </table>
		</td>
	</tr>
</table>
<input type="hidden" name="password" id="password" value=''>
</form>
</body>
</html>

