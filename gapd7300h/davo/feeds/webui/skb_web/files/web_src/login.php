<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$sys = new dvcfg();
	$sys->read("dvui");
	$captcha = $sys->search("dvui.system.captcha");

	$cfg = new dvcfg();
	$cfg->read("network","lan");
	$lanip = $cfg->search("network.lan.ipaddr");
	$local_ = explode(".",$lanip);
	$con_mode_ = "ext";
	$user_ = explode(".",$_SERVER['REMOTE_ADDR']);
	if($local_[0] == $user_[0] && $local_[1] == $user_[1] && $local_[2] == $user_[2]){
		$con_mode_ = "local";
	}
	dv_set_session("con_mode",$con_mode_);
	$uci = new uci();
	$uci->mode("get");
	$uci->get("network.wan|wireless.wifi0|wireless.vap00|wireless.wifi1|wireless.vap10|wireless.wifi2|wireless.vap20");
	$uci->run();
	$a = json_decode($uci->result());
	$wan_proto = std_get_val($a,"network.wan.proto");

	$ipaddr = "";
	$netmask = "";
	$gateway = "";
	$dns1 = "";
	$dns2 = "";
	$proto_string = "";
	if($wan_proto == "static"){
		$proto_string = "고정 IP 연결됨";
		$ipaddr = std_get_val($a,"network.wan.ipaddr");
		$dns = std_get_val($a,"network.wan.dns");
		$dns = explode(" ",$dns);
		$dns1 = $dns[0];
		$dns2 = $dns[1];
	}else{
		$proto_string = "유동 IP 연결됨";
		$syscall = new dvcmd();
		$syscall->add("ifconfig", dv_session("wan_port"),"!");
		$syscall->run();
		$rtn = $syscall->result()[0];
		$syscall->close();
		$arrif = explode("\n",$rtn);
		$ifface = array();
		for($i = 0 ; $i < count($arrif) ; $i++ ){
			if(preg_match("/^\s+\w+\s+\w+:(\d+.\d+.\d+.\d+)\s+\w+:\d+.\d+.\d+.\d+\s+\w+:(\d+.\d+.\d+.\d+)/",$arrif[$i],$d) == true) {
				$ipaddr = $d[1];
				$netmask = $d[2];
			}
		}
		
	}
	$dns = get_network_dns();
	$dns1 = $dns[0];
	$dns2 = $dns[1];
//	print_r(std_get_val($a,"network.wan.proto"));
	$wifi2 = "";
	$wifi5 = "";
	$ref = false;
	if(std_get_val($a,"wireless.vap20.ssid") == ""){
		if(std_get_val($a,"wireless.wifi1.disable") != "1"){
			$wifi2 = std_get_val($a,"wireless.vap10.ssid");
		}
	}else{
		$ref = true;
		if(std_get_val($a,"wireless.wifi2.disable") != "1"){
			$wifi2 = std_get_val($a,"wireless.vap20.ssid");
		}
	}
	if(std_get_val($a,"wireless.wifi0.disable") != "1"){
		$wifi5 = std_get_val($a,"wireless.vap00.ssid");
	}
	$syscall = new dvcmd();
	$syscall->add("wifi_info","ath0 freqlist | grep \* | sed 's/* //'","!");
	if($ref == true){
		$syscall->add("wifi_info","ath2 freqlist | grep \* | sed 's/* //'","!");
	}else{
		$syscall->add("wifi_info","ath1 freqlist | grep \* | sed 's/* //'","!");
	}
	$syscall->run();
	$wifi2_ch = rtrim($syscall->result()[1]);
	$wifi5_ch = rtrim($syscall->result()[0]);
	if($wifi2_ch == ""){
		$wifi2_ch = "Progress";
	}
	if($wifi5_ch == ""){
		$wifi5_ch = "Progress";
	}
	$syscall->close();
	$auto_up = 0;
	if(file_exists("/tmp/fw_up")){
		$auto_up = 1;
	}
//	"cat /sys/class/net/".$wan_port."/address"
//	echo getTimestamp();
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

function frmLoad()
{
    var http_obj = document.getElementsByName("username");
    http_obj[0].focus();

	if(self != parent)
	    top.location.assign("login.php");

   if(top.document.location.href.toString() != window.document.location.href.toString())
	   	top.location.assign("login.php");

	if(auto_up_flag == 1)
		show_auto_upgrade();
}

function clickApply(sel)
{
	/*
	if (document.forms[0].username.value == "") {
		alert("사용자 계정을 확인해 주세요.");
		document.forms[0].username.focus();
		return false;
	}
	if (document.forms[0].tmp_passwd.value == "") {
		alert("사용자 암호를 확인해 주세요.");
		document.forms[0].tmp_passwd.focus();
		return false;
	}*/
    document.forms[0].password.value = encode(document.forms[0].tmp_passwd.value);
	document.forms[0].hidden_action.value = 'Login';
    document.forms[0].tmp_passwd.value = '';

	//document.Login.submit();

    return true;

}

function show_auto_upgrade()
{
	if(nowCount %2)
		$("#auto_upgrade_info").css("color","white");
	else
		$("#auto_upgrade_info").css("color","red");

	if(nowCount < 1000){
		nowCount++;
		setTimeout('show_auto_upgrade()', 500);
	}
}
var proc = "proc/skb_login_proc.php";
var login_check = function(){
	<?php
		if($captcha == "0"){
			echo("login_form();\n");
			echo("return;\n");
		}
	?>
	var captcha_text_ = $("#captcha_text").val();
	if(captcha_text_ == ""){
		alert("그림문자를 입력해주세요.");
		$("#captcha_text").focus();
		return;
	}
	if(!check_xss(captcha_text_)){
		alert(xss_err_msg);
		$("#captcha_text").focus();
		return false;
	}
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'captcha';
	sobj['captcha_text'] = captcha_text_;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				login_form();
			}else{
				alert("그림문자를 확인해주세요.");
				$("#captcha_text").focus();
				return;
			}
//			location.reload();
		}
	});
}
var login_form = function(){
	document.forms[0].password.value = encode(document.forms[0].tmp_passwd.value);
	document.forms[0].hidden_action.value = 'Login';
	var user_pwd_ori_ = $("#tmp_passwd").val();
	document.forms[0].tmp_passwd.value = '';
	var user_id_ = $("#user_id").val();
	var user_pwd_ = $("#password").val();
	if("local"=="<?=$con_mode_?>"){
		$.cookie("shared_key","<?=bin2hex(openssl_random_pseudo_bytes(16));?>");
	}
	if(check_xss(user_id_) == false){
		alert(xss_err_msg);
		return;
	}
	if(check_xss(user_pwd_ori_) == false){
		alert(xss_err_msg);
		return;
	}
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'login';
	sobj["user_id"] = user_id_;
	sobj["user_pwd"] = user_pwd_;
	sobj['shard_key'] = $.cookie("shared_key");
//	sobj['dellist'] = dellist;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				$.cookie("magickey",parseInt(get_timestamp(),10));
				location.assign("/index.php");
			}else if(d == "2"){
				location.assign("/skb_passwd_change.php?user_id="+user_id_);
			}else{
				alert("로그인에 실패하였습니다.");
				$("#tmp_passwd").focus();
				return;
			}
//			location.reload();
		}
	});
}
var session_flag = true;
var session_ch = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'server_check';
//	sobj['dellist'] = dellist;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		"timeout":2000,
		success:function(d){
			if(d == "1"){
				return;
			}else{
//				location.assign("/");
				$("#captcha").attr("src",d);
			}
//			location.reload();
		},
		error:function(a,b,c){
			session_flag = false;
//			top.window.location.href="/skb_logout.php";
		},complete:function(){
//			d = null;
			sobj=null;
			dummyVal = null;
		}
		
	});
}
var reload_captcha = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'create_captcha';
//	sobj['dellist'] = dellist;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		"timeout":2000,
		success:function(d){
			$("#captcha").attr("src",d);
			return;
		},complete:function(){
			d = null;
			return;
		}
		
	});
}
$(document).ready(function(){
	$("#user_id").focus();
	<?php
		if($captcha != "0"){
			echo("setInterval(function(){\n");
			echo("\tsession_ch();\n");
			echo("},2000);");
		}
	?>
	reload_captcha();
	$.cookie("magickey",parseInt(get_timestamp(),10));
	var autoup = "<?=$auto_up?>";
	if(autoup == "1"){
		show_auto_upgrade();
	}
});
</script>
</head>
<body bgcolor="#E6E6E6" text="black" marginwidth="0" marginheight="0">
<form method="POST" name="Login">
<table border="0" cellpadding="0" cellspacing="0" width="100%" height="100%">
	<tr>
		<td width="100%" height="100%" align="center" valign="middle">
		    <table border="0" cellpadding="0" cellspacing="0" width="400" bgcolor="#A7A7A7">
		        <tr>
					<td width="400" align="center" bgcolor="white"><p>&nbsp;</p>
					</td>
				</tr>
				<tr>
					<td width="400" align="center" class="tbl_title" height="50">
					    <font color="white">
					        <b> 로그인 </b><br>
					    </font>
					</td>
				</tr>
				<tr height="10" bgcolor="white" ><td> &nbsp; </td></tr>
				<tr>
				    <td width="400"  bgcolor="white">
				        <p style="margin-left: 16pt;">
                        <label class='mn24'>  초기 상태의 사용자 암호는 매뉴얼에 있습니다.  </label>
    					<table border="0" cellpadding="0" cellspacing="1" width="360" bgcolor="#CCCCCC">
	    					<tr>
		    					<td width="360" bgcolor="white">
			    					<table border="0" cellpadding="0" cellspacing="1" width="360">
										<tr height="22">
											    <td width="120" bgcolor="#e2e7ed" class='mn24'><p>&nbsp;&nbsp;사용자 계정</p></td>
											    <td width="160" bgcolor="#F8F8F8" ><p>&nbsp;
											    <input type="text" style="width:120px;" name="user_id" id="user_id" value="" maxlength="30" tabindex="1">
											    </p></td>
											    <td width="80" bgcolor="#F8F8F8" >
											    </td>
										</tr>
										<tr height="22">
											    <td width="120" bgcolor="#e2e7ed" class='mn24'><p>&nbsp;&nbsp;사용자 암호</p></td>
											    <td width="160" bgcolor="#F8F8F8" ><p>&nbsp;
											    <input type="password" style="width:120px;" name="tmp_passwd" id="tmp_passwd" maxlength="30" tabindex="2" onkeypress='document.forms[0].password.value = encode(document.forms[0].tmp_passwd.value);if(event.keyCode  == 13){login_check();}'>
											    </p></td>
											    <td width="80" bgcolor="#F8F8F8" >
											    <p align="center">
											        <input type="hidden" name="hidden_action" value="login">
											        <input type="button" name='login' value='로그인' style="width:50px;" onclick='login_check();'>
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
				<tr>
					<td width="400"  bgcolor="white"><p style="margin-left: 16pt;"><label class='mn24'>  아래 이미지를  보이는 대로 입력해주세요.  </label>
					<table border="0" cellpadding="3" cellspacing="1" width="364" bgcolor="white" style="table-layout:fixed;word-wrap:break-word;">
						<tr>
							<td width="50%"><img id="captcha" src="" alt="CAPTCHA code""></td>
							<td>
								<button onclick="reload_captcha();" type="button" style="border:1px #ddd solid;width:90px;height:30px;border-radius:5px;">
								<i class="fa fa-refresh" aria-hidden="true">새로고침</i></button>
							</td>
						</tr>
						<tr>
							<td colspan="2"><input type="text" name="captcha_text" id="captcha_text" value="" maxlength="10" tabindex="3" onkeypress='document.forms[0].password.value = encode(document.forms[0].tmp_passwd.value);if(event.keyCode  == 13){login_check();}'></td>
						</tr>
					</table></p></td>
				</tr>
				<tr>
			    <td  bgcolor="white">
			    <p style="margin-left: 16pt;">
				<table border="0" cellpadding="3" cellspacing="1" width="364" bgcolor="white" style="table-layout:fixed;word-wrap:break-word;">
					<colgroup>
						<col style="width:140px" />
						<col style="width:224px" />
					</colgroup>
			        <tr>
				        <td height="10" bgcolor="#ffffff" colspan='2'></td>
			        </tr>
			        <tr>
	                    <td bgcolor="#3B9DCC" height='2' colspan='2'></td>
                    </tr>
					<tr>
						<td height='4' bgcolor="#ffffff" colspan='2'></td>
					</tr>
                    <tr>
	                    <td bgcolor="#e2e7ed" class='mn24'>
	                        &nbsp; 외부 IP 주소
	                    </td>
	                    <td bgcolor="#ffffff" class='mn24'>
	                        &nbsp;<?=$ipaddr?>
	                    </td>
                    </tr>
                    <tr>
	                    <td bgcolor="#e2e7ed" class='mn24'>
	                        &nbsp; DNS 서버
	                    </td>
	                    <td bgcolor="white" class='mn24'>
	                        &nbsp;<?=$dns1?><br>&nbsp;<?=$dns2?>
	                    </td>
                    </tr>
                    <tr>
	                    <td bgcolor="#e2e7ed" class='mn24'>
	                        &nbsp; 연결 상태
	                    </td>
	                    <td bgcolor="white" class='mn24'>
	                        &nbsp;<?=$proto_string?>
	                    </td>
                    </tr>
                    <tr>
	                    <td bgcolor="#e2e7ed" class='mn24'>
	                        &nbsp; 무선 SSID
	                    </td>
	                    <td bgcolor="white" class='mn24'>
	                    	&nbsp;2.4GHz&nbsp;:&nbsp;<?=$wifi2?><br>
	                    	&nbsp;5GHz&nbsp;:&nbsp;<?=$wifi5?>
	                    </td>
                    </tr>
                    <tr>
	                    <td bgcolor="#e2e7ed" class='mn24'>
	                        &nbsp; 무선 채널
	                    </td>
	                    <td bgcolor="white" class='mn24'>
	                    	<script>
	                    		
	                    	</script>
	                    	&nbsp;2.4GHz&nbsp;:&nbsp;<?=$wifi2_ch ?>
							<br>
	                    	&nbsp;5GHz&nbsp;:&nbsp;<?=$wifi5_ch ?>
	                    </td>
                    </tr>
                    <tr>
						<td bgcolor="#e2e7ed" class='mn24'>&nbsp; 소프트웨어 버전</td>
	                    <td bgcolor="white" class='mn24'>
							<script type="text/javascript">
							if( <?=$auto_up?> == 1)
								document.write("<b><span id=auto_upgrade_info style='color:red;'>&nbsp;펌웨어를 업그레이드 중입니다.<br>&nbsp;전원을 끄지말고 잠시<br>&nbsp;기다려 주시기 바랍니다.</span></b>");
							else
								document.write("&nbsp;<?=DEF_VERSION?>");
							</script>
	                    </td>
					</tr>
				<tr>
					<td height='4' bgcolor="white" colspan='2'></td>
				</tr>
				<tr>
		           <td bgcolor="3B9DCC" height='2' colspan='2'></td>
	            </tr>
				<tr>
					<td height='20' bgcolor="white" colspan='2'></td>
				</tr>
            </table>
		</td>
	</tr>
</table>
<input type="hidden" name="password" id="password" value=''>
</form>
</body>
</html>

