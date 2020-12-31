<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/func/qca_common.php");
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
	}else{
		$wifi2_ch = $wifi2_ch;
	}
	if($wifi5_ch == ""){
		$wifi5_ch = "Progress";
	}else{
		$wifi5_ch = $wifi5_ch;
	}
	$auto_up = 0;
	if(file_exists("/tmp/fw_up")){
		$auto_up = 1;
	}
?>
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="">
<meta name="author" content="">
<?=cr_header();?>
<!-- jQuery -->
<script type="text/javascript">
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
var proc = "/proc/skb_login_proc.php";
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
				location.assign("/pages/index.php");
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
<body>

	<div class="container">
		<div class="row">
			<div class="col-md-4 col-md-offset-4">
				<div class="login-panel panel panel-primary">
					<div class="panel-heading">
						<h3 class="panel-title">Please Sign In</h3>
					</div>
					<div class="panel-body">
						<form name="frm" method="post">
							<input type="hidden" name="password" id="password" value=''>
							<input type="hidden" name="hidden_action" value="login">
							<fieldset>
								<div class="form-group">
									<input class="form-control" placeholder="User ID" name="user_id" id="user_id" type="text" maxlength="30" tabindex="1" autofocus>
								</div>
								<div class="form-group">
									<input class="form-control" placeholder="Password" type="password" value="" name="tmp_passwd" id="tmp_passwd" maxlength="30" tabindex="2" onkeypress='document.forms[0].password.value = encode(document.forms[0].tmp_passwd.value);if(event.keyCode  == 13){login_check();}'>
								</div>
<!-- 								<div class="form-group"> -->
<!-- 									아래 이미지를  보이는 대로 입력해주세요. -->
<!-- 								</div> -->
								<div class="form-group">
									<input class="form-control" placeholder="아래 이미지를  보이는 대로 입력해주세요." name="captcha_text" id="captcha_text" value="" maxlength="10" tabindex="3" onkeypress="if(event.keyCode  == 13){login_check();}">
								</div>
								<div class="form-group">
									<img id="captcha" src="" alt="CAPTCHA code">&nbsp;&nbsp;<button onclick="reload_captcha();" type="button" style="border:1px #ddd solid;width:90px;height:30px;border-radius:5px;">
								<i class="fa fa-refresh" aria-hidden="true">새로고침</i></button>
								</div>
								
<!-- 								<div class="checkbox"> -->
<!-- 									<label> -->
<!-- 										<input name="remember" type="checkbox" value="Remember Me">Remember Me -->
<!-- 									</label> -->
<!-- 								</div> -->
								<!-- Change this to a button or input when using this as a form -->
								<button type="button" class="btn btn-lg btn-success btn-block" onclick='login_check();'>Login</button>
							</fieldset>
							<br>
							<table class="table table-condensed">
							<tbody>
								<tr>
									<td class="info">외부 IP 주소</td>
									<td><?=$ipaddr?></td>
								</tr>
								<tr>
									<td class="info">DNS 서버</td>
									<td>&nbsp;<?=$dns1?><br>&nbsp;<?=$dns2?></td>
								</tr>
								<tr>
									<td class="info">연결 상태</td>
									<td><?=$proto_string?></td>
								</tr>
								<tr>
									<td class="info">무선 SSID</td>
									<td><small>&nbsp;2.4GHz&nbsp;:&nbsp;<?=$wifi2?><br>
									&nbsp;5GHz&nbsp;:&nbsp;<?=$wifi5?></small></td>
								</tr>
								<tr>
									<td class="info"> 무선 채널</td>
									<td><small>&nbsp;2.4GHz&nbsp;:&nbsp;<?=$wifi2_ch ?><br>
									&nbsp;5GHz&nbsp;:&nbsp;<?=$wifi5_ch ?></small></td>
								</tr>
								<tr>
									<td class="info"> 소프트웨어 버전</td>
									<td><script type="text/javascript">
									if( <?=$auto_up?> == 1)
										document.write("<b><span id=auto_upgrade_info style='color:red;'>&nbsp;펌웨어를 업그레이드 중입니다.<br>&nbsp;전원을 끄지말고 잠시<br>&nbsp;기다려 주시기 바랍니다.</span></b>");
									else
										document.write("&nbsp;<?=DEF_VERSION?>");
									</script></td>
								</tr>
								<tr>
									<td></td>
									<td></td>
								</tr>
							</tbody>
							</table>
						</form>
					</div>
				</div>
			</div>
		</div>
	</div>

	
<?=cr_footer()?>
</body>

</html>
