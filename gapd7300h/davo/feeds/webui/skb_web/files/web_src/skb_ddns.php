<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$cfg = new dvcfg();
	$cfg->read("ddns","myddns_ipv4");
/*
ddns.myddns_ipv4.service_name='dyndns.com'
ddns.myddns_ipv4.domain='yourhost.example.com'
ddns.myddns_ipv4.username='your_username'
ddns.myddns_ipv4.password='your_password'
ddns.myddns_ipv4.interface='wan'
ddns.myddns_ipv4.ip_source='network'
ddns.myddns_ipv4.ip_network='wan'");
*/
//	print_r($cfg->result("object"));
	$ddns_enable = $cfg->search("ddns.myddns_ipv4.enabled");
	if($ddns_enable == ""){
		$ddns_enable = "0";
	}
	$ddns_host = $cfg->search("ddns.myddns_ipv4.service_name");
	$ddns_domain = $cfg->search("ddns.myddns_ipv4.domain");
	$ddns_userid = "";
	$ddns_user_pass = "";
	if($ddns_domain == ""){
		$ddns_domain = "host.dyndns.org";
	}
	$ddns_userid = $cfg->search("ddns.myddns_ipv4.username");
	$ddns_user_pass = $cfg->search("ddns.myddns_ipv4.password");
	if($ddns_enable == "0"){
		$ddns_domain = "host.dyndns.org";
		$ddns_userid = "";
		$ddns_user_pass = "";
	}
	
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>Time Zone Setting</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<link href="/style.css" rel="stylesheet" type="text/css">
</head>
<script>

function disableButton (button,val) {
  if (document.all || document.getElementById)
    button.disabled = val;
  else if (button) {
    button.oldOnClick = button.onclick;
    button.onclick = null;
    button.oldValue = button.value;
    button.value = 'DISABLED';
  }
}

function disableDdnsButton(val)
{
	disableButton(document.ddns.ddnsType, val);
	disableButton(document.ddns.domain, val);
	disableButton(document.ddns.username, val);
	disableButton(document.ddns.password, val);

}

function updateState()
{
	if(document.ddns.ddnsEnabled.checked)
		disableDdnsButton(false);
	else
		disableDdnsButton(true);
}

function ddns_saveChanges()
{
	form = document.ddns ;
	if(form.ddnsEnabled.checked){
		if(form.domain.value == ""){
			alert("Domain Name can't be empty");
			form.domain.focus();
			return false ;
		}
		if(!check_xss(form.domain.value)){
			alert(xss_err_msg);
			form.domain.focus();
			return false;
		}
		if(form.username.value == ""){
			alert("User Name/Email can't be empty");
			form.username.focus();
			return false ;
		}
		if(!check_xss(form.username.value)){
			alert(xss_err_msg);
			form.username.focus();
			return false;
		}
		if(form.password.value == ""){
			alert("Password/Key can't be empty");
			form.password.focus();
			return false ;
		}
		if(!check_xss(form.password.value)){
			alert(xss_err_msg);
			form.password.focus();
			return false;
		}
	}
	return true;
}

function init()
{
	//var cf = document.forms[0];
	var cf = document.ddns;
	var EnableDDNS = <?=$ddns_enable?>;

    	if(EnableDDNS == 1) 
        	cf.ddnsEnabled.checked = true;
        else
        	cf.ddnsEnabled.checked = false;
//	cf.ddnsType.selectedIndex = 0;
	updateState();
}
</script>

<body onload="init();">
<blockquote>
<h2>Dynamic DNS 설정</h2>


<table border=0 width="500" cellspacing=0 cellpadding=0>
  <tr><font size="2">
	Dynamic DNS 서비스를 위한 페이지 입니다.
  </tr>
  <tr><hr size=1 noshade align=top></tr>
</table>
<form action="proc/skb_ddns_proc.php" method="post" name="ddns">
<table border="0" width="600">

	<tr><td colspan="2"><font size="2"><b>
		<input type="checkbox" name="ddnsEnabled" 
		value="1" onclick="updateState()">&nbsp;&nbsp;DDNS 사용하기</b><br>
	    </td>
	</tr>
	<tr ><td height=10> </td> </tr>
	<tr>
	<td width ="20%">
	<font size="2"> <b> 서비스 공급자 : </b> </font>
	</td>
	<td width ="85%">
		<select name="ddnsType">
			<option value="dyndns.org" <?php if($ddns_host == "dydns.com"){echo("selected");}?> >DynDNS </option>
			<option value="no-ip.com" <?php if($ddns_host == "no-ip.com"){echo("selected");}?>>NO-IP</option>
		</select>
	</td>
	</tr>
	<tr><td width="20%"><font size="2"> <b>도메인 이름 : </b> </font></td>
	    <td width="85%">
 			<font size="2"><input type="text" name="domain" id="domain" size="20" maxlength="50" value="<?=$ddns_domain?>"></font>
	    </td>
	</tr>
	<tr>
	<td width ="20%">
	<font size=1.5> <b> 사용자 이름/이메일 : </b> </font>
	</td>
	<td width ="85%">
		<font size="2"><input type="text" name="username" id="username" size="20" maxlength="50" value="<?=$ddns_userid?>"></font>
	</td>
	</tr>
	
	<tr>
	<td width ="20%">
	<font size="2"> <b> 비밀번호/키: </b> </font>
	</td>
	<td width ="85%">
		<font size="2"><input type="password" name="password" id="password" size="20" maxlength="30" value="<?=$ddns_user_pass?>"></font>
	</td>
	</tr>
	<tr>
		<td  height =5>
		</td>
	</tr>
</table>
  <p>
  <input type="hidden" value="/skb_ddns.php" name="submit-url">
  <input type="submit" value="적용" name="apply" onClick="return ddns_saveChanges()">
&nbsp;&nbsp;
  <input type="reset" value="초기화" name="reset" >
</form>
</blockquote>
</font>
</body>

</html>
