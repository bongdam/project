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
<title>WAN Interface IPv6 Setup</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<link href="/style.css" rel="stylesheet" type="text/css">
<style>
.on {display:on}
.off {display:none}
</style>

<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<SCRIPT>
var autoconfig_method = 0;
var dns_method = 0;

function resetClicked()
{
	document.location.assign("skb_ipv6tcpipwan.php");
}

function disableDNSinput()
{
   document.tcpip.x_ipv6_manual_dns1.value="";
   document.tcpip.x_ipv6_manual_dns2.value="";
   disableTextField(document.tcpip.x_ipv6_manual_dns1);
   disableTextField(document.tcpip.x_ipv6_manual_dns2);
}

function enableDNSinput()
{
   enableTextField(document.tcpip.x_ipv6_manual_dns1);
   enableTextField(document.tcpip.x_ipv6_manual_dns2);
}

function autoDNSclicked()
{
  disableDNSinput();
}

function manualDNSclicked()
{
  enableDNSinput();
}

function ipv6_setup_selection(field)
{
	if(!document.getElementById){
		alert("오류! 웹브라우저가 CSS를 지원하지 않습니다!");
		return;
	}

	if(field.selectedIndex == 1){//MANUAL
		document.tcpip.x_ipv6_dns_method[0].disabled=true;
		enableDNSinput();
		document.tcpip.x_ipv6_dns_method[1].checked=true;
		document.tcpip.x_ipv6_manual_addr.disabled=false;
		document.tcpip.x_ipv6_manual_prefix_len.disabled=false;
		document.tcpip.x_ipv6_manual_gateway.disabled=false;
	}
	else {//AUTO
		document.tcpip.x_ipv6_dns_method[0].disabled=false;
		if(document.tcpip.x_ipv6_dns_method[0].checked)
			disableDNSinput();
		document.tcpip.x_ipv6_manual_addr.value="";
		document.tcpip.x_ipv6_manual_prefix_len.value="";
		document.tcpip.x_ipv6_manual_gateway.value="";
		document.tcpip.x_ipv6_manual_addr.disabled=true;
		document.tcpip.x_ipv6_manual_prefix_len.disabled=true;
		document.tcpip.x_ipv6_manual_gateway.disabled=true;
	}
}

function checkIpv6Validation(formName)
{
	if ( document.tcpip.x_ipv6_autoconfig_method.selectedIndex == 1){
		if (formName.x_ipv6_manual_addr.value == "") {
			alert("IP 주소 값을 입력 해 주세요.");
			formName.x_ipv6_manual_addr.focus();
			return false;
		}

		if (formName.x_ipv6_manual_prefix_len.value != "") {
			if (!IsDigit(formName.x_ipv6_manual_prefix_len.value)) {
            	alert('Prefix 값은 숫자만 입력하세요.');
            	formName.x_ipv6_manual_prefix_len.focus();
            	return false;
        	}
			if (parseInt(formName.x_ipv6_manual_prefix_len.value) < 1 ||
				parseInt(formName.x_ipv6_manual_prefix_len.value) > 127 ) {
				alert("Prefix 값은 1 ~ 127 까지여야 합니다.");
				formName.x_ipv6_manual_prefix_len.focus();
				return false;
			}
		} else {
			alert("Prefix 길이 값을 입력 해 주세요.");
			formName.x_ipv6_manual_prefix_len.focus();
			return false;
		}
	}

	if (formName.x_ipv6_dns_method[1].checked) {
		if (formName.x_ipv6_manual_dns1.value == "" && formName.x_ipv6_manual_dns2.value == "") {
			alert("적어도 DNS 주소가 하나 필요합니다.");
			return false;
		}
	}
	document.tcpip.submit();
}

function init_load()
{
	if ( 0 )
		document.tcpip.ipv6_passthru_enabled.checked = true;
}
</SCRIPT>
</head>

<body onload="init_load();">
<blockquote>
<h2>인터넷 설정</h2>
<form action=/boafrm/formIpv6Setup method=POST name="tcpip">

<table border=0 width="550" cellspacing=0 cellpadding=0>
  <tr><font size=2>
	IPv6 주소 설정을 위한 페이지입니다.
  </tr>
  <tr><hr size=1 noshade align=top></tr>
  <tr>
</table>
<FIELDSET style="BORDER-RIGHT: #000000 1px solid; PADDING-RIGHT: 10px; BORDER-TOP: #000000 1px solid; PADDING-LEFT: 10px; PADDING-BOTTOM: 5px; BORDER-LEFT: #000000 1px solid; WIDTH: 480px; PADDING-TOP: 0px; BORDER-BOTTOM: #000000 1px solid; "><LEGEND>IPv6 설정</LEGEND>
	<span id = "wanAccType" class = "on">
	  <table border="0" width=500>
	    <tr>
	       <td width="30%" height=40><font size=2><b>IPv6 방식선택:</b></td>
			<td width="70%"><font size=2>
			<script>
				document.write('<select size="1" name="x_ipv6_autoconfig_method" onChange="ipv6_setup_selection(this)">');
				if(autoconfig_method){
					document.write('<option value="0">자동</option>');
					document.write('<option value="1" selected="selected">수동</option>');
				}else{
					document.write('<option value="0" selected="selected">자동</option>');
					document.write('<option value="1">수동</option>');
				}
				document.write('</select>');
			</script>
			</td>
	    </tr>
	  </table>
	</span>

	<span id = "manual_div" class = "on" >
		<table border="0" width=500>
			<tr>
				<td width="30%"><font size=2><b>IPv6 주소:</b></td>
				<td width="70%"><font size=2><input type="text" name="x_ipv6_manual_addr" size="39" maxlength="39" value=""></td>
			</tr>
			<tr>
				<td width="30%"><font size=2><b>Prefix 길이:</b></td>
				<td width="70%"><font size=2><input type="text" name="x_ipv6_manual_prefix_len" size="3" maxlength="3" value=""></td>
			</tr>
			<tr>
				<td width="30%"><font size=2><b>기본 게이트웨이:</b></td>
				<td width="70%"><font size=2><input type="text" name="x_ipv6_manual_gateway" size="39" maxlength="39" value=""></td>
			</tr>
		</table>
	</span>

	<span id = "ipv6_dns_method_div" class = "on" >
		<table border="0" width=500>
			<script>
				if(dns_method){
					document.write('\
						<tr>\
							<td width="100%" colspan="2"><font size=2>\
								<b><input type="radio" value="0" name="x_ipv6_dns_method" onClick="autoDNSclicked()">자동으로 DNS 서버 주소 받기</b>\
							</td>\
						</tr>\
						<tr>\
							<td width="100%" colspan="2"><font size=2>\
								<b><input type="radio" value="1" name="x_ipv6_dns_method" checked="checked" onClick="manualDNSclicked()">다음 DNS 서버 주소 사용</b>\
							</td>\
						</tr>');
				} else{
					document.write('\
						<tr>\
							<td width="100%" colspan="2"><font size=2>\
								<b><input type="radio" value="0" name="x_ipv6_dns_method" checked="checked" onClick="autoDNSclicked()">자동으로 DNS 서버 주소 받기</b>\
							</td>\
						</tr>\
						<tr>\
							<td width="100%" colspan="2"><font size=2>\
								<b><input type="radio" value="1" name="x_ipv6_dns_method" onClick="manualDNSclicked()">다음 DNS 서버 주소 사용</b>\
							</td>\
						</tr>');
				}
			</script>
		</table>
	</span>

    <span id = "dns_div" class = "on" >
    <table border="0" width=500>
    <tr>
       <td width="30%"><font size=2><b>&nbsp;&nbsp;&nbsp;DNS 1:</b></td>
       <td width="70%"><font size=2><input type="text" name="x_ipv6_manual_dns1" size="39" maxlength="39" value=></td>
    </tr>
    <tr>
       <td width="30%"><font size=2><b>&nbsp;&nbsp;&nbsp;DNS 2:</b></td>
       <td width="70%"><font size=2><input type="text" name="x_ipv6_manual_dns2" size="39" maxlength="39" value=></td>
    </tr>
    </table>
    </span>
	<SCRIPT>
		ipv6_setup_selection(document.tcpip.x_ipv6_autoconfig_method);
	</SCRIPT>
  </span>
</FIELDSET>
<br>
<FIELDSET style="BORDER-RIGHT: #000000 1px solid; PADDING-RIGHT: 10px; BORDER-TOP: #000000 1px solid; PADDING-LEFT: 10px; PADDING-BOTTOM: 5px; BORDER-LEFT: #000000 1px solid; WIDTH: 480px; PADDING-TOP: 0px; BORDER-BOTTOM: #000000 1px solid; "><LEGEND>IPv6 PassThrough 설정</LEGEND>
	  <table border="0" width=500>
	    <tr>
	       <td width="100%" height=40><font size=2>
				<b><input type="checkbox" name="ipv6_passthru_enabled" value="ON">&nbsp;&nbsp;IPv6 PassThrough 활성화</b>
			</td>
	    </tr>
	  </table>
</FIELDSET>
<br>

  <input type="hidden" value="/skb_ipv6tcpipwan.php" name="submit-url">
  <p><input type="button" value="적용" name="save" onClick="return checkIpv6Validation(this.form)">&nbsp;&nbsp;
  <input type="reset" value="취소" name="reset" onClick="resetClicked()">
</p>
</form>
</blockquote>
</body>
</html>
