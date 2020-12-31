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
<title>Ping Test</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script>
function show_info()
{
	var temp, ping_result, add_value;
	if(parent.document.forms[0].save_ping_info_start.value == '1') {
		temp = '\n';
		ping_result = temp.split(" ");

		add_value = ping_result[0];
		if(ping_result[1].indexOf('success') > -1)
			add_value += " 정상\n";
		else if(ping_result[1].indexOf('lose') > -1)
			add_value += " 응답없음\n";
		else
			add_value = "정보없음\n";

		parent.document.forms[0].save_ping_info.value += add_value;
		document.diagnostic_ping.show_info.value = parent.document.forms[0].save_ping_info.value;
		document.diagnostic_ping.input_ip.focus();
		document.diagnostic_ping.input_ip.value = parent.document.forms[0].save_ping_ip.value;
	}
}

function check_ip()
{
	if (document.diagnostic_ping.input_ip.value=="")
		return false;

	parent.document.forms[0].save_ping_info_start.value = '1';
	parent.document.forms[0].save_ping_ip.value = document.diagnostic_ping.input_ip.value;

	if(document.diagnostic_ping.send_flag.value == '0')
		document.diagnostic_ping.send_flag.value = '1';
	else
		return false;
	document.diagnostic_ping.send_ping.disabled = true;

	document.diagnostic_ping.submit();
}

function handleEnter (event) {
	var keyCode = event.keyCode ? event.keyCode : event.which ? event.which : event.charCode;
	if (keyCode == 13){
		check_ip();
		return false;
	}
	else
		return true;
}

function scrollElementToEnd (element) {
   if (typeof element.scrollTop != 'undefined' &&
       typeof element.scrollHeight != 'undefined') {
     element.scrollTop = element.scrollHeight;
   }
}

</script>
</head>
<body>
<blockquote>
<form action=/boafrm/formDiagnostic_ping method=POST name="diagnostic_ping">
<input type="text" name="input_ip" maxlength="25" size="25" onkeypress="return handleEnter(event)" style="position:relative; right:38;">
<input type="button" value="send ping" name="send_ping" onclick="check_ip();" style="position:relative; right:38;">
<br>
<textarea rows='7' cols='58' name='show_info' style='color:white; background-color:black; position:relative; right:38;'></textarea>
<input type="hidden" value="/skb_diagnostic_ping.php" name="return-url">
<input type="hidden" value="0" name="send_flag">
</form>
<script>show_info(); scrollElementToEnd(document.diagnostic_ping.show_info);</script>
</blockquote>
</body>
</html>
