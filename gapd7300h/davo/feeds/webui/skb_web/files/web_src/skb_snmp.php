<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	check_admin($isAdmin );
	$uci = new uci();
	$uci->mode("get");
	$uci->get("snmp.config");
	$uci->run();
	$snmp = json_decode($uci->result(),true);
	
	$snmp_enable = get_array_val($snmp,"snmp.config.enable");
	if($snmp_enable == "enable"){
		$snmp_enable = "checked";
	}else{
		$snmp_enable = "";
	}
	$snmp_com1 = get_array_val($snmp,"snmp.config.snmp_com1");
	$snmp_com2 = get_array_val($snmp,"snmp.config.snmp_com2");
	$snmp_com1_enable = "";
	$snmp_com2_enable = "";
	$snmp_com1_rw = "";
	$snmp_com2_rw = "";
	if($snmp_com1 != ""){
		$tmp1 = explode("_",$snmp_com1);
		if($tmp1[0] == "1"){
			$snmp_com1_enable = "checked";
		}
		if($tmp1[1] == "0"){
			$snmp_com1_rw = "read_only";
		}else{
			$snmp_com1_rw = "write_only";
		}
	}
	if($snmp_com2 != ""){
		$tmp2 = explode("_",$snmp_com2);
		if($tmp2[0] == "1"){
			$snmp_com2_enable = "checked";
		}
		if($tmp2[1] == "0"){
			$snmp_com2_rw = "read_only";
		}else{
			$snmp_com2_rw = "write_only";
		}
	}
	$snmp_trap = get_array_val($snmp,"snmp.config.trap_enable");
	if($snmp_trap == "enable"){
		$snmp_trap = "checked";
	}else{
		$snmp_trap = "";
	}
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>SNMP 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
function updateState()
{
	if(document.formSNMP.snmpEnable.checked) {
		document.formSNMP.getsnmpEnable.disabled =false;
		document.formSNMP.setsnmpEnable.disabled =false;
		document.formSNMP.getType.disabled = false;
		document.formSNMP.setType.disabled = false;
 		enableTextField(document.formSNMP.getCom);
 		enableTextField(document.formSNMP.setCom);
		document.formSNMP.snmpTrapEnable.disabled = false;
		if(!document.formSNMP.getsnmpEnable.checked){
			document.formSNMP.getType.disabled = true;
			disableTextField(document.formSNMP.getCom);
		}
		if(!document.formSNMP.setsnmpEnable.checked){
			document.formSNMP.setType.disabled = true;
			disableTextField(document.formSNMP.setCom);
		}
		
		if(document.formSNMP.snmpTrapEnable.checked){
			enableTextField(document.formSNMP.trapCommunity);
			enableTextField(document.formSNMP.trapServer);
			enableTextField(document.formSNMP.trapServer2);
		}
		else {
			disableTextField(document.formSNMP.trapCommunity);
			disableTextField(document.formSNMP.trapServer);
			disableTextField(document.formSNMP.trapServer2);
		}
	}else{
		document.formSNMP.getsnmpEnable.disabled =true;
		document.formSNMP.setsnmpEnable.disabled =true;
		document.formSNMP.getType.disabled = true;
		document.formSNMP.setType.disabled = true;
 		disableTextField(document.formSNMP.getCom);
 		disableTextField(document.formSNMP.setCom);
		document.formSNMP.snmpTrapEnable.disabled = true;
 		disableTextField(document.formSNMP.trapCommunity);
 		disableTextField(document.formSNMP.trapServer);
 		disableTextField(document.formSNMP.trapServer2);
	}
}

function resetClicked()
{
	document.location.assign("skb_snmp.php");
}
function do_apply()
{
	var com1;
	var com2;
	var trap1, trap2, trap3;	
	if(document.formSNMP.getsnmpEnable.checked == true){
		com1 = document.formSNMP.getCom.value;
		com2 = document.formSNMP.setCom.value;
		if(com1=='' || com2==''){
			alert('Community 를 입력해주세요');
			return resetClicked();
		}
		if(!check_xss(com1)){
			alert(xss_err_msg);
			$("#getCom").focus();
			return;
		}
		if(!check_xss(com2)){
			alert(xss_err_msg);
			$("#setCom").focus();
			return;
		}
	}

	if(document.formSNMP.snmpTrapEnable.checked == true){
		trap1 = document.formSNMP.trapCommunity.value;
		trap2 = document.formSNMP.trapServer.value;
		trap3 = document.formSNMP.trapServer2.value;
		if(trap1==''){
			alert('Trap community 를 입력해주세요');
			return resetClicked();
		}
		if(!check_xss(trap1)){
			alert(xss_err_msg);
			$("#trapCommunity").focus();
			return;
		}
		if(trap2 == "" || trap3 == ""){
			alert('Trap Server 를 입력해주세요');
			return resetClicked();
		}
		if(!check_xss(trap2)){
			alert(xss_err_msg);
			$("#trapServer").focus();
			return;
		}
		if(!check_xss(trap3)){
			alert(xss_err_msg);
			$("#trapServer2").focus();
			return;
		}
	}
	alert("설정되었습니다.");
	document.formSNMP.submit();
}



</script>
</head>

<body>
<blockquote>
<h2>SNMP 설정</h2>
<table border="0" width="500" cellspacing="0" cellpadding="0">
	<tr>
		<td><font size="2"><br>네트워크 관리를 위한 SNMP를 설정하는 페이지입니다. </font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>
<form action="proc/skb_snmp_proc.php" method="POST" name="formSNMP">
<table border="0" width="550" cellspacing="0" cellpadding="0">
	<tr>
		<td colspan="2"><font size="2"><b><input type="checkbox" name="snmpEnable" id="snmpEnable" value="1" onclick="updateState()" <?=$snmp_enable?>>&nbsp;&nbsp;SNMP 사용</b></font></td>
	</tr>
	<tr>
		<td width="50%"><font size="1.5"><b>
		<input type="checkbox" name="getsnmpEnable" value="1" onclick="updateState()" <?=$snmp_com1_enable?>>&nbsp;&nbsp;SNMP Get Community&nbsp;&nbsp;</b>
		<select size="1" name="getType">
			<option value="read_only" <?php if($snmp_com1_rw =="read_only"){echo("selected");}?>>Read Only</option>
			<option value="write_only" <?php if($snmp_com1_rw =="write_only"){echo("selected");}?>>Read-Write</option>
		</select></td>
		<td width="50%"><input type="password" name="getCom" id="getCom" size="22" maxlength="30" value="*****"></font></td>
	</tr>
	<tr>
		<td width="50%"><font size="1.5"><b><input type="checkbox" name="setsnmpEnable" value="1" onclick="updateState()" <?=$snmp_com2_enable?>>&nbsp;&nbsp;SNMP Set Communit&nbsp;&nbsp;</b><select size="1" name="setType">
			<option value="read_only" <?php if($snmp_com2_rw =="read_only"){echo("selected");}?>>Read Only</option>
			<option value="write_only" <?php if($snmp_com2_rw =="write_only"){echo("selected");}?> >Read-Write</option>
		</select></td>
		<td width="50%"><input type="password" name="setCom" id="setCom" size="22" maxlength="30" value="*****"></font></td>
	</tr>
	<tr>
		<td colspan="2"><font size="2"><b><input type="checkbox" name="snmpTrapEnable" id="snmpTrapEnable" value="1" onclick="updateState()" <?=$snmp_trap?>>&nbsp;&nbsp;SNMP TRAP 사용</td>
	</tr>
	<tr>
		<td><font size="2"><b>Trap 커뮤니티: </b></font></td>
		<td><input type="password" name="trapCommunity" id="trapCommunity" size="22" maxlength="32" value="******"></font></td>
	</tr>
	<tr>
		<td><font size="2"><b>Trap-1서버: </b></td>
		<td> <input type="password" name="trapServer" id="trapServer" size="22" maxlength="64" value="******"></font></td>
	</tr>
	<tr>
		<td><font size="2"><b>Trap-2서버: </b></td>
		<td><input type="password" name="trapServer2" id="trapServer2" size="22" maxlength="64" value="******"></font></td>
	</tr>
	<tr>
		<td><br><input type="button" value="적용" name="save" onclick="do_apply()"><input type="hidden" value="/skb_snmp.php" name="submit-url"></td>
	</tr>
</table>
<script type="text/javascript"> 
	updateState(); 
</script>
</form>
</blockquote>
</body>
</html>
