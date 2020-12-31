<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$uci = new uci();
	$uci->mode("get");
	$uci->get("system.ntp");
	$uci->run();
	$ntp = $uci->result();
	if($ntp == ""){
		$ntp = "null";
	}
	$cmd = new dvcmd();
	$cmd->add("date");
	$cmd->run();
	$nowdate = $cmd->result()[0];
	if(preg_match("/^(\d+)-(\d+)-(\d+)\s(\d+):(\d+):(\d+)/",$nowdate,$d) == true) {
		$nowyear = $d[1];
		$nowmonth = $d[2];
		$nowday = $d[3];
		$nowhour = $d[4];
		$nowmin = $d[5];
		$nowsec = $d[6];
	}
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>시간 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var ntp = <?=$ntp?>;
var proc="proc/skb_ntp_proc.php";
function checkEmpty(field){
	if(field.value.length == 0){
		alert(field.name + "필드 값을 입력하세요.");
		field.value = field.defaultValue;
		field.focus();
		return false;
	}
	else
		return true;
}
function checkNumber(field){
    str =field.value ;
    for (var i=0; i<str.length; i++) {
    	if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9'))
                        continue;
	field.value = field.defaultValue;
        alert(field.name + " 필드 값이 올바르지 않습니다. 0-9 사이에 해당하는 값을 입력하세요.");
        return false;
    }	
	return true;
}

function includeSpace(field)
{
	for (var i=0; i<field.length; i++) {
		if ( field.charAt(i) == ' ' ) {
			return true;
		}
	}
	return false;
}

function saveChanges(form) {
	var ntp_prio = 0;
	var comdate = "";
	if (form.enabled.checked) {
		if (form.ntpServerId[1].checked == true) { 
			if (form.ntpServerIp2.value != "") {
				if (includeSpace(form.ntpServerIp2.value)) {
					alert("주소에 공백을 입력할 수 없습니다. 다시 입력하여 주십시오.");
					form.ntpServerIp2.focus();
					return false;
				}
				if(!check_xss(form.ntpServerIp2.value)){
					alert(xss_err_msg);
					form.ntpServerIp2.focus();
					return;
				}
			}
			ntp_prio = 1;
		} else if (form.ntpServerId[0].checked == true) {
			if (form.ntpServerIp1.value != "") {
				if (includeSpace(form.ntpServerIp1.value)) {
					alert("주소에 공백을 입력할 수 없습니다. 다시 입력하여 주십시오.");
					form.ntpServerIp1.focus();
					return false;
				}
				if(!check_xss(form.ntpServerIp1.value)){
					alert(xss_err_msg);
					form.ntpServerIp1.focus();
					return;
				}
			}
			ntp_prio = 0;
		}
	}else{
		if(check_date($("#year").val() + "-" + convert_two_digit($("#month").val()) + "-" + convert_two_digit($("#day").val())) == false) {
			alert("날짜 형식이 잘 못되었습니다.");
			return;
		}
		if(check_time(convert_two_digit($("#hour").val()) + ":" + convert_two_digit($("#minute").val()) + ":" + convert_two_digit($("#second").val())) == false){
			alert("시간 형식이 잘 못되었습니다.");
			return;
		}
		comdate = $("#year").val() + "-" + convert_two_digit($("#month").val()) + "-" + convert_two_digit($("#day").val()) + " " + convert_two_digit($("#hour").val()) + ":" + convert_two_digit($("#minute").val()) + ":" + convert_two_digit($("#second").val());
		console.log(comdate);
	}
	var ntp_use = form.enabled.checked ? "1" : "0";
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = "save_time";
	sobj['ntp_enable'] = ntp_use;
	sobj["ntp_server1"] = form.ntpServerIp1.value;
	sobj["ntp_server2"] = form.ntpServerIp2.value;
	sobj['com_time'] = comdate;
	sobj["ntp_prio"] = ntp_prio;
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

function updateState(form)
{
	if(form.enabled.checked){
		form.ntpServerId[0].disabled = false;
		form.ntpServerId[1].disabled = false;
		enableTextField(form.ntpServerIp1);
		enableTextField(form.ntpServerIp2);
	}
	else{
		form.ntpServerId[0].disabled = true;
		form.ntpServerId[1].disabled = true;
		disableTextField(form.ntpServerIp1);
		disableTextField(form.ntpServerIp2);
	}
}

/** Copy time from the host computer.*/
function copy_computer_time()
{
	var date = new Date();
	document.time.year.value = date.getFullYear();
	document.time.month.value = date.getMonth()+1;
	document.time.day.value = date.getDate();
	document.time.hour.value = date.getHours();
	document.time.minute.value = date.getMinutes();
	document.time.second.value = date.getSeconds();
}

function init()
{
	var cf = document.time;
	var ntpEnabled = ntp["system.ntp.enabled"];
	var ntpServerId = 0;

	if(ntpEnabled == "1") {
		cf.ntpServerId[0].disabled = false;
		cf.ntpServerId[1].disabled = false;
		cf.enabled.checked = true;
	} else {
		cf.ntpServerId[0].disabled = true;
		cf.ntpServerId[1].disabled = true;
  		cf.enabled.checked = false;
	}
	if(ntpServerId == 0) {
		cf.ntpServerId[0].checked = true;
	} else if(ntpServerId == 1){
		cf.ntpServerId[1].checked = true;
	}
	if(ntp != null){
		if(ntp["system.ntp.server1"] != ""){
			$("#ntpServerIp1").val(ntp["system.ntp.server1"]);
			
		}
		if(ntp["system.ntp.server2"] != ""){
			$("#ntpServerIp2").val(ntp["system.ntp.server2"]);
		}
	}
	$("#ntpServerId"+ntp["system.ntp.primary"]).prop("checked",true);
	updateState(document.time);
}
$(document).ready(function(){
	init();
	updateState(document.time);
});
</script>
</head>
<body>
<blockquote>
<h2>시간 설정</h2>
<table border=0 width="500" cellspacing="0" cellpadding="0">
	<tr>
		<td><font size="2">인터넷에 공개된 타임 서버와 동기화하여 시스템의 시간을 유지할 수 있는 페이지입니다.</td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>
<form action="proc/skb_ntp_proc.php" method="POST" name="time">
<table border="0" width="520">
	<tr>
		<td width ="25%">
		<font size="2"> <b> 현재 시간 : </b> </font></td>
		<td width ="75%"><font size="2"> <b>
		<input type="text" name="year" id="year" value="<?=$nowyear?>" defaultValue="<?=$nowyear?>" size="4" maxlength="4"> 년
		<input type="text" name="month" id="month" value="<?=$nowmonth?>" defaultValue="<?=$nowmonth?>" size="2" maxlength="2"> 월
		<input type="text" name="day" id="day" value="<?=$nowday?>" defaultValue="<?=$nowday?>" size="2" maxlength="2"> 일
		<input type="text" name="hour" id="hour" value="<?=$nowhour?>" defaultValue="<?=$nowhour?>" size="2" maxlength="2"> 시
		<input type="text" name="minute" id="minute" value="<?=$nowmin?>" defaultValue="<?=$nowmin?>" size="2" maxlength="2"> 분
		<input type="text" name="second" id="second" value="<?=$nowsec?>" defaultValue="<?=$nowsec?>" size="2" maxlength="2"> 초
		</b></font></td>
	</tr>
	<tr>
		<td width ="25%">&nbsp;</td>
		<td width ="75%"><input type="button" class="button_submit" id="copy_computer_time_button" value="컴퓨터 시간 복사하기" onclick="copy_computer_time();"/></td>
	</tr>
	<tr>
		<td height="10" colspan="2"> </td>
	</tr>

	<tr>
		<td colspan="2"><font size="2"><b><input type="checkbox" name="enabled" value="ON" onclick="updateState(document.time)">&nbsp;&nbsp; NTP 사용하기 </b><br></font></td>
	</tr>
	<tr>
		<td width ="25%"><font size="2"> <b> NTP 서버 : </b> </font></td>
		<td width ="75%"><input type="radio" value="0" name="ntpServerId" id="ntpServerId0"><input type="text" name="ntpServerIp1" id="ntpServerIp1" size="20" maxlength="30" value="time.bora.net"></td>
	</tr>
	<tr>
		<td width ="25%"> <font size="2"><b> </b></font></td>
		<td width ="75%"><input type="radio" value="1" name="ntpServerId"  id="ntpServerId1"><input type="text" name="ntpServerIp2" id="ntpServerIp2" size="20" maxlength="30" value="time-b.nist.gov"></td>
	</tr>
</table>
<input type="hidden" value="/skb_ntp.php" name="submit-url">
<p><input type="button" value="저장" name="save" onclick="saveChanges(document.time)">
&nbsp;&nbsp;
<input type="reset" value="초기화" name="set" >
&nbsp;&nbsp;
<input type="button" value="새로고침" name="refresh" onclick="javascript: window.location.reload()">
</form>
</blockquote>
</body>

</html>
