<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$logmsg = "";
	if(file_exists("/var/log/dhcp_log.old") == true){
		$logfile = fopen("/var/log/dhcp_log.old", "r");
		$logmsg .= fread($logfile,filesize("/var/log/dhcp_log.old"));
		fclose($logfile);
	}
	if(file_exists("/var/log/dhcp_log") == true){
		$logfile = fopen("/var/log/dhcp_log", "r");
		$logmsg .= fread($logfile,filesize("/var/log/dhcp_log"));
		fclose($logfile);
	}
	$ori_log = $logmsg;
	$logmsg = explode("\n",rtrim($logmsg));
	$uci = new uci();
	$uci->mode("get");
	$uci->get("dvlog.log_web_cfg");
	$uci->run();
	$logcfg = json_decode($uci->result());
	$log_enable = std_get_val($logcfg,"dvlog.log_web_cfg.enabled");
	$rlog_enabled = std_get_val($logcfg,"dvlog.log_web_cfg.rlog_enabled");
	$rlog_ip = std_get_val($logcfg,"dvlog.log_web_cfg.rlog_ip");
	$uci->close();
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>System Command</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<!-- <script type="text/javascript" src="skb_xml_data.js"></script> -->
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var isMeshDefined = 0 
var str='';
var arrlog= Array();
var httpRequest = null;
var proc = "proc/skb_syslog_proc.php";
  
function saveClick()
{
	if ( document.formSysLog.rtLogEnabled.checked && checkIpAddr(document.formSysLog.logServer, '로그 서버 IP 주소가 올바르지 않습니다. ') == false ){
		return false;
	}
	var enabled_ = $("#logEnabled").prop("checked") == true ? "1" : "0";
	var rlog_enabled_ = $("#rtLogEnabled").prop("checked") == true ? "1" : "0";
	var rlog_ip_ = $("#logServer").val();
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'save_log_cfg';
	sobj['enabled'] = enabled_;
	sobj['rlog_enabled'] = rlog_enabled_;
	sobj['rlog_ip'] = rlog_ip_;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
//			get_static_list();
			alert("적용되었습니다.");
			window.location.reload();
		}
	});
	return true;
}

function updateState()
{
	if(document.formSysLog.logEnabled.checked) {
		enableTextField(document.formSysLog.rtLogEnabled);
//		enableTextField(document.formSysLog.syslogEnabled);
		updateStateRemote();
	} else {
		disableTextField(document.formSysLog.logServer);
		disableTextField(document.formSysLog.rtLogEnabled);
//		disableTextField(document.formSysLog.syslogEnabled);
	}
}

function updateStateRemote()
{
	if(document.formSysLog.rtLogEnabled.checked)
		enableTextField(document.formSysLog.logServer);
	else
		disableTextField(document.formSysLog.logServer);

}

function scrollElementToEnd () 
{
	var div = document.getElementById("display"); 
	if (div.scrollHeight > 0) 
		div.scrollTop = div.scrollHeight;
}

function init()
{
	var cf = document.formSysLog;
	var logEnabled = "<?=$log_enable?>";
	var rtLogEnabled = "<?=$rlog_enabled?>";

	if(logEnabled != "0") 
		cf.logEnabled.checked = true;
	else
		cf.logEnabled.checked = false;

	if(rtLogEnabled != "0")
		cf.rtLogEnabled.checked = true;
	else
		cf.rtLogEnabled.checked = false;

	updateState();
}

function clear_log_buffer()
{
	document.formSysLog.msg.value="";
}
var save_single_log = function(filename_,val_){
	var textToWrite = val_;
	var textFileAsBlob = new Blob([textToWrite], {type:'text/plain'});
	var fileNameToSaveAs = filename_;
	var downloadLink = document.createElement("a");
	downloadLink.download = fileNameToSaveAs;
	downloadLink.innerHTML = "My Hidden Link";
	window.URL = window.URL || window.webkitURL;
	downloadLink.href = window.URL.createObjectURL(textFileAsBlob);
	downloadLink.onclick = destroyClickedElement;
	downloadLink.style.display = "none";
	document.body.appendChild(downloadLink);
	downloadLink.click();
}
function destroyClickedElement(event)
{
	document.body.removeChild(event.target);
}
var log_down = function(){
	var logmsg = $("#ori_log").val();
	save_single_log(CreateDummy()+".log",logmsg);
}
$(document).ready(function(){
	init();
});
</script>
</head>
<body>
<blockquote>
	<h2>시스템 로그</h2>
<form action="proc/skb_syslog_proc.php" method="POST" name="formSysLog">
<table border="0" width="800" cellspacing="0" cellpadding="0">
	<tr>
		<td><font size="2">시스템 Log를 보여주는 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><font size="2"><b><input type="checkbox" name="logEnabled" id="logEnabled" value="1" onClick="updateState()">&nbsp;&nbsp;Log 사용하기</b></font></td>
	</tr>
</table>
<table border="0" width="800">
	<tr>
		<td width="25%">&nbsp;&nbsp;&nbsp;&nbsp;<input type="hidden" name="syslogEnabled" value="1"></td>
	</tr>
</table>
<table border="0" width="800">
	<tr>
		<td width="40%">&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="rtLogEnabled" id="rtLogEnabled" value="1" onClick="updateStateRemote()"> <font size=2><b>원격 로그 사용하기</b></font><br></td>
		<td width="60%"><b><font size="2">로그 서버 IP 주소:</b>&nbsp;&nbsp;<input type="text" name="logServer" id="logServer" value="<?=$rlog_ip?>" size="13" maxlength="16"></font></b></td>
	</tr>
	<tr>
		<td height="10"> </td>
	</tr>
	<tr>
		<td colspan="2"><p><input type="button" value="적용" name="Apply" onclick="saveClick()" >&nbsp;&nbsp; </td>
	</tr>
</table>
<p>
<input type="hidden" value="/skb_syslog.php" name="submit-url">
<div id="display" style="width:700px; height:600px; overflow:auto">  
<table name="msg" border="1" rules="none" width="1000" cellpadding="0" cellspacing="1"  bgcolor="white">
<?php
	for($i=0; $i < count($logmsg); $i++){
		$log = explode("  ",$logmsg[$i],2);
?>
	<tr>
		<td class='mn24'><center><?=$log[0]?></center></td>
		<td class='mn24'><pre><?=$log[1]?></pre></td>
	</tr>
	<tr>
		<td colspan="2"><hr></td>
	</tr>
<?php
	}
?>
</table> 
</div>
<script type="text/javascript">
	scrollElementToEnd();
</script>
</p>
<input type="button" value="새로 고침" name="refresh" onClick="javascript: window.location.reload()">
&nbsp;&nbsp; <input type="button" value="로그 저장 " name="save" onclick="log_down();" > 
</table>
</form>
<textarea id="ori_log" style="display:none;"><?=$ori_log?></textarea>
</body>
</blockquote>
</html>


