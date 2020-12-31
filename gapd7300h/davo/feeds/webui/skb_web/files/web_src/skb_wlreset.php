<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	check_admin($isAdmin );
	$cfg = new dvcfg();
	$cfg->read("dvmgmt");
	$smart_reset = $cfg->search("dvmgmt.smart_reset");
//	print_r($smart_reset);
	$enable = get_json_val($smart_reset,"enable");
	if($enable == "1"){
		$enable = "checked";
	}else{
		$enable = "";
	}
	$cfg->close();
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>무선 리셋 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/spin.min.js"></script>
<script type="text/javascript" src="inc/js/jquery.spin.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script language="javascript">
var proc = "proc/skb_wlreset_proc.php";

function valid_check()
{
	var enable_ = $("#enable:checked").val() ? "1" : "0";
	var start_t_ = $("#hour_range_start").val();
	var end_t_ = $("#hour_range_end").val();
	var hour_range_ = start_t_ + "-" + end_t_;
	var day_check_ = $("#day_check").val();
	var wl_traffic_avg_data_ = $("#wl_traffic_avg_data").val();

	$("#frm_enable").val("");
	$("#frm_hour_range").val("");
	$("#frm_day_check").val("");
	$("#frm_wl_traffic_avg_data").val("");

	if(!isNumVal(start_t_) || !isNumVal(end_t_)) {
		alert('"무선 리셋 시간"에는 숫자만 입력가능합니다');
		return false;
	}

	if ( (parseInt(start_t_) < 1 || parseInt(start_t_) > 24) || (parseInt(end_t_) < 1 || parseInt(end_t_) > 24) ) {
		alert('"무선 리셋 시간" 의 범위는 1~24까지 입력 가능합니다');
		return false;
	}

	if (start_t_ >= end_t_) {
		alert('"무선 리셋 시간"의 시작 시간은 종료 시간보다 크거나 같을 수 없습니다.');
		return false;
	}


	if(!isNumVal(day_check_)) {
		alert('"무선 리셋 확인 주기"에는 숫자만 입력가능합니다');
		return false;
	}

	if (parseInt(day_check_) < 0 || parseInt(day_check_) > 365) {
		alert('"무선 리셋 확인 주기" 의 범위는 1~365까지 입력 가능합니다');
		return false;
	}

	if(!isNumVal(wl_traffic_avg_data_)) {
		alert('"무선 평균 데이타량(1분)"에는 숫자만 입력가능합니다');
		return false;
	}

	if (parseInt(wl_traffic_avg_data_) < 1 || parseInt(wl_traffic_avg_data_) > 9999999) {
		alert('"무선 평균 데이타량(1분)" 의 범위는 1~9999999까지 입력 가능합니다');
		return false;
	}

	$("#frm_enable").val(enable_);
	if(enable_ == "1"){
		$("#frm_hour_range").val(hour_range_);
		$("#frm_day_check").val(day_check_);
		$("#frm_wl_traffic_avg_data").val(wl_traffic_avg_data_);
	}
	$("[value='']").prop("disabled",true);

	document.formWlReset.submit();

	alert("설정 되었습니다.");
}
var update_cfg = function(){
	if($("#enable").prop("checked") == true){
		$("#day_check").prop("disabled",false);
		$("#hour_range_start").prop("disabled",false);
		$("#hour_range_end").prop("disabled",false);
		$("#wl_traffic_avg_data").prop("disabled",false);
	}else{
		$("#day_check").prop("disabled",true);
		$("#hour_range_start").prop("disabled",true);
		$("#hour_range_end").prop("disabled",true);
		$("#wl_traffic_avg_data").prop("disabled",true);
	}
}
function resetClick()
{
	window.location.reload();
}
var run_now_restart = function(){
	$("input").prop("disabled",true);
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'run_now_restart';
	create_loading();
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			remove_loading();
		},complete:function(){
			$("input").prop("disabled",false);
		}
	});
}
$(document).ready(function(){
	var tmptime = $("#hour_range").val().split("-");
	$("#hour_range_start").val(tmptime[0]);
	$("#hour_range_end").val(tmptime[1]);
	update_cfg();
});
</script>

</head>
<body>
<blockquote>
<table border="0" width="550" cellspacing="4" cellpadding="0">
<tr><td><h2><font size=3 face="arial" color="#3c7A95">Reset Wireless</font></h2></td></tr>
<tr><td><font size=2> 무선 재시작을 설정하는 페이지입니다. </font></td></tr>
<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<form action="proc/skb_wlreset_proc.php" method="POST" name="formWlReset">
<input type="hidden" name="act" id="act" value="form_save">
<input type="hidden" name="frm_enable" id="frm_enable" value="">
<input type="hidden" name="frm_hour_range" id="frm_hour_range" value="">
<input type="hidden" name="frm_day_check" id="frm_day_check" value="">
<input type="hidden" name="frm_wl_traffic_avg_data" id="frm_wl_traffic_avg_data" value="">
<br>
	<br>
	<table border="0" width="550" cellspacing="4" cellpadding="0">
		<tr>
			<td width="30%">
				무선 리셋 사용:
			</td>
			<td>
				<input type="checkbox" name="enable" id="enable" value="1" <?=$enable;?> onclick="update_cfg();">&nbsp;<input type="button" name="btn_now_reset" id="btn_now_reset" value="즉시리셋" onclick="run_now_restart();">
			</td>
		</tr>
		<tr>
			<td width="30%">
				무선 리셋 확인 주기:
			</td>
			<td width="30%">
				<input type="text" name="day_check" id="day_check" value="<?=get_json_val($smart_reset,"day_check");?>" size="3" maxlength="3" >(일)
			</td>
		</tr>

		<tr>
			<td width="30%">무선 리셋 시간:
			</td>
			<td width="30%">
				<input type="hidden"  name="hour_range" id="hour_range" value="<?=get_json_val($smart_reset,"hour_range");?>" >
				<input type="text"  name="hour_range_start" id="hour_range_start" size="2" maxlength="2" >&nbsp;-&nbsp;
				<input type="text"  name="hour_range_end" id="hour_range_end" size="2" maxlength="2" >(24h)
			</td>
		</tr>

		<tr>
			<td width="30%">
				무선 평균 데이타량(1분):
			</td>
			<td width="30%">
				<input type="text" name="wl_traffic_avg_data" id="wl_traffic_avg_data" value="<?=get_json_val($smart_reset,"wl_traffic_avg_data");?>" size="7" maxlength="7" >(kbyte)이하
			</td>
		</tr>
	</table>
<br>
<br>
<input type="button" value="적용" name="save" onclick="valid_check();">
<input type="hidden" value="/skb_wlreset.php" name="submit-url" >
<input type="reset" value="취소" name="reset" onclick="resetClick();">

</form>
</blockquote>
</body>
</html>
