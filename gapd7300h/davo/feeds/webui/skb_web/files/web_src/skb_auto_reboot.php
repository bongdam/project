<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	check_admin($isAdmin );
	$uci = new uci();
	$uci->mode("get");
	$uci->get("dvmgmt.auto_reboot");
	$uci->run();
	$auto = json_decode($uci->result(),true);
	$auto_enable = get_array_val($auto,"dvmgmt.auto_reboot.auto_reboot_enable");
	if($auto_enable == "1"){
		$auto_enable = "checked";
	}else{
		$auto_enable = "";
	}
	$auto_usr_enable = get_array_val($auto,"dvmgmt.auto_reboot.usr_auto_reboot_enable");
	if($auto_usr_enable == "1"){
		$auto_usr_enable = "checked";
	}else{
		$auto_usr_enable = "";
	}
	$usr_auto_reboot_idle = get_array_val($auto,"dvmgmt.auto_reboot.usr_auto_reboot_on_idle");
	$usr_auto_uptime = get_array_val($auto, "dvmgmt.auto_reboot.usr_uptime");
	$usr_auto_wan_idle = get_array_val($auto, "dvmgmt.auto_reboot.usr_wan_port_idle");
	$usr_auto_hour_ragne = get_array_val($auto, "dvmgmt.auto_reboot.usr_hour_range");
	if($usr_auto_hour_ragne != ""){
		$tmp = explode("-",$usr_auto_hour_ragne);
		$auto_ragne1 = $tmp[0];
		$stmp = explode(":",$auto_ragne1);
		$usr_start_hour = $stmp[0];
		$usr_start_min = $stmp[1];
		$auto_ragne2 = $tmp[1];
		$etmp = explode(":",$auto_ragne2);
		$usr_end_hour = $etmp[0];
		$usr_end_min = $etmp[1];
	}
	$usr_day_of_week = get_array_val($auto,"dvmgmt.auto_reboot.usr_day_of_week");
	$usr_auto_avg_data = get_array_val($auto,"dvmgmt.auto_reboot.usr_auto_avg_data");
	/*
	dvmgmt.auto_reboot.ldap_cfg_get_success='0'
	dvmgmt.auto_reboot.def_auto_reboot_on_idle='1'
	dvmgmt.auto_reboot.def_uptime='7d'
	dvmgmt.auto_reboot.def_wan_port_idle='1'
	dvmgmt.auto_reboot.def_hour_range='04:30-05:00'
	dvmgmt.auto_reboot.def_day_of_week='5'
	dvmgmt.auto_reboot.def_auto_avg_data='1000'
	dvmgmt.auto_reboot.crc='20'
	*/
	$ldap_success = get_array_val($auto,"dvmgmt.auto_reboot.ldap_cfg_get_success");
	if($ldap_success == "0"){
		$ldap_val = "Fail";
	}else{
		$ldap_val = "Success";
	}
	$auto_reboot_on_idle = get_array_val($auto,"dvmgmt.auto_reboot.def_auto_reboot_on_idle");
	if($auto_reboot_on_idle == "1"){
		$on_idle_val = "Yes";
	}else{
		$on_idle_val = "No";
	}
	$auto_reboot_uptime = get_array_val($auto,"dvmgmt.auto_reboot.def_uptime");
	$auto_reboot_wan_port_idle = get_array_val($auto,"dvmgmt.auto_reboot.def_wan_port_idle");
	if($auto_reboot_wan_port_idle == "1"){
		$wan_port_idle_val = "Yes";
	}else{
		$wan_port_idle_val = "No";
	}
	$auto_hour_range = get_array_val($auto,"dvmgmt.auto_reboot.def_hour_range");
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>AUTO REBOOT</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">


function valid_check(formAutoReboot)
{
	var tmp;
	var start_t = formAutoReboot.autoreboot_time_shour.value;
	var start_tm = formAutoReboot.autoreboot_time_smin.value;
	var end_t = formAutoReboot.autoreboot_time_ehour.value;
	var end_tm = formAutoReboot.autoreboot_time_emin.value;
	var uptime = formAutoReboot.autoreboot_uptime.value;
	var kbps = formAutoReboot.autoreboot_kbps.value;

	var day_uptime = uptime.toLowerCase().indexOf("d");
	var hour_uptime = uptime.toLowerCase().indexOf("h");
	var min_uptime = uptime.toLowerCase().indexOf("m");

	if(day_uptime < 0 && hour_uptime < 0 && min_uptime < 0)
	{
		alert("Auto Uptime의 단위를 정확히 입력해주세요.");
		return false;
	}

	if(!IsDigit(start_t) || !IsDigit(end_t) || !IsDigit(start_tm) || !IsDigit(end_tm)) {
		alert('"Auto Hour/Min Range"에는 숫자만 입력가능합니다');
		return false;
	}

	if(!IsDigit(kbps)) {
		alert('"autoreboot_kbps"에는 숫자만 입력가능합니다');
		return false;
	}

	if(parseInt(kbps) > 270000) {
		alert('"autoreboot_kbps"에는 최대 270000 까지 입력가능합니다');
		return false;
	}

	if(parseInt(start_t) >= 24 || parseInt(end_t) >= 24) {
		alert('"Auto Hour Range"에는 0~23 까지 입력가능합니다');
		return false;
	}

	if(parseInt(start_tm) >= 60 || parseInt(end_tm) >= 60) {
		alert('"Auto Min Range"에는 0~59 까지 입력가능합니다');
		return false;
	}
	if(parseInt(start_t) > parseInt(end_t)){
		alert("시간 설정이 잘못되었습니다.");
		return false;
	}
	if(parseInt(start_t) == parseInt(end_t) && parseInt(start_tm) > parseInt(end_tm)){
		alert("시간 설정이 잘못되었습니다.");
		return false;
	}
	tmp = convert_two_digit(start_t)+':'+convert_two_digit(start_tm)+'-'+convert_two_digit(end_t)+':'+convert_two_digit(end_tm);
	formAutoReboot.autoreboot_time.value=tmp;

	start_t=formAutoReboot.autoreboot_week_s.value;
	end_t=formAutoReboot.autoreboot_week_s.value;
	//end_t=formAutoReboot.autoreboot_week_e.value;
	formAutoReboot.autoreboot_week.value=start_t+'-'+end_t;

	alert("설정 되었습니다.");
	formAutoReboot.submit();
}

function update_cfg()
{
	if (document.formAutoReboot.autoreboot_userforce.checked == true) {
		enableRadioGroup(document.formAutoReboot.autoreboot_on_idle);
		enableRadioGroup(document.formAutoReboot.autoreboot_wan_idle);
		document.formAutoReboot.autoreboot_uptime.disabled =false;
		document.formAutoReboot.autoreboot_kbps.disabled =false;
		document.formAutoReboot.autoreboot_wan_idle.disabled =false;
		document.formAutoReboot.autoreboot_time_shour.disabled =false;
		document.formAutoReboot.autoreboot_time_smin.disabled =false;
		document.formAutoReboot.autoreboot_time_ehour.disabled =false;
		document.formAutoReboot.autoreboot_time_emin.disabled =false;
		document.formAutoReboot.autoreboot_week_s.disabled =false;
		//document.formAutoReboot.autoreboot_week_e.disabled =false;
	} else {
		disableRadioGroup(document.formAutoReboot.autoreboot_on_idle);
		disableRadioGroup(document.formAutoReboot.autoreboot_wan_idle);
		document.formAutoReboot.autoreboot_uptime.disabled =true;
		document.formAutoReboot.autoreboot_kbps.disabled =true;
		document.formAutoReboot.autoreboot_wan_idle.disabled =true;
		document.formAutoReboot.autoreboot_time_shour.disabled =true;
		document.formAutoReboot.autoreboot_time_smin.disabled =true;
		document.formAutoReboot.autoreboot_time_ehour.disabled =true;
		document.formAutoReboot.autoreboot_time_emin.disabled =true;
		document.formAutoReboot.autoreboot_week_s.disabled =true;
		//document.formAutoReboot.autoreboot_week_e.disabled =true;
	}
}

function update_cfgs()
{
	if(document.formAutoReboot.autoreboot_enabled.checked == true)
		document.formAutoReboot.autoreboot_userforce.disabled = false;
	else
		document.formAutoReboot.autoreboot_userforce.disabled = true;

	if(document.formAutoReboot.autoreboot_userforce.disabled==true)
		document.formAutoReboot.autoreboot_userforce.checked = false;

	update_cfg();
}

function resetClick()
{
	document.location.reload();
}

</script>
</head>
<body onload="update_cfgs();">
<blockquote>
<h2>AUTO REBOOTING</h2>
<table border="0" width="500" cellspacing="4" cellpadding="0">
	<tr>
		<td><font size="2">자동 재시작을 설정하는 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>
	<form action="proc/skb_auto_reboot_proc.php" method="POST" name="formAutoReboot">

<table>
	<input type="checkbox" name="autoreboot_enabled" value="1" onClick="update_cfgs();" <?=$auto_enable?>><b>AUTO_REBOOT 사용
</table>
<br>

<table border=0 width="500" cellspacing="4" cellpadding="0">
    <tr>
        <td align="left" width="30%" colspan="2">
            <b>*서버로부터 내려받은 설정 상태</b>
        </td>
    </tr>
    <tr>
        <td colspan="2" width="100%" style="height:1px;line-height:1px;font-size:1px;background-color:#666;padding:0px;"></td>
    </tr>
    <tr>
        <td width="50%">
            GET FROM LDAP CFG SERVER:
        </td>
        <td><?=$ldap_val?></td>
    </tr>
    <tr>
        <td width="50%">
            Auto Reboot on idle:
        </td>
        <td><?=$on_idle_val?></td>
    </tr>
    <tr>
        <td width="50%">
            Auto Uptime:
        </td>
        <td width="50%"><?=$auto_reboot_uptime?></td>
    </tr>
    <tr>
        <td width="50%">
            Auto Wan Port Idle:
        </td>
        <td><?=$wan_port_idle_val?></td>
    </tr>
    <tr>
        <td width="50%">Auto Hour Range:(00~23):
        </td>
        <td width="50%"><?=$auto_hour_range?></td>
    </tr>
</table>
	<br>
	<br>
	<table border="0" width="500" cellspacing="4" cellpadding="0">
		<tr>
			<td align="left" width="30%" colspan="2">
				<b>*운영자 수동 설정 상태
			</td>
		</tr>
		<tr>
			<td colspan="2" width="100%" style="height:1px;line-height:1px;font-size:1px;background-color:#666;padding:0px;" ></td>
		</tr>
		<br>
		<tr>
			<td width="30%">
				수동 설정 사용:
			</td>
			<td>
				<input type="checkbox" name="autoreboot_userforce" id="autoreboot_userforce" value="1" onClick="update_cfg();" <?=$auto_usr_enable?>>
			</td>
		</tr>
		<tr>
			<td width="30%">
				Auto Reboot on idle:
			</td>
			<td>
				<input type="radio" name="autoreboot_on_idle" id="autoreboot_on_idle" value="1" <?php if($usr_auto_reboot_idle == "1"){echo("checked");}?>>YES
				<input type="radio" name="autoreboot_on_idle" id="autoreboot_on_idle" value="0" <?php if($usr_auto_reboot_idle == "0"){echo("checked");}?>>NO
			</td>
		</tr>
		<tr>
			<td width="30%">
				Auto Uptime:
			</td>
			<td width="30%">
				<input type="text" name="autoreboot_uptime" id="autoreboot_uptime" size="3" maxlength="3" value="<?=$usr_auto_uptime?>" >(d/h/m (예:15일 설정)-"15d")
			</td>
		</tr>
		<tr>
			<td width="30%">
				Auto Wan Port Idle:
			</td>
			<td>
				<input type="radio" name="autoreboot_wan_idle" value="1" <?php if($usr_auto_wan_idle == "1"){echo("checked");}?>>YES
				<input type="radio" name="autoreboot_wan_idle" value="0" <?php if($usr_auto_wan_idle == "0"){echo("checked");}?>>NO
			</td>
		</tr>
		<tr>
			<td width="30%">Auto 시간:(00~23):</td>
			<td width="30%">
				<input type="hidden"  name="autoreboot_time" id="autoreboot_time" value="" >
				<input type="text"  name="autoreboot_time_shour" id="autoreboot_time_shour" value="<?=$usr_start_hour?>" size="1" maxlength="2" >시
				<input type="text"  name="autoreboot_time_smin" id="autoreboot_time_smin" value="<?=$usr_start_min?>" size="1" maxlength="2" >분--
				<input type="text"  name="autoreboot_time_ehour" id="autoreboot_time_ehour" value="<?=$usr_end_hour?>" size="1" maxlength="2" >시
				<input type="text"  name="autoreboot_time_emin" id="autoreboot_time_emin" value="<?=$usr_end_min?>" size="1" maxlength="2" >분
			</td>
		</tr>
		<tr>
			<td width="30%">Auto 요일:</td>
			<td width="30%">
				<input type="hidden"  name="autoreboot_week" value="" >
				<select name="autoreboot_week_s">
					<option value="1" <?php if($usr_day_of_week == "1"){echo("selected");}?>>월</option>
					<option value="2" <?php if($usr_day_of_week == "2"){echo("selected");}?>>화</option>
					<option value="3" <?php if($usr_day_of_week == "3"){echo("selected");}?>>수</option>
					<option value="4" <?php if($usr_day_of_week == "4"){echo("selected");}?>>목</option>
					<option value="5" <?php if($usr_day_of_week == "5"){echo("selected");}?>>금</option>
					<option value="6" <?php if($usr_day_of_week == "6"){echo("selected");}?>>토</option>
					<option value="0" <?php if($usr_day_of_week == "0"){echo("selected");}?>>일</option>
				</select>
				<input type="hidden" name="autoreboot_week_e" id="autoreboot_week_e" value="">
<!--				</select>-
				<select name="autoreboot_week_e">
					<option value="1">월
					<option value="2">화
					<option value="3">수
					<option value="4">목
					<option value="5">금
					<option value="6">토
					<option value="0">일
				</select>-->
			</td>
		</tr>
		<tr>
			<td width="30%">Auto 평균 데이타량(1분):</td>
			<td width="30%">
				<select name="autoreboot_kbps" id="autoreboot_kbps">
					<option value="100" <?php if($usr_auto_avg_data == "100"){echo("selected");}?>>100(kbps)이하</option>
					<option value="200" <?php if($usr_auto_avg_data == "200"){echo("selected");}?>>200(kbps)이하</option>
					<option value="300" <?php if($usr_auto_avg_data == "300"){echo("selected");}?>>300(kbps)이하</option>
					<option value="400" <?php if($usr_auto_avg_data == "400"){echo("selected");}?>>400(kbps)이하</option>
					<option value="500" <?php if($usr_auto_avg_data == "500"){echo("selected");}?>>500(kbps)이하</option>
					<option value="600" <?php if($usr_auto_avg_data == "600"){echo("selected");}?>>600(kbps)이하</option>
					<option value="700" <?php if($usr_auto_avg_data == "700"){echo("selected");}?>>700(kbps)이하</option>
					<option value="800" <?php if($usr_auto_avg_data == "800"){echo("selected");}?>>800(kbps)이하</option>
					<option value="900" <?php if($usr_auto_avg_data == "900"){echo("selected");}?>>900(kbps)이하</option>
					<option value="1000" <?php if($usr_auto_avg_data == "1000"){echo("selected");}?>>1000(kbps)이하</option>
				</select>
			</td>
		</tr>
	</table>
<br>
<br>
<input type="button" value="적용" name="save" onClick="valid_check(this.form);">&nbsp;&nbsp;
<input type="reset" value="취소" name="reset" onclick="resetClick();">
<input type="hidden" value="/skb_auto_reboot.php" name="submit-url">
</form>
</table>
</blockquote>
</body>
</html>
