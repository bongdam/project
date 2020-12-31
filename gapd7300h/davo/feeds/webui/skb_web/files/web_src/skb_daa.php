<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	check_admin($isAdmin );
	$wlan_id = dv_session("wlan_id");
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>무선 간섭 경감</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<style>
.on {display:on}
.off {display:none}
</style>
<script>

var wlan_idx="<?=$wlan_id?>";

function do_it_go(scanform)
{
    scanform.doIt.disabled=true;
    scanform.mirror_daa_hist.disabled=true;
    scanform.mirror_daa_status.disabled=true;
    scanform.run_do_it.value = 1;

    scanform.submit();
    return true;
}

function change_viewtable(scanform)
{
	if (scanform.mirror_daa_hist.value == 1)
		scanform.mirror_daa_hist.value = 0;
	else
		scanform.mirror_daa_hist.value = 1;

	scanform.mirror_daa_status.disabled=true;
    scanform.run_do_it.disabled=true;

    scanform.submit();
    return true;
}

function change_status_viewtable(scanform)
{
	if (scanform.mirror_daa_status.value == 1)
		scanform.mirror_daa_status.value = 0;
	else
		scanform.mirror_daa_status.value = 1;

	scanform.mirror_daa_hist.disabled=true;
    scanform.run_do_it.disabled=true;

    scanform.submit();
    return true;
}

function init_load()
{
	if (document.formDaa.wlanDisabled.value == 1) {
		disableButton(document.formDaa.doIt);
		disableButton(document.formDaa.daa_hist);
		disableButton(document.formDaa.daa_status);
	}
	if (parseInt(wlan_idx) == 1) {
		document.formDaa.wl_detect_mode.value = 0;
	} else {
		document.formDaa.wl_detect_mode.value = 0;
	}

	if(wlan_idx == "0")
		document.formDaa.Wlanintf.options[0].selected = true;
	else
		document.formDaa.Wlanintf.options[1].selected = true;
}

function page_change(selectObj)
{
	if (selectObj.value==1)
		location.href='wlan_redriect.php?redirect-url=skb_daa.php&wlan_id=1';
	else
		location.href='wlan_redriect.php?redirect-url=skb_daa.php&wlan_id=0';
}

</script>
</head>
<blockquote>
<body onload="init_load();">
<b><font size=3 face="arial" color="#3c7A95">무선환경 검사</font></b>
<table border=0 width="650" cellspacing=4 cellpadding=0>
<tr><td><font size=2><br>
 무선환경을 검사하기 위한 설정 페이지입니다.
</font></td></tr>
<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<form name="formDaa" action=/boafrm/formDaa method="POST" onSubmit="return false;">
	<table border=0 width="200" cellspacing=4 cellpadding=0>
		<tr>
			<td width="25%"><font size=2><b>무선:</b></font></td>
			<td width="75%">
				<select name="Wlanintf" id="Wlanintf" onChange="page_change(this)">
					<option value="0">2.4 GHz</option>
					<option value="1">5 GHz</option>
				</select>
			</td>
		</tr>
	</table>
	<table border=1 width="650" cellspacing=4 cellpadding=0>
		<tr bgcolor="#FFFFFF">
			<td width="25%" align="left" nowrap bgcolor="#FFFFFF">
				&nbsp;동작 모드
			</td>
			<td align="left">
				<Select name="wl_detect_mode">
					<Option value="0">동작 정지 </Option>
					<Option value="1">무선 환경 검사 </Option>
					<Option value="2">연속 무선 환경 검사 </Option>
					<!--Option value="3">무선 간섭 회피[1]</Option>
					<Option value="4">무선 간섭 회피[2]</Option>
					<Option value="5">무선 간섭 회피[3]</Option-->
				</Select>
				&nbsp;&nbsp;<input type="button" value="실행" name="doIt" onClick="return do_it_go(this.form)">
			</td>
			<!--td>

			</td-->
		</tr>

		<tr bgcolor="#FFFFFF">
			<td width="20%" align="left" nowrap bgcolor="#FFFFFF">
				&nbsp;동작 정지
			</td>
			<td align="left">
				 &nbsp;간섭 신호 검출 기능 동작을 중지한다.
			</td>
		</tr>
		<tr bgcolor="#FFFFFF">
			<td width="20%" align="left" nowrap bgcolor="#FFFFFF">
				&nbsp;무선 환경 검사
			</td>
			<td align="left">
				&nbsp;3분 동안 현재 동작 채널의 간섭 정도를 검사해서 기록한다. <br>
				운용자는 별도 명령으로 조회가 가능하다.
				<br>3분 측정 후 자동으로 모드를 0로 초기화 한다.
			</td>
		</tr>
		<tr bgcolor="#FFFFFF">
			<td width="20%" align="left" nowrap bgcolor="#FFFFFF">
				&nbsp;연속 무선 환경 검사
			</td>
			<td align="left">
				 &nbsp;모드를 0으로 변경하기 전까지 연속해서 무선 환경을 검사하며, <br>
				최근 3분, 15분, 1시간에 대한 검사 결과 기록을 제공한다.
			</td>
		</tr>
		<!--tr bgcolor="#FFFFFF">
			<td width="20%" align="left" nowrap bgcolor="#FFFFFF">
				&nbsp;무선 간섭 회피[1]
			</td>
			<td align="left">
				 &nbsp;현재 동작 채널의 간섭 정도가 1시간 동안 초기 설치한 상황보다<br>
				 심하게 악화된 경우, 채널을 변경한다. <br>
				 단, 무선 단말이 연결되어 있지 않을 경우 만 변경한다.
			</td>
		</tr>
		<tr bgcolor="#FFFFFF">
			<td width="20%" align="left" nowrap bgcolor="#FFFFFF">
				&nbsp;무선 간섭 회피[2]
			</td>
			<td align="left">
				 &nbsp;현재 동작 채널의 간섭 정도가 1시간 동안 초기 설치한 상황보다<br>
				 심하게 악화된 경우, 채널을 변경한다.<br>
				 단, 무선 단말이 사용 중이 아닐 경우만 변경한다.
			</td>
		</tr>
		<tr bgcolor="#FFFFFF">
			<td width="20%" align="left" nowrap bgcolor="#FFFFFF">
				&nbsp;무선 간섭 회피[3]
			</td>
			<td align="left">
				 &nbsp;현재 동작 채널의 간섭 정도가 1시간 동안 초기 설치한 상황보다<br>
				 심하게 악화된 경우, 무조건 채널을 변경한다.
			</td>
		</tr-->
	</table>
	<br>
	<table width="95%" cellpadding="3" cellspacing="1" border="0">
		<tr valign="bottom">
			<td width="100%" >
				<table width="650" cellpadding="3" cellspacing="1" border="0">
				<tr bgcolor="#FFFFFF"><td width="25%" align="left" nowrap bgcolor="#FFFFFF" >
현재 진행 모드: </td>
<td align="left">
동작 정지 상태</td>
</tr>

				</table>
			</td>
		</tr>
		<input type="hidden" name="wlanDisabled" value=0>
		<input type="hidden" value="Refresh" name="refresh">
		<input type="hidden" name="wlan_idx" value=1>
		<input type="hidden" name="wlmode_change" value="0" >
		<input type="hidden" name="run_do_it" value="0" >
		<input type="hidden" name="mirror_daa_hist" value="0" >
		<input type="hidden" name="mirror_daa_status" value="0" >
		<input type="hidden" value="/skb_daa.php" name="submit-url">
		<input type="button" value="새로 고침" name="refresh" onClick="javascript: window.location.reload()">
	</table>
</form>
</blockquote>

</body>
</html>
