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
<title>연결 해제 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script>

var wlan_idx=<?=$wlan_id?>;

function selectMac(tmpMac)
{
	document.formRedirEncrypt.disc_sta_mac.value = tmpMac;

	return true;
}

function page_change(selectObj)
{

	if (selectObj.value==1)
		location.href='wlan_redriect.php?redirect-url=skb_wlsecurity_disclient.php&wlan_id=1';
	else
		location.href='wlan_redriect.php?redirect-url=skb_wlsecurity_disclient.php&wlan_id=0';
}

function resetForm()
{
	document.location.assign("skb_wlsecurity_disclient.php");
}
function LoadSetting()
{
	if(wlan_idx == "0")
		document.formRedirEncrypt.Wlanintf.options[0].selected = true;
	else
		document.formRedirEncrypt.Wlanintf.options[1].selected = true;
}

</script>
</head>

<body onload="LoadSetting();">
<blockquote>
<b><font size=3 face="arial" color="#3c7A95">연결 해제 설정</font></b>
<table border=0 width="540" cellspacing=4 cellpadding=0>
<tr><td><font size=2><br>
 현재 무선 인터넷(RADIUS 인증)으로 연결중인 클라이언트의 연결 해제를 위한 페이지입니다.
</font></td></tr>
<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<form action=/boafrm/formRedirWlEncrypt method=POST name="formRedirEncrypt">
	<table width="400" border="0">
		<tr>
			<td width="30%"><font size="2"><b>무선:</b></font></td>
			<td width="70%">
				<select name="Wlanintf" id="Wlanintf" onChange="page_change(this)">
					<option value="0">2.4 GHz</option>
					<option value="1">5 GHz</option>
				</select>
			</td>
		</tr>
	</table>
	<table width="580" border="0">
		<tr>
			<td colspan="4"><input type="button" value="다시 보기" name="reset"  onclick="resetForm()"></td>
			<td colspan="5" align="right"><input type="submit" value="전체 차단" name="disc_all" ></td>
		</tr>
	</table>
	<table width="580" border='1' cellspacing="1" cellpadding="2">
		<tr align="center">
			<td width="80" class="tbl_title"><font size="2"><b>MAC 주소</b></font></td>
			<td width="60" class="tbl_title"><font size="2"><b>모드</b></font></td>
			<td width="60" class="tbl_title"><font size="2"><b>송신<br>kByte</b></font></td>
			<td width="60" class="tbl_title"><font size="2"><b>수신<br>kByte</b></font></td>
			<td width="60" class="tbl_title"><font size="2"><b>전송률<br>(Mbps)</b></font></td>
			<td width="60" class="tbl_title"><font size="2"><b>전원<br>절약</b></font></td>
			<td width="60" class="tbl_title"><font size="2"><b>남은<br>시간</b></font></td>
			<td width="80" class="tbl_title"><font size="2"><b>경과<br>시간</b></font></td>
			<td width="60" class="tbl_title"><font size="2"><b>차단</b></font></td>
		</tr>
		
		
		
		
		

	</table>

<input type="hidden" value=" " name="disc_sta_mac">
<input type="hidden" value="/skb_wlsecurity_disclient.php" name="submit-url">

</form>

</blockquote>
</body>
</html>

