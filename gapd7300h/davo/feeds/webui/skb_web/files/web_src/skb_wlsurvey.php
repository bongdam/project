<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
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
<title>무선 AP 검색</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<style>
.on {display:on}
.off {display:none}
</style>
<script>
var wlan_idx= <?=$wlan_id?>;
var siteSurveyForm=document.wizardPocket;
var getFFVersion=navigator.userAgent.substring(navigator.userAgent.indexOf("Firefox")).split("/")[1]
//extra height in px to add to iframe in FireFox 1.0+ browsers
var FFextraHeight=getFFVersion>=0.1? 16 : 0
function SetCwinHeight(){

	if (document.getElementById){
		var iframeObj = document.getElementById("SSIDSiteSurvey");
		if (iframeObj){
			if (iframeObj.contentDocument && iframeObj.contentDocument.body.offsetHeight){
				iframeObj.height = iframeObj.contentDocument.body.offsetHeight;
			} else if (document.frames[iframeObj.name].document && document.frames[iframeObj.name].document.body.scrollHeight){
				iframeObj.height = document.frames[iframeObj.name].document.body.scrollHeight;
			}
		}
	}
}

function dyniframesize() {
	var iframename ="SSIDSiteSurvey";
	var pTar = null;
	if (document.getElementById){
		pTar = document.getElementById(iframename);
	}else{
		eval('pTar = ' + iframename + ';');
	}
	if (pTar && !window.opera){
		//begin resizing iframe
		pTar.style.display="block"

		if (pTar.contentDocument && pTar.contentDocument.body.offsetHeight){
			//ns6 syntax
			pTar.height = pTar.contentDocument.body.offsetHeight+FFextraHeight;
		}else if (pTar.Document && pTar.Document.body.scrollHeight){
			//ie5+ syntax
			pTar.height = pTar.Document.body.scrollHeight;
		}
	}
}
function button_color(f)
{
	f.refresh.disabled=true;
}
function button_color_active()
{
	document.wizardPocket.refresh.disabled=false;
}
function page_change(selectObj)
{
	if (selectObj.value==1)
		location.href='wlan_redriect.php?redirect-url=skb_wlsurvey.php&wlan_id=1';
	else
		location.href='wlan_redriect.php?redirect-url=skb_wlsurvey.php&wlan_id=0';
}
$(document).ready(function(){
	if(wlan_idx){
		document.wizardPocket.Wlanintf.options[1].selected = true;
	}else{
		document.wizardPocket.Wlanintf.options[0].selected = true;
	}
});

</script>
</head>
<body>
<blockquote>
<h2>
<?php
	if(dv_session("wlan_id") == "1"){
		echo("AP 검색 5G ");
	}elseif(dv_session("wlan_id") == "0"){
		echo("AP 검색 2.4G");
	}else{
		echo("Wireless Site Survey");
	}
?>
</h2>
<table border="0" width="500" cellspacing="0" cellpadding="0">
	<tr>
		<td><font size="2">주변에 있는 AP들에 대한 정보를 보여주는 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>
<form action="" method="POST" name="wizardPocket">
<span id="top_div" class="on">
<table border="0" width="500">
	<tr>
		<td width="30%"><font size="2"><b>무선:</b>
			<select name="Wlanintf" id="Wlanintf" onchange="page_change(this)">
				<option value="0">2.4 GHz</option>
				<option value="1">5 GHz</option>
			</select></td>
		<td width="70%"><input type="button" value=" 갱신 " name="refresh" onclick="button_color(this.form);SSIDSiteSurvey.window.siteSurvey(1);"></td>
	</tr>
</table>
<iframe id="SSIDSiteSurvey" name="SSIDSiteSurvey" onload="javascript:{SetCwinHeight();}" marginwidth="0" marginheight="0" frameborder="0" scrolling="no" src="skb_pocket_sitesurvey.php#form" width="800" height="0"></iframe>
<br>
</span>


<input type="hidden" value="/skb_wlsurvey.php" name="submit-url">
<span id = "wait_div" class = "off" >
Please wait...
</span>

</form>

</blockquote>
</body>
</html>
