<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<% getIndex("no-cache"); %>
<title> 무선 채널 검색 </title>
<script type="text/javascript" src="util_gw.js"> </script>
<% getInfo("include_css"); %>
<script>

var best_ch=0;

function disableReflesh(scanform)
{
	scanform.best_channel.value = "";
	disableButton(document.formWlSiteSurvey.ApScanSearch);
	disableButton(document.formWlSiteSurvey.ApScanSet);
    scanform.submit();
}

function display_best_ch_select()
{
	var color = "#FF0000";
	if(best_ch)
		show_best_ch_select.innerHTML = "최적채널 검색결과 권장채널은 <font color="+color+">"+best_ch+"번</font>입니다.";
}

function setbestchannel(scanform)
{
	var wlan_id = <% getIndex("wlan_idx"); %>;
	var chan_list = window.opener.document.wlanSetup.elements["chan"+wlan_id];

	alert("페이지 하단의 적용버튼을 클릭하시면 최적채널이 적용됩니다.")
	for(var i=0; i < chan_list.options.length; i++){
		if(chan_list.options[i].value == best_ch){
			chan_list.selectedIndex = i;
			break;
		}
	}
	window.close();
}

</script>
</head>
<body onload='mouse_r_click();'>
<blockquote>
<h2>
<script>
	var wlan_num =  <% getIndex("wlan_num"); %>;
	if (wlan_num > 1) {
		var wlan_idx_ = <% getIndex("wlan_idx"); %> + 1;
		if(wlan_idx_== 1)
			document.write("채널 검색 5G </p>");
		else
			document.write("채널 검색 2.4G </p>");
	}
</script>
</h2>
<SPAN id=show_best_ch_select></SPAN>

<table border=0 width="500" cellspacing=4 cellpadding=0>
<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<form action=/boafrm/formWlSiteSurvey method=POST name="formWlSiteSurvey">
	<table border="0" width=500>
	<tr>
		<td align="left">
			<input type="button" value="최적 채널 검색" name="ApScanSearch" onclick="disableReflesh(this.form);">
		</td>
		<td align="right">
			<input type="button" value="권장 채널 설정" name="ApScanSet" onclick="setbestchannel(this.form);">
		</td>
	</tr>
	<br>
		<font size=2> <SPAN id=show_warning_ch></SPAN></font>
	</table>
  <input type="hidden" value="AP ScanStart" name="refresh">
  <input type="hidden" value="/wlap_search.asp" name="submit-url">
  <input type="hidden" value="" name="best_channel">
<div id="display_channel_info" name="display_channel_info">
  <table border="0" width=500>
  <% wlSiteSurveyTbl("1"); %>
  </table>
</div>
  <br>
 <SCRIPT>display_best_ch_select();</SCRIPT>
 <script>
	var wlanState="<%getScheduleInfo("wlan_state");%>";

	if (wlanState=="Disabled") {
		disableButton(document.formWlSiteSurvey.ApScanSearch);
		disableButton(document.formWlSiteSurvey.ApScanSet);
	}

	if (best_ch==12 || best_ch==13)
	    show_warning_ch.innerHTML = "(채널 <font color='red'>12, 13 </font>선택 시 일부 클라이언트의 <font color='red'>접속 제한</font>이 발생할 수 있습니다.)";
 </script>

 <table border='0' width=500>
	<tr>
		<td align="right">
			<input type="button" value=" 닫기 " name="close" onClick="javascript: window.close();">
		</td>
	</tr>
</table>

</form>

</blockquote>
</body>
</html>
