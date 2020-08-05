<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<% getIndex("no-cache"); %>
<title> 무선 인터넷 기본 설정</title>
<script type="text/javascript" src="util_gw.js"> </script>
</head>
<body onload='mouse_r_click();'>
<form action=/boafrm/formWlSiteSurvey method=POST name='formWlSiteSurvey'>
<input type='hidden' value='AP ScanStart' name='refresh'>
<input type='hidden' value='/wlap_search.asp' name='submit-url'>
<script>
if ( <% getIndex("wlanStatus"); %>  == 0) {
	alert("무선이 꺼져있습니다. 설정 및 재부팅 후 다시 시도해주세요.");
	window.close();
} else {
	document.forms[0].submit();
}
</script>
</form>
</body>
</html>
