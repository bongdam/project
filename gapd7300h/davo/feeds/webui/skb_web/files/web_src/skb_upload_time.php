<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<script type="text/javascript" src="js/skb_util_gw.js"></script>
<link href="style.css" rel="stylesheet" type="text/css">
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<style type="text/css">
.on {display:on}
.off {display:none}
</style>
<script type="text/javascript">
var count = 60 * <?=$firmTime?>;
function get_by_id(id)
{
	with(document)
	{
		return getElementById(id);
	}
}
function change_state(istate)
{
	if(count == 3)
	  get_by_id("show_msg").className = "off";
	if(1)
		return;
	if(parent.frames[1])
	{
		parent.frames[1].state = istate;
//		MTMDisplayMenu();
	}
}
function do_count_down()
{
	get_by_id("show_sec").innerHTML = count;
	if(count == 0)
	{
		var browser=eval ( '"' + top.location + '"' );
		var domainName = "Davolink";
		var connect_url;
		var redirect_ip = "172.17.122.160";
		change_state('normal');
		connect_url=redirect_ip;
		var lastUrl="";
		top.location.href="http://<?=$_SERVER['HTTP_HOST']?>";
//		if(lastUrl == "/skb_home.php")
//		{
//			parent.location.href = 'http://'+connect_url;
//		} else {
//			var location_href = 'http://'+connect_url+lastUrl+'?t='+new Date().getTime();
//			parent.frames[4].location.assign(lastUrl);
//		}
		return false;
	}
	if (count > 0)
	{
		count--;
		setTimeout('do_count_down()',1000);
	}
}
var apply_firmware = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'apply';
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:"proc/skb_upload_proc.php",
		"dataType":"text",
		"type":"POST",
		success:function(d){
			
		}
	});
	do_count_down();
}
$(document).ready(function(){
	change_state('normal');
	apply_firmware();
});
</script>
</head>
<body>
<blockquote>
	<br><br><b>업로드 성공!!</b><br><br>펌웨어 업그레이드 진행중...<br><b><font color="red" size="2">(주의!) 단말의 전원및 인터넷(랜) 케이블 연결을 분리하지 마세요.</font></b><br><br>
	<span id="show_msg">재부팅중이니 장치의 전원을 끄지말고 잠시 기다려주시기 바랍니다.</span>
	</h4>
	<p align=left>
		<h4><b><span id="show_sec" class="on"></span></b>&nbsp;<span id=show_seconds>초 남았습니다 ...</span></h4>
	</p>
</blockquote>
</body>
</html>
