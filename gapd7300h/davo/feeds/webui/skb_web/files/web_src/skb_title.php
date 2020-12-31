<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	$con_mode = dv_session("con_mode");
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<link rel="stylesheet" rev="stylesheet" href="style.css" type="text/css">
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript">
var seschk;
var proc = "proc/skb_chk.php";
var check_user_session = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'session_check';
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		"timeout":2000,
		statusCode: {
			404: function() {
//				alert( "page not found" );
				console.log("page not found");
			},
			
		},
		success:function(d){
			if(d == "1"){
			}else{
				console.log(d);
//				setTimeout(function(){
//				$.cookie("logout_issue","session timeout");
				top.window.location.href="/skb_logout.php?flag=0";
//				},1000);
			}
		},
		error:function(a,b,c){
//			console.log(b);
//			top.window.location.href="/skb_logout.php";
		}
	});
}
var update_cookie = function(){
//	console.log(parseInt(get_timestamp(),10),parseInt($.cookie("magickey"),10),parseInt(get_timestamp(),10) - parseInt($.cookie("magickey"),10));
	if($.cookie("magickey") != null && $.cookie("magickey") != ""){
		if(parseInt(get_timestamp(),10) - parseInt($.cookie("magickey"),10) > 3000){
			$.cookie("magickey","");
//			$.cookie("logout_issue","magickey logout");
//			setTimeout(function(){
			top.window.location.href="/skb_logout.php?flag=1";
//			},1000);
			return;
		}
	}
	$.cookie("magickey",parseInt(get_timestamp(),10));
//	console.log($.cookie("magickey"),parseInt(CreateDummy(),10) - parseInt($.cookie("magickey"),10));
}
var check_shard_key = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'check_shard_key';
	sobj['shard_key'] = $.cookie("shared_key");
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		"timeout":2000,
		success:function(d){
			if(d == "0"){
				$.cookie("magickey","");
				$.cookie("shared_key","");
//				$.cookie("logout_issue","shared_key error logout");
				top.window.location.href="/skb_logout.php?flag=2";
			}
		}
	});
}
$(document).ready(function(){
	check_user_session();
	update_cookie();
	setInterval(update_cookie,1000);
	seschk = setInterval(check_user_session,10000);

	var con_mode = "<?=$con_mode?>";
	if(con_mode == "local"){
		check_shard_key();
	}
});
</script>
</head>
<body style="padding: 1px;">
<img src="img/topbar_H824G.jpg" width="1022" height="124" border="0" align="middle">
</body>
</html>
 