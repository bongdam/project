<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<link rel="stylesheet" rev="stylesheet" href="style.css" type="text/css">
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_navigation.js"></script>
<script type="text/javascript" src="js/skb_fadeFont.js"></script>
<title>test</title>
</head>
<body style="background-color: #3B9DCC">
<script type="text/javascript">
	draw_subnav_head();
	draw_subnav_setup();
	draw_subnav_tail();
	init_submenu("상태정보");

</script>
</body>
</html>