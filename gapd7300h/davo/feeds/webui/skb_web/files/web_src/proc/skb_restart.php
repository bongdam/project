<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");

	echo(rtn_reboot_page(dv_post("submit-url"),dv_post("act")));
?>