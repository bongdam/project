<?php
	date_default_timezone_set("Asia/seoul");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/class/dvcfg.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/class/dvshow.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/const.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/func/deviceHelper.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/class/dvsock.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/class/dvuci.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/class/dvcmd/dvcmd.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/func/common.php");
	header("Pragma: no-cache");
	header("Cache-Control: no-cache,must-revalidate");
	if(dv_session("login_flag") == ""){
		header("Location:/login.php");
		EXIT;
	}
	if(getTimestamp()-dv_session("session_time") > DEF_MAX_TIMEOUT){
		header("Location:/login.php");
		EXIT;
	}
	dv_set_session("session_time",getTimestamp());
?>