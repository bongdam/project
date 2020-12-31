<?php
	date_default_timezone_set("Asia/seoul");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/class/dvcfg.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/class/dvshow.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/const.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/func/deviceHelper.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/func/htmlHelper.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/class/dvsock.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/class/dvuci.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/class/dvcmd/dvcmd.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/func/common.php");
	header("Pragma: no-cache");
	header("Cache-Control: no-cache,must-revalidate");
	if(dv_session("login_flag") == ""){
//		@session_start();
//		$ses_con = json_encode($_SESSION);
//		@session_write_close(); 
//		web_log_save("/tmp/web_log","LOGOUT","default_ssi Session empty |" .dv_session("login_flag")."|".$ses_con);
		
		header("Location:/pages/login.php");
		EXIT;
	}
	if(getTimestamp()-dv_session("session_time") > DEF_MAX_TIMEOUT){
//		@session_start();
//		$ses_con = json_encode($_SESSION);
//		@session_write_close(); 
//		web_log_save("/tmp/web_log","LOGOUT","Session time out 10min".DEF_MAX_TIMEOUT."|".dv_session("session_time")."|".getTimestamp()."|".$ses_con);
		
		header("Location:/pages/login.php");
		EXIT;
	}
	dv_set_session("session_time",getTimestamp());
?>