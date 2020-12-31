<?php
	require($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
	$user_id_ = dv_post("user_id");
	$user_pwd_ = dv_post("user_pwd");
	/*
	http_username=admin
	http_passwd=admin
	*/
	$cfg = new dvcfg();
	$cfg->read("dvui","nas");
	$arruser = $cfg->search("dvui.nas.user");
	$arrpass = $cfg->search("dvui.nas.pass");
	$arrpermit = $cfg->search("dvui.nas.permission");
	if($arruser != ""){
		$loginidx = array_search($user_id_, $arruser);
		$pass = AES_Encode($user_pwd_);
		if($loginidx === false){
			echo("0");
		}else{
			if($arrpass[$loginidx] == $pass){
				dv_set_session("webhard_flag","1");
				dv_set_session("wb_permit",$arrpermit[$loginidx]);
				dv_set_session("wb_session_time",getTimestamp());
				echo("1");
			}else{
				echo("0");
			}
		}
	}else{
		echo("0");
	}

?>