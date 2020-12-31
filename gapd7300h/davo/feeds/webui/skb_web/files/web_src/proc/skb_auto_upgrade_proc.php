<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$mode = dv_post("UseAutoup");
	$server_url_ = dv_post("server_url");
	$pre_ = dv_post("pre");
	$datafile_ = dv_post("datafile");
	$uci = new uci();
	$uci->mode("set");
	if($mode == "swms"){
		$uci->set("swms.config.enable","1");
		if($server_url_ != "******************************" && $server_url_ != false){
			$uci->set("swms.config.server_url",$server_url_);
		}
		if($datafile_ != "********************" && $datafile_ != false){
			$uci->set("swms.config.cfg_file",$datafile_);
		}
//		if($pre_ != "**********" && $pre_ != false){
//			$uci->set("swms.config.prefix",$pre_);
//		}
		$uci->run();
		$uci->commit();
		header("Location:".dv_post("submit-url"));
	}elseif($mode == "ldap"){
		$uci->set("swms.config.enable","");
		$uci->run();
		$uci->commit();
		header("Location:".dv_post("submit-url"));
	}elseif($mode == "disable"){
		$uci->set("swms.config.enable","0");
		$uci->run();
		$uci->commit();
		header("Location:".dv_post("submit-url"));
	}
?>