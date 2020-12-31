<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$enabled_ = dv_post("enabled");
	$rlog_enabled_ = dv_post("rlog_enabled");
	$rlog_ip_ = dv_post("rlog_ip");
	$uci = new uci();
	$uci->mode("set");
	$uci->set("dvlog.log_web_cfg.enabled",$enabled_);
	$uci->set("dvlog.log_web_cfg.rlog_enabled",$rlog_enabled_);
	$uci->set("dvlog.log_web_cfg.rlog_ip",$rlog_ip_);
	$uci->run();
	$uci->result();
	$uci->commit();
	$uci->close();
	$cmd = new dvcmd();
	$cmd->add("dvlog_restart");
	$cmd->run();
	$cmd->result();
	$cmd->close();
?>