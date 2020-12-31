<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");

	$act_ = dv_post("act");
	if($act_ == "form_save"){
		$enable_ = dv_post("frm_enable");
		$day_check_ = dv_post("frm_day_check");
		$hour_range_ = dv_post("frm_hour_range");
		$wl_traffic_avg_data_ = dv_post("frm_wl_traffic_avg_data");

		$uci = new uci();
		$uci->mode("set");
		if($enable_ != ""){
			$uci->set("dvmgmt.smart_reset.enable",$enable_);
		}
		if($day_check_ != ""){
			$uci->set("dvmgmt.smart_reset.day_check",$day_check_);
		}
		if($hour_range_ != ""){
			$uci->set("dvmgmt.smart_reset.hour_range",$hour_range_);
		}
		if($wl_traffic_avg_data_ != ""){
			$uci->set("dvmgmt.smart_reset.wl_traffic_avg_data",$wl_traffic_avg_data_);
		}
		$uci->run();
		$uci->commit();
		$param = null;
		$sock = new rcqm();
		$sock->connect();
		if($sock->con()){
			$sock->write("wifi_auto_reboot",$param);
		}
		$uci->close();
		header("Location:".dv_post("submit-url"));
	}elseif($act_ == "run_now_restart"){
		$cmd = new dvcmd();
		$cmd->add("dvmgmt","TEST/SKb2gbw_restart");
		$cmd->add("wifi_restart");
		$cmd->run();
		$cmd->result();
		$cmd->close();
		echo(1);
	}
//	echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));
?>