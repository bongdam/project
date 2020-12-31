<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$act_ = dv_post("act");
	$wlan_id = dv_session("wlan_id");
	$seq_ = dv_post("seq");
	if($wlan_id == "0"){
		$radio = "1";
	}else{
		$radio = "0";
	}
	switch($act_){
		case "get_mac_list":
			$cfg = new dvcfg();
			$cfg->read("wireless","vap".$radio.$seq_);
			$cfg->result_remove("wireless.vap".$radio.$seq_.".key");
			$cfg->result_remove("wireless.vap".$radio.$seq_."._orig_key");
			$cfg->result_remove("wireless.vap".$radio.$seq_.".key1");
			$cfg->result_remove("wireless.vap".$radio.$seq_."._orig_key1");
			$cfg->result_remove("wireless.vap".$radio.$seq_.".key2");
			$cfg->result_remove("wireless.vap".$radio.$seq_."._orig_key2");
			$cfg->result_remove("wireless.vap".$radio.$seq_.".key3");
			$cfg->result_remove("wireless.vap".$radio.$seq_."._orig_key3");
			$cfg->result_remove("wireless.vap".$radio.$seq_.".key4");
			$cfg->result_remove("wireless.vap".$radio.$seq_."._orig_key4");
			echo $cfg->result("json_string");
			break;
		case "set_mac_list":
			$mode = dv_post("mode");
			$seq = dv_post("seq");
			$data = dv_post("data");

			$mac = Array();
			$comment = Array();
			for($i=0; $i < count($data); $i++){
				$mac[$i] = $data[$i]["mac"];
				$comment[$i] = $data[$i]["comment"];
			}
			$uci = new uci();
			
			if($mode !=  "-1"){
				$uci->set("wireless.vap".$radio.$seq.".macaddr_acl",$mode);
			}else{
				$uci->del("wireless.vap".$radio.$seq.".macaddr_acl");
			}
			if(count($mac) == 0){
				$uci->del("wireless.vap".$radio.$seq.".maclist");
				$uci->del("wireless.vap".$radio.$seq.".comment");
			}else{
				$uci->set("wireless.vap".$radio.$seq.".maclist",$mac);
				$uci->set("wireless.vap".$radio.$seq.".comment",$comment);
			}
			$uci->mode("del");
			$uci->run();
			$uci->mode("set");
			$uci->run();
			$uci->commit();
			echo("1");
			break;
		case "del_all_data":
			$mode = dv_post("mode");
			$seq = dv_post("seq");
			$uci = new uci();
			if($mode !=  "-1"){
				$uci->set("wireless.vap".$radio.$seq.".macaddr_acl",$mode);
			}else{
				$uci->del("wireless.vap".$radio.$seq.".macaddr_acl");
			}
			$uci->del("wireless.vap".$radio.$seq.".maclist");
			$uci->del("wireless.vap".$radio.$seq.".comment");
			$uci->mode("del");
			$uci->run();
			$uci->commit();
			echo("1");
			break;
		case "data_apply":
			$mode = dv_post("mode");
			$seq = dv_post("seq");
			$uci = new uci();
			if($mode !=  "-1"){
				$uci->mode("set");
				$uci->set("wireless.vap".$radio.$seq.".macaddr_acl",$mode);
			}else{
				$uci->mode("del");
				$uci->del("wireless.vap".$radio.$seq.".macaddr_acl");
			}
			$uci->run();
			$uci->commit();
			$cmd = new dvcmd();
			$cmd->add("dvmgmt","TEST/SKb2gbw_restart");
			$cmd->add("snmp_restart");
			$cmd->add("wifi_restart");
			$cmd->run();
			$cmd->close();
			echo("1");
			break;
	}
?>