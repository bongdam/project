<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/func/qca_common.php");
	$act_ = dv_post("act");
	$data_ = dv_post("data");

	if($act_ == "add_rule"){
//		print_r($data_);
		$uci = new uci();
		$uci->mode("del");
		for($i=1; $i <= 60; $i++){
			$uci->del("child_guard.child_guard_".$i);
		}
		$uci->run();
		if($data_ != false){
			$uci->mode("set");
			$num = 1;
			for($i=0; $i < count($data_); $i++){
	//			print_r($data_[$i]);
				$uci->set("child_guard.child_guard_".$num,"child_guard");
				$uci->set("child_guard.child_guard_".$num.".num",$num);
				$uci->set("child_guard.child_guard_".$num.".name",$data_[$i]["name"]);
				$uci->set("child_guard.child_guard_".$num.".mac",$data_[$i]["mac"]);
				$uci->set("child_guard.child_guard_".$num.".start_time",$data_[$i]["start_time"]);
				$uci->set("child_guard.child_guard_".$num.".end_time",$data_[$i]["end_time"]);
				$uci->set("child_guard.child_guard_".$num.".mode",$data_[$i]["rule"]);

				$uci->set("child_guard.child_guard_".$num.".sun",$data_[$i]["week"][0]);
				$uci->set("child_guard.child_guard_".$num.".mon",$data_[$i]["week"][1]);
				$uci->set("child_guard.child_guard_".$num.".tue",$data_[$i]["week"][2]);
				$uci->set("child_guard.child_guard_".$num.".wed",$data_[$i]["week"][3]);
				$uci->set("child_guard.child_guard_".$num.".thu",$data_[$i]["week"][4]);
				$uci->set("child_guard.child_guard_".$num.".fri",$data_[$i]["week"][5]);
				$uci->set("child_guard.child_guard_".$num.".sat",$data_[$i]["week"][6]);
				$num++;
			}
			$uci->run();
		}
		$uci->commit();
		$uci->close();
		dv_set_session("child_guard_set","1");
		echo("1");
	}elseif($act_ == "get_rule"){
		$cfg = new dvcfg();
		$cfg->read("child_guard","child_guard");
		print_r($cfg->result("json_string"));
	}elseif($act_ == "all_del_rule"){
		$uci = new uci();
		$uci->mode("del");
		for($i=1; $i <= 60; $i++){
			$uci->del("child_guard.child_guard_".$i);
		}
		$uci->run();
		$uci->commit();
		$uci->close();
		dv_set_session("child_guard_set","1");
		echo("1");
	}elseif($act_ == "apply_rule"){
		dv_set_session("child_guard_set","");
		$cmd = new dvcmd();
		$cmd->add("dvmgmt","TEST/SKb2gbw_restart");
		$cmd->add("snmp_restart");
		$cmd->add("child_guard");
		$cmd->run();
		$cmd->close();
		echo("1");
	}elseif($act_ == "restart_ntp"){
		$cmd = new dvcmd();
		$cmd->add("ntp_restart");
		$cmd->run();
		$cmd->close();
		echo getTimestamp();
	}

	

?>