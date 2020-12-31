<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$act = dv_post("act");

	Switch($act){
		case "save_time":
			$ntp_enable = dv_post("ntp_enable");
			$com_time = dv_post("com_time");
			$ntp_prio = dv_post("ntp_prio");
			$ntp_server1 = dv_post("ntp_server1");
			$ntp_server2 = dv_post("ntp_server2");
			$uci = new uci();
			$uci->mode("set");
			if($ntp_enable == "1"){
				$uci->set("system.ntp.enabled","1");
				$uci->set("system.ntp.primary",$ntp_prio);
				$uci->set("system.ntp.server1",$ntp_server1);
				$uci->set("system.ntp.server2",$ntp_server2);
				$uci->run();
				$uci->commit();
				$uci->close();
				$cmd = new dvcmd();
				$cmd->add("ntp_restart");
				$cmd->run();
				$cmd->result();
				$cmd->close();
				echo "1";
			}else{
				$uci->set("system.ntp.enabled","0");
				$uci->set("system.ntp.primary",$ntp_prio);
				$uci->set("system.ntp.server1",$ntp_server1);
				$uci->set("system.ntp.server2",$ntp_server2);
				$uci->run();
				$uci->commit();
				$uci->close();
				$cmd = new dvcmd();
				$cmd->add("ntp_stop");
				$cmd->add("date_set", $com_time);
				$cmd->run();
				$cmd->result();
				$cmd->close();
				echo "1";
			}
			
			break;
	}
?>