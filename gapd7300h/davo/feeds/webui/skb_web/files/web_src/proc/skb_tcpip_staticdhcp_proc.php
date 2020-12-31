<?php
	require_once($_SERVER["DOCUMENT_ROOT"]."/inc/default_ssi.php");
	require_once($_SERVER["DOCUMENT_ROOT"]."/skb_common.php");
	$act_ = dv_post("act");
	Switch($act_){
		Case "add_ipaddr":
			$uci = new uci();
			$uci->mode("set");
			$ip = dv_post("static_ip");
			$mac = dv_post("static_mac");
			$name = dv_post("static_name");
			$no = dv_post("no");
			if($no == ""){
				$no = "1";
			}
			$uci->set("dhcp.host_".$no,"host");
			$uci->set("dhcp.host_".$no.".ip",$ip);
			$uci->set("dhcp.host_".$no.".mac",$mac);
			$uci->set("dhcp.host_".$no.".name",$name);
			$uci->run();
			$uci->commit();
			$uci->close();
			$cmd = new dvcmd();
			$cmd->add("dhcp_reload");
			$cmd->run();
			$cmd->result();
			$cmd->close();
			echo("1");
			break;
		Case "get_static_list":
			$uci = new uci();
			$uci->mode("get");
			for($i=1; $i <= 30; $i++){
				$uci->get("dhcp.host_".$i);
			}
			$uci->run();
			$uci->set_head_json();
			$rtn = $uci->result();
			echo($rtn);
			$uci->close();
			break;
		Case "del_list":
			$uci = new uci();
			$uci->mode("del");
			for($i=1; $i <= 30; $i++){
				$uci->del("dhcp.host_".$i);
			}
			$uci->run();
			
			$del_list = dv_post("del_list");
			$no = 1;
			if($del_list != false){
				$uci->mode("set");
				for($i=0; $i < count($del_list); $i++){
					//print_r($del_list[$i]["ip"]);
					$uci->set("dhcp.host_".$no,"host");
					$uci->set("dhcp.host_".$no.".ip",$del_list[$i]["ip"]);
					$uci->set("dhcp.host_".$no.".mac",$del_list[$i]["mac"]);
					$uci->set("dhcp.host_".$no.".name",$del_list[$i]["host"]);
					$no = $no + 1;
				}
				$uci->run();
			}
			$uci->commit();
			$uci->close();
			$cmd = new dvcmd();
			$cmd->add("dhcp_reload");
			$cmd->run();
			$cmd->result();
			$cmd->close();
			echo("1");
			break;
	}
?>