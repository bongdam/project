<?php
	require_once($_SERVER["DOCUMENT_ROOT"]."/inc/default_ssi.php");
	require_once($_SERVER["DOCUMENT_ROOT"]."/skb_common.php");
	$act_ = dv_post("act");

	
	Switch($act_){
		case "add_static_mapping":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("firewall.dmz");
			$uci->run();
			$dmz = json_decode($uci->result());
			$dmz_use = 0;
			if(std_get_val($dmz,"firewall.dmz.dest_ip") != ""){
				$dmz_use = 1;
			}
			$seq = dv_post("seq");
			$s_ip_ = dv_post("s_ip");
			$s_port_ = dv_post("s_port");
			$protocol_ = dv_post("protocol");
			$d_ip_ = dv_post("d_ip");
			$d_port_ = dv_post("d_port");

			/*
			config redirect           
			option target 'DNAT'
			option src 'wan'     
			option dest 'lan'     
			option proto 'tcp'                    <-- protocol tcp,udp,'tcp udp'
			option src_dport '12312'              <-- WAN I/F port 
			option dest_ip '192.168.1.118'        <-- LAN에 위치한 HOST IP
			option dest_port '12312'              <-- HOST의 port 번호
			option name 'test'                    <-- 포트 포워딩 이름
			*/
			$uci->mode("set");
			$uci->set("firewall.staticmapping_".$seq,"redirect");
			$uci->set("firewall.staticmapping_".$seq.".name","static_mapping");
			$uci->set("firewall.staticmapping_".$seq.".target","DNAT");
			$uci->set("firewall.staticmapping_".$seq.".src","wan");
			$uci->set("firewall.staticmapping_".$seq.".dest","lan");
			$uci->set("firewall.staticmapping_".$seq.".src_ip",$s_ip_);
			$uci->set("firewall.staticmapping_".$seq.".src_dport",$s_port_);
			$uci->set("firewall.staticmapping_".$seq.".proto",$protocol_);
			$uci->set("firewall.staticmapping_".$seq.".dest_ip",$d_ip_);
			$uci->set("firewall.staticmapping_".$seq.".dest_port",$d_port_);
			$uci->run();



			if($dmz_use == 1){
				$uci->mode("del");
				$uci->del("firewall.dmz");
				$uci->run();
				$uci->mode("set");
				$uci->set("firewall.dmz","redirect");
				$uci->set("firewall.dmz.target","DNAT");
				$uci->set("firewall.dmz.src","wan");
				$uci->set("firewall.dmz.dest","lan");
				$uci->set("firewall.dmz.proto","all");
				$uci->set("firewall.dmz.name","DMZ");
				$uci->set("firewall.dmz.dest_ip",std_get_val($dmz,"firewall.dmz.dest_ip"));
				$uci->run();
			}
			$uci->commit();
			$uci->close();
			$cmd = new dvcmd();
			$cmd->add("firewall_restart");
			$cmd->run();
			$cmd->result();
			$cmd->close();
			echo("1");
			break;
		case "get_static_mapping":
			$uci = new uci();
			for($i=1; $i<= 32; $i++){
				$uci->get("firewall.staticmapping_".$i);
			}
			$uci->run();
			$uci->set_head_json();
			echo( json_encode(json_decode($uci->result(),true)));

			break;
		case "del_static_mapping":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("firewall.dmz");
			$uci->run();
			$dmz = json_decode($uci->result());
			$dmz_use = 0;
			if(std_get_val($dmz,"firewall.dmz.dest_ip") != ""){
				$dmz_use = 1;
			}
			$uci->mode("del");
			for($i=1; $i <= 32; $i++){
				$uci->del("firewall.staticmapping_".$i);
			}
			$uci->run();
			$del_list = dv_post("del_list");
			$no = 1;
			if($del_list != false){
				$uci->mode("set");
				for($i=0; $i < count($del_list); $i++){
					$uci->set("firewall.staticmapping_".$no,"redirect");
					$uci->set("firewall.staticmapping_".$no.".name","static_mapping");
					$uci->set("firewall.staticmapping_".$no.".target","DNAT");
					$uci->set("firewall.staticmapping_".$no.".src","wan");
					$uci->set("firewall.staticmapping_".$no.".dest","lan");
					$uci->set("firewall.staticmapping_".$no.".src_ip",$del_list[$i]["s_ip"]);
					$uci->set("firewall.staticmapping_".$no.".src_dport",$del_list[$i]["s_port"]);
					$uci->set("firewall.staticmapping_".$no.".proto",$del_list[$i]["proto"]);
					$uci->set("firewall.staticmapping_".$no.".dest_ip",$del_list[$i]["d_ip"]);
					$uci->set("firewall.staticmapping_".$no.".dest_port",$del_list[$i]["d_port"]);
					$no = $no + 1;
				}
				$uci->run();
			}
			if($dmz_use == 1){
				$uci->mode("del");
				$uci->del("firewall.dmz");
				$uci->run();
				$uci->mode("set");
				$uci->set("firewall.dmz","redirect");
				$uci->set("firewall.dmz.target","DNAT");
				$uci->set("firewall.dmz.src","wan");
				$uci->set("firewall.dmz.dest","lan");
				$uci->set("firewall.dmz.proto","all");
				$uci->set("firewall.dmz.name","DMZ");
				$uci->set("firewall.dmz.dest_ip",std_get_val($dmz,"firewall.dmz.dest_ip"));
				$uci->run();
			}
			$uci->commit();
			$uci->close();
			$cmd = new dvcmd();
			$cmd->add("firewall_restart");
			$cmd->run();
			$cmd->result();
			$cmd->close();
			echo("1");
			break;
		case "del_all_static_mapping":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("firewall.dmz");
			$uci->run();
			$dmz = json_decode($uci->result());
			$dmz_use = 0;
			if(std_get_val($dmz,"firewall.dmz.dest_ip") != ""){
				$dmz_use = 1;
			}
			$uci->mode("del");
			for($i=1; $i <= 32; $i++){
				$uci->del("firewall.staticmapping_".$i);
			}
			$uci->run();
			$uci->result();
			if($dmz_use == 1){
				$uci->mode("del");
				$uci->del("firewall.dmz");
				$uci->run();
				$uci->mode("set");
				$uci->set("firewall.dmz","redirect");
				$uci->set("firewall.dmz.target","DNAT");
				$uci->set("firewall.dmz.src","wan");
				$uci->set("firewall.dmz.dest","lan");
				$uci->set("firewall.dmz.proto","all");
				$uci->set("firewall.dmz.name","DMZ");
				$uci->set("firewall.dmz.dest_ip",std_get_val($dmz,"firewall.dmz.dest_ip"));
				$uci->run();
			}
			$uci->commit();
			$uci->close();
			$cmd = new dvcmd();
			$cmd->add("firewall_restart");
			$cmd->run();
			$cmd->result();
			$cmd->close();
			echo("1");
			break;
	}

	
?>