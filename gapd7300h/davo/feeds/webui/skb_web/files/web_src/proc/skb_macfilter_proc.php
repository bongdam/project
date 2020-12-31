<?php
	require_once($_SERVER["DOCUMENT_ROOT"]."/inc/default_ssi.php");
	require_once($_SERVER["DOCUMENT_ROOT"]."/skb_common.php");
	$act_ = dv_post("act");
	switch($act_){
		case "get_macfilter":
//			$uci = new uci();
//			$uci->mode("get");
//			$port_no = dv_session("lan_no");
//			$seq = 1;
//			$result = Array();
//			for($i=0; $i < DEF_MAX_LAN; $i++){
//				$seq = 1;
//				for($j=1; $j <= 4; $j++){
//					$uci->get("network.fdbentry_lan_".$port_no."_".$seq);
////					$uci->get("network.fdbentry_lan_".$port_no."_".$seq.".device");
////					$uci->get("network.fdbentry_lan_".$port_no."_".$seq.".sacmd");
////					$uci->get("network.fdbentry_lan_".$port_no."_".$seq.".addr");
////					$uci->get("network.fdbentry_lan_".$port_no."_".$seq.".comment");
////					echo("network.fdbentry_lan_".$port_no."_".$seq."\n");
//					$seq = $seq + 1;
//				}
//				
//				$port_no = $port_no + 1;
//			}
//			$uci->run();
//			echo $uci->result();
//			$uci->close();
			set_head_json();
			$sys = new dvcfg();
			$sys->read("macfilter","");
			print_r($sys->search("macfilter","json_string"));
			break;
		case "set_macfilter" :
			
			$lan_no = dv_session("lan_no");
			$seq = 1;
			$port_no = $lan_no;
			$uci = new uci();
			
			$lan1_ = dv_post("lan1");
			$lan2_ = dv_post("lan2");
			$lan3_ = dv_post("lan3");
			$lan4_ = dv_post("lan4");
			$lan1_mac = Array();
			$lan1_comment = Array();
			$lan2_mac = Array();
			$lan2_comment = Array();
			$lan3_mac = Array();
			$lan3_comment = Array();
			$lan4_mac = Array();
			$lan4_comment = Array();
			$mfacl_cnt = 0;
			$mfact_ruleid = 70;
			$uci->mode("del");
			for($j=0; $j <= 15; $j++){
				$uci->del("network.aclmf_".$j);
			}
			$uci->run();
			$uci->mode("set");

			function port_hex($port_){
				switch($port_){
					case "0":
						$bin = "000100";
						break;
					case "1":
						$bin = "001000";
						break;
					case "2":
						$bin = "010000";
						break;
					case "3":
						$bin = "100000";
						break;
				}
				$hex = "0x".dechex(bindec($bin));
				return $hex;
			}

			IF($lan1_ != false){
				if($lan1_[0]["status"] == "drop"){
					$lan1_mode = 2;
				}elseif($lan1_[0]["status"] == "forward"){
					$lan1_mode = 1;
				}
				$uci->set("macfilter.mf_lan_0.mode",$lan1_mode);
				
				for($i=0; $i < count($lan1_); $i++){
					array_push($lan1_mac,$lan1_[$i]["mac"]);
					array_push($lan1_comment,$lan1_[$i]["comment"]);
				}
				$uci->set("macfilter.mf_lan_0.mac",$lan1_mac);
				$uci->set("macfilter.mf_lan_0.comment",$lan1_comment);
				$phy_port1 = port_hex("0");
				if($lan1_mode == 2){
					for($i=0; $i < count($lan1_mac); $i++){
						$uci->set("network.aclmf_".$mfacl_cnt,"switch_ext");
						$uci->set("network.aclmf_".$mfacl_cnt.".device","switch0");
						$uci->set("network.aclmf_".$mfacl_cnt.".name","AclRule");
						$uci->set("network.aclmf_".$mfacl_cnt.".rule_id",$mfact_ruleid);
						$uci->set("network.aclmf_".$mfacl_cnt.".priority","1");
						$uci->set("network.aclmf_".$mfacl_cnt.".rule_type","mac");
						$uci->set("network.aclmf_".$mfacl_cnt.".port_bitmap",$phy_port1);
						$uci->set("network.aclmf_".$mfacl_cnt.".packet_drop","yes");
						$uci->set("network.aclmf_".$mfacl_cnt.".src_mac_address",str_replace(":","-",$lan1_mac[$i]));
						$uci->set("network.aclmf_".$mfacl_cnt.".src_mac_address_mask","ff-ff-ff-ff-ff-ff");
						$mfacl_cnt++;
						$mfact_ruleid++;
					}
				}
			}else{
				$lan1_mode = 0;
				$uci->set("macfilter.mf_lan_0.mode","0");
				$uci->set("macfilter.mf_lan_0.mac",$lan1_mac);
				$uci->set("macfilter.mf_lan_0.comment",$lan1_comment);
			}
			IF($lan2_ != false){
				if($lan2_[0]["status"] == "drop"){
					$lan2_mode = 2;
				}elseif($lan2_[0]["status"] == "forward"){
					$lan2_mode = 1;
				}
				$uci->set("macfilter.mf_lan_1.mode",$lan2_mode);
				
				for($i=0; $i < count($lan2_); $i++){
					array_push($lan2_mac,$lan2_[$i]["mac"]);
					array_push($lan2_comment,$lan2_[$i]["comment"]);
				}
				$uci->set("macfilter.mf_lan_1.mac",$lan2_mac);
				$uci->set("macfilter.mf_lan_1.comment",$lan2_comment);
				$phy_port2 = port_hex("1");
				if($lan2_mode == 2){
					for($i=0; $i < count($lan2_mac); $i++){
						$uci->set("network.aclmf_".$mfacl_cnt,"switch_ext");
						$uci->set("network.aclmf_".$mfacl_cnt.".device","switch0");
						$uci->set("network.aclmf_".$mfacl_cnt.".name","AclRule");
						$uci->set("network.aclmf_".$mfacl_cnt.".rule_id",$mfact_ruleid);
						$uci->set("network.aclmf_".$mfacl_cnt.".priority","1");
						$uci->set("network.aclmf_".$mfacl_cnt.".rule_type","mac");
						$uci->set("network.aclmf_".$mfacl_cnt.".port_bitmap",$phy_port2);
						$uci->set("network.aclmf_".$mfacl_cnt.".packet_drop","yes");
						$uci->set("network.aclmf_".$mfacl_cnt.".src_mac_address",str_replace(":","-",$lan2_mac[$i]));
						$uci->set("network.aclmf_".$mfacl_cnt.".src_mac_address_mask","ff-ff-ff-ff-ff-ff");
						$mfacl_cnt++;
						$mfact_ruleid++;
					}
				}
			}else{
				$uci->set("macfilter.mf_lan_1.mode","0");
				$uci->set("macfilter.mf_lan_1.mac",$lan2_mac);
				$uci->set("macfilter.mf_lan_1.comment",$lan2_comment);
			}
			IF($lan3_ != false){
				if($lan3_[0]["status"] == "drop"){
					$lan3_mode = 2;
				}elseif($lan3_[0]["status"] == "forward"){
					$lan3_mode = 1;
				}
				$uci->set("macfilter.mf_lan_2.mode",$lan3_mode);
				for($i=0; $i < count($lan3_); $i++){
					array_push($lan3_mac,$lan3_[$i]["mac"]);
					array_push($lan3_comment,$lan3_[$i]["comment"]);
				}
				$uci->set("macfilter.mf_lan_2.mac",$lan3_mac);
				$uci->set("macfilter.mf_lan_2.comment",$lan3_comment);
				$phy_port3 = port_hex("2");
				if($lan3_mode == 2){
					for($i=0; $i < count($lan3_mac); $i++){
						$uci->set("network.aclmf_".$mfacl_cnt,"switch_ext");
						$uci->set("network.aclmf_".$mfacl_cnt.".device","switch0");
						$uci->set("network.aclmf_".$mfacl_cnt.".name","AclRule");
						$uci->set("network.aclmf_".$mfacl_cnt.".rule_id",$mfact_ruleid);
						$uci->set("network.aclmf_".$mfacl_cnt.".priority","1");
						$uci->set("network.aclmf_".$mfacl_cnt.".rule_type","mac");
						$uci->set("network.aclmf_".$mfacl_cnt.".port_bitmap",$phy_port3);
						$uci->set("network.aclmf_".$mfacl_cnt.".packet_drop","yes");
						$uci->set("network.aclmf_".$mfacl_cnt.".src_mac_address",str_replace(":","-",$lan3_mac[$i]));
						$uci->set("network.aclmf_".$mfacl_cnt.".src_mac_address_mask","ff-ff-ff-ff-ff-ff");
						$mfacl_cnt++;
						$mfact_ruleid++;
					}
				}
			}else{
				$uci->set("macfilter.mf_lan_2.mode","0");
				$uci->set("macfilter.mf_lan_2.mac",$lan3_mac);
				$uci->set("macfilter.mf_lan_2.comment",$lan3_comment);
			}
			IF($lan4_ != false){
				if($lan4_[0]["status"] == "drop"){
					$lan4_mode = 2;
				}elseif($lan4_[0]["status"] == "forward"){
					$lan4_mode = 1;
				}
				$uci->set("macfilter.mf_lan_3.mode",$lan4_mode);
				for($i=0; $i < count($lan4_); $i++){
					array_push($lan4_mac,$lan4_[$i]["mac"]);
					array_push($lan4_comment,$lan4_[$i]["comment"]);
				}
				$uci->set("macfilter.mf_lan_3.mac",$lan4_mac);
				$uci->set("macfilter.mf_lan_3.comment",$lan4_comment);
				$phy_port4 = port_hex("3");
				if($lan4_mode == 2){
					for($i=0; $i < count($lan4_mac); $i++){
						$uci->set("network.aclmf_".$mfacl_cnt,"switch_ext");
						$uci->set("network.aclmf_".$mfacl_cnt.".device","switch0");
						$uci->set("network.aclmf_".$mfacl_cnt.".name","AclRule");
						$uci->set("network.aclmf_".$mfacl_cnt.".rule_id",$mfact_ruleid);
						$uci->set("network.aclmf_".$mfacl_cnt.".priority","1");
						$uci->set("network.aclmf_".$mfacl_cnt.".rule_type","mac");
						$uci->set("network.aclmf_".$mfacl_cnt.".port_bitmap",$phy_port4);
						$uci->set("network.aclmf_".$mfacl_cnt.".packet_drop","yes");
						$uci->set("network.aclmf_".$mfacl_cnt.".src_mac_address",str_replace(":","-",$lan4_mac[$i]));
						$uci->set("network.aclmf_".$mfacl_cnt.".src_mac_address_mask","ff-ff-ff-ff-ff-ff");
						$mfacl_cnt++;
						$mfact_ruleid++;
					}
				}
			}else{
				$uci->set("macfilter.mf_lan_3.mode","0");
				$uci->set("macfilter.mf_lan_3.mac",$lan4_mac);
				$uci->set("macfilter.mf_lan_3.comment",$lan4_comment);
			}
			print_r($uci->get_param());


			$uci->run();
			$uci->result();
			$uci->commit();
			echo("1");
			break;
		case "macfilter_apply":
			echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));
			break;
	}
?>
