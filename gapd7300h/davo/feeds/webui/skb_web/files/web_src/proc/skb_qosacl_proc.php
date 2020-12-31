<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
//	create_post_value();
	$wan_no = dv_post("wan_no");
	$lan_no = dv_post("lan_no");

	$act_ = dv_post("act");
	$rule_id_ = dv_post("rule_id");
	
	Switch($act_){
		case "rule_add":
			$rule_type_	= dv_post("rule_type");
			$port_bitmap_ = dv_post("port_bitmap");
			$packet_drop_ = dv_post("packet_drop");
			$vlan_id_ = dv_post("vlan_id");
			$vlan_priority_ = dv_post("vlan_priority");

			$phy_port_ = dv_post("phy_port");

			$mac_start_use_ = dv_post("mac_start_use");
			$mac_start_ = dv_post("mac_start");
			if($mac_start_ != ""){
				$mac_start_ = str_replace(":","-",$mac_start_);
			}
			$mac_end_use_ = dv_post("mac_end_use");
			$mac_end_ = dv_post("mac_end");
			if($mac_end_ != ""){
				$mac_end_ = str_replace(":","-",$mac_end_);
			}
			$ether_use_ = dv_post("ether_use");
			$ether_ = dv_post("ether");

			$iprio_ = dv_post("iprio");
			$premark_ = dv_post("premark");
			$dscp_remark_ = dv_post("dscp_remark");
			$ip_protocol_ = dv_post("ip_protocol");
			$ip_tos_ = dv_post("ip_tos");
			$ip_dscp_ = dv_post("ip_dscp");

			$srcip_ = dv_post("srcip");
			$srcmask_ = dv_post("srcmask");
			$srcport_ = dv_post("srcport");
			$dstip_ = dv_post("dstip");
			$dstmask_ = dv_post("dstmask");
			$dstport_ = dv_post("dstport");

			$uci = new uci();
			$uci->mode("del");
			$uci->del("network.aclrule_".$rule_id_);
			$uci->run();
			$uci->mode("set");
			$uci->set("network.aclrule_".$rule_id_,"switch_ext");
			$uci->set("network.aclrule_".$rule_id_.".device","switch0");
			$uci->set("network.aclrule_".$rule_id_.".name","AclRule");
			$uci->set("network.aclrule_".$rule_id_.".rule_id",$rule_id_);
			$uci->set("network.aclrule_".$rule_id_.".priority","1");
			$uci->set("network.aclrule_".$rule_id_.".rule_type",$rule_type_);
			$uci->set("network.aclrule_".$rule_id_.".port_bitmap",$port_bitmap_);
			$uci->set("network.aclrule_".$rule_id_.".packet_drop",$packet_drop_);
			if($phy_port_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".phy_mac_address","00-00-00-00-00-00");
				$uci->set("network.aclrule_".$rule_id_.".phy_mac_address_mask","ff-ff-ff-ff-ff-ff");
				$uci->set("network.aclrule_".$rule_id_.".inverse_check_fields","yes");
			}
			if($mac_start_use_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".src_mac_address",$mac_start_);
				$uci->set("network.aclrule_".$rule_id_.".src_mac_address_mask","ff-ff-ff-ff-ff-ff");
			}
			if($mac_end_use_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".dst_mac_address",$mac_end_);
				$uci->set("network.aclrule_".$rule_id_.".dst_mac_address_mask","ff-ff-ff-ff-ff-ff");
			}
			if($ether_use_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".ethernet_type",$ether_);
				$uci->set("network.aclrule_".$rule_id_.".ethernet_type_mask","0xfff");
			}
			if($vlan_id_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".vlan_id",$vlan_id_);
				$uci->set("network.aclrule_".$rule_id_.".vlan_id_mask","0xfff");
			}
			if($vlan_priority_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".vlan_priority",$vlan_priority_);
				$uci->set("network.aclrule_".$rule_id_.".vlan_priority_mask","0x07");
			}
			if($ip_protocol_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".ip_protocol",$ip_protocol_);
				$uci->set("network.aclrule_".$rule_id_.".ip_protocol_mask","0xff");
			}
			if($ip_tos_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".ip_dscp",$ip_tos_);
				$uci->set("network.aclrule_".$rule_id_.".ip_dscp_mask","0xff");
			}
			if($srcip_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".ipv4_src_address",$srcip_);
				$uci->set("network.aclrule_".$rule_id_.".ipv4_src_address_mask",$srcmask_);
			}
			if($srcport_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".ip_src_port",$srcport_);
				$uci->set("network.aclrule_".$rule_id_.".ip_src_port_mask","0xffff");
			}
			if($dstip_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".ipv4_dst_address",$dstip_);
				$uci->set("network.aclrule_".$rule_id_.".ipv4_dst_address_mask",$dstmask_);
			}
			if($dstport_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".ip_dst_port",$dstport_);
				$uci->set("network.aclrule_".$rule_id_.".ip_dst_port_mask","0xffff");
			}
			if($iprio_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".queue_of_remark",$iprio_);
			}
			if($premark_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".ctag_priority_of_remark",$premark_);
			}
			if($dscp_remark_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".dscp_of_remark",$dscp_remark_);
			}
			if($ip_dscp_ != ""){
				$uci->set("network.aclrule_".$rule_id_.".ip_dscp",$ip_dscp_);
				$uci->set("network.aclrule_".$rule_id_.".ip_dscp_mask","0xff");
			}
			
			$uci->run();
			$uci->close();
			echo("1");
			break;
		case "rule_del":
			$del_list = dv_post("dellist");
			$dellist = explode(",",$del_list);
			$uci = new uci();
			$uci->mode("del");
			for($i=0; $i < count($dellist); $i++){
				$uci->del($dellist[$i]);
			}
			$uci->run();
			$uci->close();
			echo "1";
			break;
		case "qos_apply":
			$uci = new uci();
			$uci->commit();
			echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));
			break;
	}

//	$uci->mode("del");
	
//	$uci->commit();
//	echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));


?>