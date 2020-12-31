<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$act_ = dv_post("act");
	switch($act_){
		case "get_lan_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("network.lan");
			$uci->get("dhcp.lan");
			$uci->get("dhcpr.ipv4");
			$uci->get("loop_check.cfg");
			$uci->run();
			$uci_wan = $uci->result();
			echo($uci_wan);
			break;
		case "set_lan_info":
			$lan_ip_ = dv_post("lan_ip");
			$lan_mask_ = dv_post("lan_mask");
			$dhcp_ = dv_post("dhcp");
			$dhcp_start_ = dv_post("dhcp_start");
			$dhcp_limit_ = dv_post("dhcp_limit");
			$dhcp_leasetime_ = dv_post("dhcp_leasetime");
			$loop_check_ = dv_post("loop_check");
			$option82 = "0";
			if(dv_post("option82") == "1") {
				$option82 = "1";
			}
			$uci = new uci();
			$uci->mode("get");
			$uci->get("network.lan");
			$uci->get("dvui.network");
			$uci->run();
			$lan = json_decode($uci->result(),true);
			$opmode = 0; // 0 : NAT 1: BRIDGE
			$lan_ip = "";
			if(get_array_val($lan,"dvui.network.opmode") == "bridge"){
				$lan_ip = get_array_val($lan,"network.lan._orig_ipaddr");
			}else{
				$opmode = 1;
				$lan_ip = get_array_val($lan,"network.lan.ipaddr");
			}

			if($lan_ip != $lan_ip_){
				$uci->set("system.reboot","reboot");
				$uci->set("system.reboot.status","1");
				$uci->set("firewall.rd_telnet.dest_ip",$lan_ip_);
			}
			$uci->set("loop_check.cfg.enabled",$loop_check_);
			if($dhcp_ == "1"){
				$uci->mode("del");
				$uci->del("dhcp.lan.ignore");
				$uci->run();
				$uci->mode("set");
				if($opmode == 1){
					$uci->set("network.lan.ipaddr",$lan_ip_);
					$uci->set("network.lan.netmask",$lan_mask_);
				}else{
					$uci->set("network.lan._orig_ipaddr",$lan_ip_);
					$uci->set("network.lan._orig_netmask",$lan_mask_);
				}
				$uci->set("dhcp.lan.start",$dhcp_start_);
				$uci->set("dhcp.lan.limit",$dhcp_limit_);
				$uci->set("dhcp.lan.leasetime",$dhcp_leasetime_);
				$uci->set("dhcpr.ipv4.enabled",$option82);
				$uci->run();
				$uci->commit();
			}else{
				$uci->mode("del");
				$uci->del("dhcp.lan.start");
				$uci->del("dhcp.lan.limit");
				$uci->del("dhcp.lan.leasetime");
				$uci->run();
				$uci->mode("set");
				$uci->set("dhcp.lan.ignore",1);
				if($opmode == 1){
					$uci->set("network.lan.ipaddr",$lan_ip_);
					$uci->set("network.lan.netmask",$lan_mask_);
				}else{
					$uci->set("network.lan._orig_ipaddr",$lan_ip_);
					$uci->set("network.lan._orig_netmask",$lan_mask_);
				}
				$uci->set("dhcpr.ipv4.enabled",$option82);
				$uci->run();
				$uci->commit();
			}
			echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));
			break;
		default:
			echo("error");
			break;
	}
?>