<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$act_ = dv_post("act");
	switch($act_){
		case "get_wan_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("network.wan");
			$uci->run();
			$uci_wan = $uci->result();
			$uci->set_head_json();
			echo($uci_wan);
			break;
		case "set_wan_info":
			$dns_mode_ = dv_post("dns_mode");
			$wan_proto_ = dv_post("wan_proto");
			$wan_ip_ = dv_post("wan_ip");
			$wan_netmask_ = dv_post("wan_netmask");
			$wan_gateway_ = dv_post("wan_gateway");
			$wan_mtu_ = dv_post("wan_mtu");
			$wan_dns2_ = dv_post("wan_dns2");
			$uci = new uci();
			$uci->mode("get");
			$uci->get("network.lan.ipaddr");
			$uci->get("network.lan._orig_ipaddr");
			$uci->run();
			$lan = json_decode($uci->result());
			$lanip = std_get_val($lan,"network.lan.ipaddr");
			$lanip_ori = std_get_val($lan,"network.lan._orig_ipaddr");
			if($lanip_ori != ""){
				$lanip = $lanip_ori;
			}
			if($wan_proto_ == "dhcp"){
				$uci->mode("del");
				$uci->del("network.wan.ipaddr");
				$uci->del("network.wan.netmask");
				$uci->del("network.wan.gateway");
				$uci->del("network.wan.hostname");
				$uci->del("network.wan.macaddr");
				if($wan_mtu_ == "1500"){
					$uci->del("network.wan.mtu");
				}
				if($dns_mode_ == "0"){
					$uci->del("network.wan.dns");
				}
				$uci->run();
				$uci->mode("set");
				$uci->set("network.wan.hostname","");
				$uci->set("network.wan.proto","dhcp");
				if($dns_mode_ == "1"){
					if(dv_post("wan_dns2") != ""){
						$uci->set("network.wan.dns",dv_post("wan_dns1")." ".dv_post("wan_dns2"));
					}else{
						$uci->set("network.wan.dns",dv_post("wan_dns1"));
					}
				}
			}else{
				//static
				$uci->mode("del");
				$uci->del("network.wan.hostname");
				$uci->del("network.wan.macaddr");
				if($wan_mtu_ == "1500"){
					$uci->del("network.wan.mtu");
				}
				if($dns_mode_ == "0"){
					$uci->del("network.wan.dns");
				}
				$uci->run();
				$uci->mode("set");
				$uci->set("network.wan.proto","static");
				$uci->set("network.wan.ipaddr",$wan_ip_);
				$uci->set("network.wan.netmask",$wan_netmask_);
				$uci->set("network.wan.gateway",$wan_gateway_);
				if(dv_post("wan_dns2") != ""){
					$uci->set("network.wan.dns",dv_post("wan_dns1")." ".dv_post("wan_dns2"));
				}else{
					$uci->set("network.wan.dns",dv_post("wan_dns1"));
				}
			}
			if(dv_post("macCloneEnable") == "1"){
				$uci->set("network.wan.macaddr",trim(dv_post("wan_macAddr")));
			}
			if(dv_post("igmp_enabled") == "1"){
//				$uci->set("network.wan.macaddr",trim(dv_post("wan_macAddr")));
			}else{
				
			}
			if(dv_post("igmp_enabled") == "1"){
				$uci->set("igmpproxy.igmpproxy.enabled","1");
			}else{
				$uci->set("igmpproxy.igmpproxy.enabled","0");
			}
			if(dv_post("ping_enabled") == "1"){
				$uci->set("firewall.allow_icmp","rule");
				$uci->set("firewall.allow_icmp.name","Allow-Ping");
				$uci->set("firewall.allow_icmp.src","wan");
				$uci->set("firewall.allow_icmp.proto","icmp");
				$uci->set("firewall.allow_icmp.icmp_type","echo-request");
				$uci->set("firewall.allow_icmp.family","ipv4");
				$uci->set("firewall.allow_icmp.target","ACCEPT");
			}else{
				$uci->set("firewall.allow_icmp","rule");
				$uci->set("firewall.allow_icmp.name","Allow-Ping");
				$uci->set("firewall.allow_icmp.src","wan");
				$uci->set("firewall.allow_icmp.proto","icmp");
				$uci->set("firewall.allow_icmp.icmp_type","echo-request");
				$uci->set("firewall.allow_icmp.family","ipv4");
				$uci->set("firewall.allow_icmp.target","DROP");
			}
			if(dv_post("ipsec_enabled") == "1"){
				$uci->set("firewall.allow_esp","rule");
				$uci->set("firewall.allow_esp.name","Allow-ESP");
				$uci->set("firewall.allow_esp.src","wan");
				$uci->set("firewall.allow_esp.dest","lan");
				$uci->set("firewall.allow_esp.proto","esp");
				$uci->set("firewall.allow_esp.target","ACCEPT");

				$uci->set("firewall.allow_ipsec","rule");
				$uci->set("firewall.allow_ipsec.name","Allow-IPsec");
				$uci->set("firewall.allow_ipsec.src","wan");
				$uci->set("firewall.allow_ipsec.dest","lan");
				$uci->set("firewall.allow_ipsec.dest_port","500");
				$uci->set("firewall.allow_ipsec.proto","udp");
				$uci->set("firewall.allow_ipsec.target","ACCEPT");
			}else{
				$uci->set("firewall.allow_esp","rule");
				$uci->set("firewall.allow_esp.name","Allow-ESP");
				$uci->set("firewall.allow_esp.src","wan");
				$uci->set("firewall.allow_esp.dest","lan");
				$uci->set("firewall.allow_esp.proto","esp");
				$uci->set("firewall.allow_esp.target","DROP");

				$uci->set("firewall.allow_ipsec","rule");
				$uci->set("firewall.allow_ipsec.name","Allow-IPsec");
				$uci->set("firewall.allow_ipsec.src","wan");
				$uci->set("firewall.allow_ipsec.dest","lan");
				$uci->set("firewall.allow_ipsec.dest_port","500");
				$uci->set("firewall.allow_ipsec.proto","udp");
				$uci->set("firewall.allow_ipsec.target","DROP");
			}
			if(dv_post("pptp_enabled") == "1"){
				$uci->set("firewall.allow_pptp","rule");
				$uci->set("firewall.allow_pptp.name","Allow-PPTP");
				$uci->set("firewall.allow_pptp.src","wan");
				$uci->set("firewall.allow_pptp.dest","lan");
				$uci->set("firewall.allow_pptp.dest_port","1723");
				$uci->set("firewall.allow_pptp.proto","tcp");
				$uci->set("firewall.allow_pptp.target","ACCEPT");
			}else{
				$uci->set("firewall.allow_pptp","rule");
				$uci->set("firewall.allow_pptp.name","Allow-PPTP");
				$uci->set("firewall.allow_pptp.src","wan");
				$uci->set("firewall.allow_pptp.dest","lan");
				$uci->set("firewall.allow_pptp.dest_port","1723");
				$uci->set("firewall.allow_pptp.proto","tcp");
				$uci->set("firewall.allow_pptp.target","DROP");
			}
			if(dv_post("l2tp_enabled") == "1"){
				$uci->set("firewall.allow_l2tp","rule");
				$uci->set("firewall.allow_l2tp.name","Allow-L2TP");
				$uci->set("firewall.allow_l2tp.src","wan");
				$uci->set("firewall.allow_l2tp.dest","lan");
				$uci->set("firewall.allow_l2tp.dest_port","1701");
				$uci->set("firewall.allow_l2tp.proto","udp");
				$uci->set("firewall.allow_l2tp.target","ACCEPT");
			}else{
				$uci->set("firewall.allow_l2tp","rule");
				$uci->set("firewall.allow_l2tp.name","Allow-L2TP");
				$uci->set("firewall.allow_l2tp.src","wan");
				$uci->set("firewall.allow_l2tp.dest","lan");
				$uci->set("firewall.allow_l2tp.dest_port","1701");
				$uci->set("firewall.allow_l2tp.proto","udp");
				$uci->set("firewall.allow_l2tp.target","DROP");
			}
			if(dv_post("netbios_enabled") == "1"){
				$uci->set("firewall.allow_netbios","rule");
				$uci->set("firewall.allow_netbios.name","Allow-netbios");
				$uci->set("firewall.allow_netbios.src","wan");
				$uci->set("firewall.allow_netbios.tproto","tcpudp");
				$uci->set("firewall.allow_netbios.dest_port","137-139");
				$uci->set("firewall.allow_netbios.target","ACCEPT");
			}else{
				$uci->set("firewall.allow_netbios","rule");
				$uci->set("firewall.allow_netbios.name","Allow-netbios");
				$uci->set("firewall.allow_netbios.src","wan");
				$uci->set("firewall.allow_netbios.tproto","tcpudp");
				$uci->set("firewall.allow_netbios.dest_port","137-139");
				$uci->set("firewall.allow_netbios.target","DROP");
			}
			if(dv_post("cifs_enabled") == "1"){
				$uci->set("firewall.allow_msds","rule");
				$uci->set("firewall.allow_msds.name","Allow-cifs");
				$uci->set("firewall.allow_msds.src","wan");
				$uci->set("firewall.allow_msds.tproto","tcpudp");
				$uci->set("firewall.allow_msds.dest_port","445");
				$uci->set("firewall.allow_msds.target","ACCEPT");
			}else{
				$uci->set("firewall.allow_msds","rule");
				$uci->set("firewall.allow_msds.name","Allow-cifs");
				$uci->set("firewall.allow_msds.src","wan");
				$uci->set("firewall.allow_msds.tproto","tcpudp");
				$uci->set("firewall.allow_msds.dest_port","445");
				$uci->set("firewall.allow_msds.target","DROP");
			}
			if(dv_post("lltd_enabled") == "1"){
				$uci->set("network.allow_lltd","switch_ext");
				$uci->set("network.allow_lltd.device","switch0");
				$uci->set("network.allow_lltd.name","AclRule");
				$uci->set("network.allow_lltd.rule_id","60");
				$uci->set("network.allow_lltd.priority","1");
				$uci->set("network.allow_lltd.rule_type","mac");
				$uci->set("network.allow_lltd.port_bitmap","0x02");
				$uci->set("network.allow_lltd.packet_drop","no");
				$uci->set("network.allow_lltd.ethernet_type","0x88da");
				$uci->set("network.allow_lltd.ethernet_type_mask","0xffff");
			}else{
				$uci->set("network.allow_lltd","switch_ext");
				$uci->set("network.allow_lltd.device","switch0");
				$uci->set("network.allow_lltd.name","AclRule");
				$uci->set("network.allow_lltd.rule_id","60");
				$uci->set("network.allow_lltd.priority","1");
				$uci->set("network.allow_lltd.rule_type","mac");
				$uci->set("network.allow_lltd.port_bitmap","0x02");
				$uci->set("network.allow_lltd.packet_drop","yes");
				$uci->set("network.allow_lltd.ethernet_type","0x88da");
				$uci->set("network.allow_lltd.ethernet_type_mask","0xffff");
			}
			if(dv_post("battle_enabled") == "1"){
				$uci->set("dvmgmt.starcraft.enable","1");
			}else{
				$uci->set("dvmgmt.starcraft.enable","0");
			}
			if(dv_post("telnet_enabled") == "1"){
				$uci->set("firewall.rd_telnet","redirect");
				$uci->set("firewall.rd_telnet.name","Telnet DNAT");
				$uci->set("firewall.rd_telnet.src","wan");
				$uci->set("firewall.rd_telnet.src_dport","6000");
				$uci->set("firewall.rd_telnet.dest","lan");
				$uci->set("firewall.rd_telnet.dest_ip",$lanip);
				$uci->set("firewall.rd_telnet.proto","tcp");
				$uci->set("firewall.rd_telnet.target","DNAT");

				$uci->set("firewall.allow_wan_telnet.target","allowed_wan_rule");

				$uci->set("firewall.allow_lan_telnet","rule");
				$uci->set("firewall.allow_lan_telnet.name","Allow-telnet");
				$uci->set("firewall.allow_lan_telnet.src","lan");
				$uci->set("firewall.allow_lan_telnet.proto","tcp");
				$uci->set("firewall.allow_lan_telnet.dest_port","6000");
				$uci->set("firewall.allow_lan_telnet.target","ACCEPT");
			}else{
				$uci->set("firewall.rd_telnet","redirect");
				$uci->set("firewall.rd_telnet.name","Telnet DNAT");
				$uci->set("firewall.rd_telnet.src","wan");
				$uci->set("firewall.rd_telnet.src_dport","6000");
				$uci->set("firewall.rd_telnet.dest","lan");
				$uci->set("firewall.rd_telnet.dest_ip",$lanip);
				$uci->set("firewall.rd_telnet.proto","tcp");
				$uci->set("firewall.rd_telnet.target","DNAT");

				$uci->set("firewall.allow_wan_telnet.target","DROP");

				$uci->set("firewall.allow_lan_telnet","rule");
				$uci->set("firewall.allow_lan_telnet.name","Allow-telnet");
				$uci->set("firewall.allow_lan_telnet.src","lan");
				$uci->set("firewall.allow_lan_telnet.proto","tcp");
				$uci->set("firewall.allow_lan_telnet.dest_port","6000");
				$uci->set("firewall.allow_lan_telnet.target","DROP");
			}
			$uci->run();
			$uci->commit();
			$cmd = new dvcmd();
			$cmd->add("firewall_restart");
			$cmd->run();
			$cmd->result();
			$cmd->close();
			echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));
			break;
		case "get_service_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("igmpproxy.igmpproxy");
			$uci->get("firewall.allow_icmp");
			$uci->get("firewall.allow_ipsec");
			$uci->get("firewall.allow_pptp");
			$uci->get("firewall.allow_l2tp");
			$uci->get("firewall.allow_netbios");
			$uci->get("firewall.allow_msds");
			$uci->get("network.allow_lltd");
			$uci->get("dvmgmt.starcraft");
			$uci->get("firewall.allow_lan_telnet");
			$uci->run();
			$get = $uci->result();
			$uci->set_head_json();
			$uci->close();
			echo($get);
			break;
			break;
		case "get_ping_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("firewall.allow_icmp");
			$uci->run();
			$get = $uci->result();
			$uci->set_head_json();
			$uci->close();
			echo($get);
			break;
		case "get_ipsec_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("firewall.allow_ipsec");
			$uci->run();
			$get = $uci->result();
			$uci->set_head_json();
			$uci->close();
			echo($get);
			break;
		case "get_pptp_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("firewall.allow_pptp");
			$uci->run();
			$get = $uci->result();
			$uci->set_head_json();
			$uci->close();
			echo($get);
			break;
		case "get_l2tp_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("firewall.allow_l2tp");
			$uci->run();
			$get = $uci->result();
			$uci->set_head_json();
			$uci->close();
			echo($get);
			break;
		case "get_netbios_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("firewall.allow_netbios");
			$uci->run();
			$get = $uci->result();
			$uci->set_head_json();
			$uci->close();
			echo($get);
			break;
		case "get_cifs_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("firewall.allow_msds");
			$uci->run();
			$get = $uci->result();
			$uci->set_head_json();
			$uci->close();
			echo($get);
			break;
		case "get_lltd_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("network.allow_lltd");
			$uci->run();
			$get = $uci->result();
			$uci->set_head_json();
			$uci->close();
			echo($get);
			break;
		case "get_telnet_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("firewall.allow_lan_telnet");
			$uci->run();
			$get = $uci->result();
			$uci->set_head_json();
			$uci->close();
			echo($get);
			break;
		default:
			echo("error");
			break;
	}
?>