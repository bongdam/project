<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
//	create_post_value();
	$act_ = dv_post("act");
	Switch($act_){
		case "set_dos":
			$uci = new uci();
			$uci->mode("set");
			$dosEnabled_ = dv_post("dos_enable");
			$sysfloodSYN_ = dv_post("tcpsynflood");
			$sysfloodSYNcount_ = dv_post("tcpsynflood_pkt");

			$TCPUDPPortScan_ = dv_post("tcpportscan");
//			$portscanSensi_ = dv_post("tcpportscan_type");

			$ICMPSmurfEnabled_ = dv_post("icmpsmurf");

			$ip_spoof_ = dv_post("ip_spoof");

			$PingOfDeathEnabled_ = dv_post("ping_of_death");

			$pingSecEnabled_ = dv_post("ping_of_sec");
			$pingSecCount_ = dv_post("ping_of_sec_pkt");

			$traceroute_ = dv_post("traceroute");

			$arpspoof_ = dv_post("arpspoof");

			$macflood_ = dv_post("macflood");
			$macflood_limit_ = dv_post("macflood_limit");

			$dns_input_rate_ = dv_post("dns_input_rate");
			$ntp_input_rate_ = dv_post("ntp_input_rate");
			$snmp_input_rate_ = dv_post("snmp_input_rate");

			$IPblockTime_ = dv_post("source_ip_block");
			if($dosEnabled_ == false){
				//disable
				$uci->set("firewall.dos_config.enabled","0");
			}else{
				$uci->set("firewall.dos_config.enabled","1");
			}
			if($sysfloodSYN_ == false){
				$uci->set("firewall.dos_config.tcpsyn_flood","0");
				$uci->set("firewall.dos_config.tcpsyn_flood_rate","0");
			}else{
				$uci->set("firewall.dos_config.tcpsyn_flood","1");
				$uci->set("firewall.dos_config.tcpsyn_flood_rate",$sysfloodSYNcount_);
			}
			if($TCPUDPPortScan_ == false){
				$uci->set("firewall.dos_config.portscan","0");
//				$uci->set("firewall.dos_config.portscan_sense","0");
			}else{
				$uci->set("firewall.dos_config.portscan","1");
//				$uci->set("firewall.dos_config.portscan_sense",$portscanSensi_);
			}
			if($ICMPSmurfEnabled_ == false){
				$uci->set("firewall.dos_config.icmp_smurf","0");
			}else{
				$uci->set("firewall.dos_config.icmp_smurf","1");
			}
			if($ip_spoof_ == false){
				$uci->set("firewall.dos_config.ip_spoof","0");
			}else{
				$uci->set("firewall.dos_config.ip_spoof","1");
			}
			if($PingOfDeathEnabled_ == false){
				$uci->set("firewall.dos_config.ping_of_death","0");
			}else{
				$uci->set("firewall.dos_config.ping_of_death","1");
			}
			if($pingSecEnabled_ == false){
				$uci->set("firewall.dos_config.ping_limit","0");
				$uci->set("firewall.dos_config.ping_rate","0");
			}else{
				$uci->set("firewall.dos_config.ping_limit","1");
				$uci->set("firewall.dos_config.ping_rate",$pingSecCount_);
			}
			if($traceroute_ == false){
				$uci->set("firewall.dos_config.block_tracert","0");
			}else{
				$uci->set("firewall.dos_config.block_tracert","1");
			}
			if($arpspoof_ == false){
				$uci->set("firewall.dos_config.arp_spoof","0");
			}else{
				$uci->set("firewall.dos_config.arp_spoof","1");
			}
			$uci->set("firewall.dos_config.macflood",$macflood_);
			if($macflood_limit_ != ""){
				$uci->set("firewall.dos_config.macflood_limit",$macflood_limit_);
			}
			$uci->set("firewall.dos_config.dns_relay_protect",$dns_input_rate_);
			$uci->set("firewall.dos_config.ntp_protect",$ntp_input_rate_);
			$uci->set("firewall.dos_config.snmp_protect",$snmp_input_rate_);

//			$uci->set("firewall.dos_config.block_time",$IPblockTime_);

			$uci->run();
			$uci->commit();
//			$cmd = new dvcmd();
//			$cmd->add("firewall_restart");
//			$cmd->run();
//			$cmd->result();
//			$cmd->close();
//			sleep(1);
			echo("1");
			break;
		
	}
?>