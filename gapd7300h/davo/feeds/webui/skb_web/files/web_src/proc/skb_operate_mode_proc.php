<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");

$page_ = dv_post("page");
$prev_op_mode_ = dv_post("prev_op_mode");
$operation_mode_ = dv_post("operation_mode");
$radio_ = dv_post("radio");
if($radio_ == "0"){
	$radio = "1";
}else{
	$radio = "0";
}

/*
	$operation_mode_
	0 = NAT
	1 = Bridge
*/
//echo $submit-url_;

//uci show wireless | grep wifi-iface | grep network | sed "s/='lan'//"
/*
wireless.@wifi-iface[0].network
wireless.@wifi-iface[1].network
wireless.@wifi-iface[2].network
wireless.@wifi-iface[3].network
wireless.@wifi-iface[4].network
wireless.@wifi-iface[5].network
*/
function setting_opmode($opmode_){
	$uci = new uci();
	$uci->mode("get");
	$uci->get("network.switch_port_1");
	$uci->run();
	$vinfo = json_decode($uci->result(),true);
	
	
	$uci->mode("get");
	$uci->get("network.wan");
	$uci->get("network.lan");
	$uci->run();
	$network = $uci->result();
	$network = json_decode($network);
	$wanifname = std_get_val($network,"network.wan.ifname");
	$lanifname = std_get_val($network,"network.lan.ifname");
	$lanipaddr = std_get_val($network,"network.lan.ipaddr");
	$lannetmask = std_get_val($network,"network.lan.netmask");
	

	$wanifname_ori = std_get_val($network,"network.wan._orig_ifname");
	$cpu2lan = std_get_val($network,"network.lan._orig_cpu2lan");

	$lanifname_ori = std_get_val($network,"network.lan._orig_ifname");
	$lanipaddr_ori = std_get_val($network,"network.lan._orig_ipaddr");
	$lannetmask_ori = std_get_val($network,"network.lan._orig_netmask");

	if($wanifname_ori != ""){
		$wanifname = $wanifname_ori;
	}

	if($lanifname_ori != ""){
		$lanifname = $lanifname_ori;
	}

	if($lanipaddr_ori != ""){
		$lanipaddr = $lanipaddr_ori;
	}
	if($lannetmask_ori != ""){
		$lannetmask = $lannetmask_ori;
	}
	$uci->mode("set");
	Switch($opmode_){
		case "0":
			//Bridge
			for($i=0; $i < 5; $i++){
				$uci->set("wireless.vap0".$i.".network","wan");
				if($i < 4){
					$uci->set("wireless.vap1".$i.".network","wan");
				}
			}
			$uci->set("dvui.network.opmode","bridge");
			$uci->set("dvui.network.repeater","0");
			$uci->set("wireless.vap07.disabled","1");
			$uci->set("wireless.vap17.disabled","1");
			$uci->set("firewall.zone_lan.network",array(""));
			$uci->set("firewall.zone_wan.network",array("wan","wan6","lan"));
			
			$uci->set("network.lan.proto","none");
			$uci->set("network.lan._orig_ifname",$lanifname);
			$uci->set("network.lan._orig_ipaddr",$lanipaddr);
			$uci->set("network.lan._orig_netmask",$lannetmask);

			$uci->set("network.wan.ifname",$lanifname);
			
			if(std_get_val($network,"network.wan.type") == ""){
				$uci->set("network.wan._orig_type","none");
			}elseif(std_get_val($network,"network.wan.type") == "bridge"){
				$uci->set("network.wan._orig_type","bridge");
			}
			$uci->set("network.wan.type","bridge");
			$uci->set("network.wan._orig_ifname",$wanifname);
			
			$uci->set("network.cpu2wan.proto","static");
			$uci->set("network.cpu2wan.ifname",$wanifname);

			$uci->set("network.cpu2lan.proto","static");
			$uci->set("network.cpu2lan.ifname",$cpu2lan);

			$uci->set("network.sys_vlan_1.device","switch0");
			$uci->set("network.sys_vlan_1.vlan","2");
			$uci->set("network.sys_vlan_1.ports","0t 1");

			$uci->set("network.sys_vlan_2.device","switch0");
			$uci->set("network.sys_vlan_2.vlan","3");
			$uci->set("network.sys_vlan_2.ports","0t 2 3 4 5");

			$uci->set("network.sys_vlan_3.device","switch0");
			$uci->set("network.sys_vlan_3.vlan","1");
			$uci->set("network.sys_vlan_3.ports","0t 1 2 3 4 5");
			

			$uci->set("system.reboot","reboot");
			$uci->set("system.reboot.status","1");
			
			$uci->del("network.lan.ifname");
			$uci->del("network.lan.ipaddr");
			$uci->del("network.lan.netmask");

			$uci->del("network.lan.ip6assign");
			$uci->del("network.lan.force_link");
			$uci->del("network.lan.type");

			if(count($vinfo) > 0){
				if($vinfo["network.switch_port_1.pvid"] == "1" || $vinfo["network.switch_port_1.pvid"] == "2"){
					$uci->set("network.switch_port_1.pvid","1");
				}
			}
			$uci->run();
			$uci->mode("del");
			$uci->run();
			break;
		case "1":
			//NAT
			for($i=0; $i < 5; $i++){
				$uci->set("wireless.vap0".$i.".network","lan");
				if($i < 4){
					$uci->set("wireless.vap1".$i.".network","lan");
				}
			}
			$uci->set("dvui.network.opmode","nat");
			$uci->set("dvui.network.repeater","0");
			$uci->set("wireless.vap07.disabled","1");
			$uci->set("wireless.vap17.disabled","1");
			$uci->set("firewall.zone_lan.network",array("lan"));
			$uci->set("firewall.zone_wan.network",array("wan","wan6"));

			
			$uci->set("network.lan.proto","static");
			$uci->set("network.lan.ifname",$lanifname);
			$uci->set("network.lan.ipaddr",$lanipaddr);

			$uci->set("network.wan.ifname",$wanifname);
			
			if(std_get_val($network,"network.wan._orig_type") == "bridge"){
				$uci->set("network.wan.type","bridge");
			}
			
			$uci->set("network.lan.netmask",$lannetmask);
			$uci->set("network.lan.force_link","1");
			$uci->set("network.lan.ip6assign","60");
			$uci->set("network.lan.type","bridge");

			$uci->set("network.sys_vlan_1.device","switch0");
			$uci->set("network.sys_vlan_1.vlan","1");
			$uci->set("network.sys_vlan_1.ports","0t 2 3 4 5");

			$uci->set("network.sys_vlan_2.device","switch0");
			$uci->set("network.sys_vlan_2.vlan","2");
			$uci->set("network.sys_vlan_2.ports","0t 1");

			$uci->set("system.reboot","reboot");
			$uci->set("system.reboot.status","1");

			if(std_get_val($network,"network.wan._orig_type") == "none"){
				$uci->del("network.wan.type");
			}
			$uci->del("network.wan._orig_type");
			$uci->del("network.wan._orig_ifname");
			$uci->del("network.lan._orig_ifname");
			$uci->del("network.lan._orig_ipaddr");
			$uci->del("network.lan._orig_netmask");

			$uci->del("network.cpu2wan.proto");
			$uci->del("network.cpu2wan.ifname");

			$uci->del("network.cpu2lan.proto");
			$uci->del("network.cpu2lan.ifname");

			$uci->del("network.sys_vlan_3.device");
			$uci->del("network.sys_vlan_3.vlan");
			$uci->del("network.sys_vlan_3.ports");

			if(count($vinfo) > 0){
				if($vinfo["network.switch_port_1.pvid"] == "1" || $vinfo["network.switch_port_1.pvid"] == "2"){
					$uci->set("network.switch_port_1.pvid","2");
				}
			}

			$uci->run();
			$uci->mode("del");
			$uci->run();
			break;
		default:
			exit;
			break;
	}
	$uci->commit();
	$uci->close();
}


if($prev_op_mode_ == $operation_mode_ && $operation_mode_ != "2"){
	echo(rtn_reboot_page(dv_post("submit-url"),"system_restart"));
}else{
	Switch($operation_mode_){
		case "0":
			setting_opmode("0");
			break;
		case "1":
			setting_opmode("1");
			break;
		case "2":
			if($prev_op_mode_ != $operation_mode_){
				if($prev_op_mode_ == "1"){
					setting_opmode("0");
				}
			}
			$uci = new uci();
			$uci->mode("del");
			$uci->del("wireless.".$vap.".key");
			$uci->del("wireless.".$vap.".key_type");
			$uci->del("wireless.".$vap.".wep_key_len");
			$uci->del("wireless.".$vap.".wep_key_type");
			$uci->del("wireless.".$vap.".key1");
			$uci->del("wireless.".$vap.".key2");
			$uci->del("wireless.".$vap.".key3");
			$uci->del("wireless.".$vap.".key4");
			$uci->run();
			$uci->mode("set");
			$vap = "";
			if($radio_ == "0"){
				$vap = "vap17";
				$uci->set("wireless.vap07.disabled","1");
			}else{
				$vap = "vap07";
				$uci->set("wireless.vap17.disabled","1");
			}
			$wifi_mode_ = dv_post("wifi_mode");
			$ssid_ = dv_post("ssid");
			$enc_ = dv_post("enc");
			$psk_type_ = dv_post("psk_type");
			$psk_key_ = dv_post("psk_key");
			
			$uci->set("dvui.network.repeater","1");
			$uci->set("dvui.network.repeater_radio",$radio_);
			$uci->set("wireless.".$vap.".ssid",$ssid_);
			if($wifi_mode_ == "psk"){
				$uci->set("wireless.".$vap.".encryption",$enc_);
				$uci->set("wireless.".$vap.".key_type",$psk_type_);
				if($psk_key_ != "" && $psk_key_ != "********"){
					$uci->set("wireless.".$vap.".key",$psk_key_);
					$uci->set("wireless.".$vap."._orig_key",$psk_key_);
				}
			}elseif($wifi_mode_ == "wep"){
				$uci->mode("set");
				$wep_key_len_ = dv_post("wep_key_len");
				$wep_key_type_ = dv_post("wep_key_type");
				$select_key_ = dv_post("select_key");
				$wep_key_ = dv_post("wep_key");
				$uci->set("wireless.".$vap.".encryption",$enc_);
				$uci->set("wireless.".$vap.".wep_key_len",$wep_key_len_);
				$uci->set("wireless.".$vap.".wep_key_type",$wep_key_type_);
				$uci->set("wireless.".$vap.".key",$select_key_);
				$uci->set("wireless.".$vap.".wep_key",$select_key_);
				$prefix = "";
				if($wep_key_type_ == "ascii"){
					$prefix = "s:";
				}
				$uci->set("wireless.".$vap.".key1",$prefix.$wep_key_);
				$uci->set("wireless.".$vap.".key2",$prefix.$wep_key_);
				$uci->set("wireless.".$vap.".key3",$prefix.$wep_key_);
				$uci->set("wireless.".$vap.".key4",$prefix.$wep_key_);
			}elseif($wifi_mode_ == "none"){
				$uci->set("wireless.".$vap.".encryption","none");
			}
			$uci->set("wireless.".$vap.".disabled","0");
			$uci->run();
			$uci->commit();
			$uci->close();
			break;
	}
	
	echo(rtn_reboot_page(dv_post("submit-url"),"system_restart"));
}
?>

