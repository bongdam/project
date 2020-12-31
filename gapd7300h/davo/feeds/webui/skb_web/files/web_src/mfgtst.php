<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
	function switch_port_status($filter_ = ""){
		$syscall = new dvcmd();
		$syscall->add("port_status", $filter_,"!");
		$syscall->run();
		$rtn = $syscall->result();
		$syscall->close();
		$syscall = null;
	//	print_r($rtn);
		$port_tmp = explode("\n",$rtn[0]);
	//	print_r($port_tmp);
		$json = Array();
	//	print_r($port_tmp);
		for($i=0; $i < count($port_tmp); $i++){
			if($port_tmp[$i] != ""){
				$port_line = explode(" ",$port_tmp[$i]);
				for($j=0 ; $j < count($port_line); $j++){
					$tmp = explode(":",$port_line[$j]);
					if($tmp[1] !==null){
						if($j == 0){
							$json_tmp = Array($tmp[0] => $tmp[1]);
						}else{
							$json_tmp = array_merge($json_tmp,Array($tmp[0] => $tmp[1]));
						}
					}
				}
				$json[] = $json_tmp;
			}
		}
		
		return $json;
	}
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
				$uci->set("wireless.vap05.disabled","1");
				$uci->set("wireless.vap14.disabled","1");
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
				$uci->set("wireless.vap05.disabled","1");
				$uci->set("wireless.vap14.disabled","1");
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
	$cfg = new dvcfg();
	$cfg->read("system");
	$sys = $cfg->result();
	$fac_mode = get_json_val($sys,"system.system.factory_mode");
	$cfg->close();
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<style type="text/css">
html,body{
	font-family:fixedsys;
	padding:0;margin:0;
	padding-left:5px;
}
</style>
</head>
<body>
<?php
	$action = "";
	
	$cmd = new dvcmd();
	$uci = new uci();
	if($fac_mode == "1"){
		if(dv_get("led") !== false){
			$action = "led";
		}
		if(dv_get("tftpServer") !== false){
			$action = "tftpServer";
		}
		if(dv_get("reboot") !== false){
			$action = "reboot";
		}
		if(dv_get("factoryDefault") !== false){
			$action = "factoryDefault";
		}
		if(dv_get("info_system_htm") !== false){
			$action = "info_system_htm";
		}
		if(dv_get("info_cal_show_htm") !== false){
			$action = "info_cal_show_htm";
		}
		if(dv_get("info_rssi_show_htm") !== false){
			$action = "info_rssi_show_htm";
		}
		if(dv_get("diag_Button") !== false){
			$action = "diag_Button";
		}
		if(dv_get("diag_result") !== false){
			$action = "diag_result";
		}
		if(dv_get("sys_mode") !== false){
			$action = "sys_mode";
		}
		if(dv_get("sys_usb_test") !== false){
			$action = "sys_usb_test";
		}
		if(dv_get("sys_usb_result") !== false){
			$action = "sys_usb_result";
		}
		if(dv_get("handover_disable") !== false){
			$action = "handover_disable";
		}
		if(dv_get("check_wan_link_speed") !== false){
			$action = "check_wan_link_speed";
		}
		if(dv_get("cal_factory_reset") !== false){
			$action = "cal_factory_reset";
		}
	}else{
		if(dv_get("setting_factory_mode") !== false){
			$action = "setting_factory_mode";
		}
	}
//	echo($action);
	Switch($action){
		CASE "led":
			if(dv_get("led") == "1"){
				$cmd->add("dvmgmt","/TEST/fac/led on");
			}elseif(dv_get("led") == "2"){
				$cmd->add("dvmgmt","/TEST/fac/led default");
			}else{
				$cmd->add("dvmgmt","/TEST/fac/led off");
			}
			$cmd->run();
			break;
		CASE "tftpServer":
			$cmd->add("dvmgmt","/debug/shell debugmodeon");
			$cmd->run();
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
			$uci->mode("set");
			if(dv_get("tftpServer") == "1"){
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
			$uci->close();
			$cmd->add("firewall_restart");
			$cmd->run();
			break;
		CASE "reboot":
			if(dv_get("reboot") == "1"){
				$cmd->add("reboot");
				$cmd->run();
			}
			break;
		CASE "factoryDefault":
			if(dv_get("factoryDefault") == "1"){
				$cmd->add("restore","factory","!");
				$cmd->run();
			}
			break;
		CASE "info_system_htm":
			$system_version = "";
			$system_reverison = "";
			$model_name = "";
			$fp = fopen("/proc/fwinfo/version","r");
			$system_version = rtrim(fread($fp,100));
			fclose($fp);
			$fp = fopen("/proc/fwinfo/revision","r");
			$system_vision = rtrim(fread($fp,100));
			fclose($fp);
			$fp = fopen("/proc/fwinfo/model","r");
			$model_name = rtrim(fread($fp,100));
			fclose($fp);
			echo "<br>Firmware Version: ".$system_version." ( ".$system_vision.")<br>";
			$cmd->add("fw_printenv"," version | sed s/'version='//","!");
			$cmd->run();
			$boot_version = rtrim($cmd->result()[0]);
			echo "BOOT Version: ".$boot_version."<br>";
			echo "H/W Version: Unknown<br>";
			echo "ModelName: ".$model_name."<br>";
			$cmd->add("fw_printenv"," ethaddr | sed s/'ethaddr='//","!");
			$cmd->run();
			$basic_mac = str_replace(":","-",strtoupper($cmd->result()[0]));
			echo("Base MAC Address: ".$basic_mac."<br>");

			echo("<br>");
			$iface = "";
			if($fp = fopen("/tmp/state/network", 'r')){ 
				$iface = fread($fp, filesize("/tmp/state/network"));
				fclose($fp); 
			}
			$wface = "";
			if($fp = fopen("/tmp/state/wireless", 'r')){ 
				$wface = fread($fp, filesize("/tmp/state/wireless"));
				fclose($fp);
			}
			$show = new dvshow();
			$show->read($iface);
			$show->read($wface);
			$riface = $show->result("object");
			$wan_ifname = "";
			$wan_up = "";
			$wan_mac = "";
			$lan_ifname = "";
			$lan_up = "";
			$lan_mac = "";
			if(get_json_val($riface,"network.wan.ifname") == ""){
				$wan_ifname = get_json_val($riface,"network.wan.device");
			}else{
				$wan_ifname = get_json_val($riface,"network.wan.ifname");
			}
			$wan_up = get_json_val($riface,"network.wan.up");
			if(get_json_val($riface,"network.lan.ifname") == ""){
				$lan_ifname = get_json_val($riface,"network.lan.device");
			}else{
				$lan_ifname = get_json_val($riface,"network.lan.ifname");
			}
			$lan_up = get_json_val($riface,"network.lan.up");
			if($fp = fopen("/sys/devices/virtual/net/".$wan_ifname."/address", 'r')){ 
				$wan_mac = str_replace(":","-",strtoupper(rtrim(fread($fp, filesize("/sys/devices/virtual/net/".$wan_ifname."/address")))));
				fclose($fp); 
			}
			if($fp = fopen("/sys/devices/virtual/net/".$lan_ifname."/address", 'r')){ 
				$lan_mac = str_replace(":","-",strtoupper(rtrim(fread($fp, filesize("/sys/devices/virtual/net/".$lan_ifname."/address")))));
				fclose($fp); 
			}
			echo("LAN MAC Address: ".$lan_mac."<br>");
			echo("WAN MAC Address: ".$wan_mac."<br>");
			$cmd->add("fw_printenv"," serial_num | sed s/'serial_num='//","!");
			$cmd->run();
			$serial_no = rtrim($cmd->result()[0]);
			echo("Serial Number:".$serial_no." (길이:<span style=\"color:red;\">".strlen($serial_no)."</span>)<br>");

			function mac_to_plus($mac_, $opts_){
				$dec = base_convert(str_replace(":","",$mac_),16,10);
				$dec = $dec + $opts_;
				$hex = base_convert($dec,10,16);
				$result = substr($hex,-12);
				
				$result = rtrim(strtoupper(chunk_split($result, 2, '-')),'-');
				return $result;
			}
			$basemac = str_replace("-","",str_replace(substr($wan_mac,0,9),"",$wan_mac));
			$cfg = new dvcfg();
			$cfg->read("wireless");
			$winfo = $cfg->result("object");
			echo("<br><5G><br>");
				if(get_json_val($riface,"wireless.vap00.up") == "1"){
					echo "WLAN0(<span style=\"color:red;\">".get_json_val($winfo,"wireless.vap00.ssid")."</span>):"."0A-23-AA-".mac_to_plus($basemac,0)."<br>";
				}else{
					echo "WLAN0(<span style=\"color:red;\">".get_json_val($winfo,"wireless.vap00.ssid")."</span>):"."0A-23-AA-".mac_to_plus($basemac,0)."| Interface down<br>";
				}
				if(get_json_val($riface,"wireless.vap01.up") == "1"){
					echo "WLAN0-VA0: "."0A-23-AA-".mac_to_plus($basemac,1)." | "."0A-23-AA-".mac_to_plus($basemac,1)."<br>";
				}else{
					echo "WLAN0-VA0: "."0A-23-AA-".mac_to_plus($basemac,1)." | Interface down<br>";
				}
				if(get_json_val($riface,"wireless.vap02.up") == "1"){
					echo "WLAN0-VA1: "."0A-23-AA-".mac_to_plus($basemac,2)." | "."0A-23-AA-".mac_to_plus($basemac,2)."<br>";
				}else{
					echo "WLAN0-VA1: "."0A-23-AA-".mac_to_plus($basemac,2)." | Interface down<br>";
				}
				if(get_json_val($riface,"wireless.vap03.up") == "1"){
					echo "WLAN0-VA2: "."0A-23-AA-".mac_to_plus($basemac,3)." | "."0A-23-AA-".mac_to_plus($basemac,3)."<br>";
				}else{
					echo "WLAN0-VA2: "."0A-23-AA-".mac_to_plus($basemac,3)." | Interface down<br>";
				}
				if(get_json_val($riface,"wireless.vap04.up") == "1"){
					echo "WLAN0-VA3: "."0A-23-AA-".mac_to_plus($basemac,4)." | "."0A-23-AA-".mac_to_plus($basemac,4)."<br>";
				}else{
					echo "WLAN0-VA3: "."0A-23-AA-".mac_to_plus($basemac,4)." | Interface down<br>";
				}
				echo("Channel: ".get_json_val($winfo,"wireless.wifi0.channel")."<br>");
				echo("Status: ");
				echo(get_json_val($winfo,"wireless.wifi0.disabled") == "1" ? "Disabled":"Enabled"."<br><br>");
			echo("<2.4G><br>");
				if(get_json_val($riface,"wireless.vap10.up") == "1"){
					echo "WLAN0(<span style=\"color:red;\">".get_json_val($winfo,"wireless.vap10.ssid")."</span>):"."06-23-AA-".mac_to_plus($basemac,0)."<br>";
				}else{
					echo "WLAN0(<span style=\"color:red;\">".get_json_val($winfo,"wireless.vap10.ssid")."</span>):"."06-23-AA-".mac_to_plus($basemac,0)."| Interface down<br>";
				}
				if(get_json_val($riface,"wireless.vap11.up") == "1"){
					echo "WLAN0-VA0: "."06-23-AA-".mac_to_plus($basemac,1)." | "."06-23-AA-".mac_to_plus($basemac,1)."<br>";
				}else{
					echo "WLAN0-VA0: "."06-23-AA-".mac_to_plus($basemac,1)." | Interface down<br>";
				}
				if(get_json_val($riface,"wireless.vap12.up") == "1"){
					echo "WLAN0-VA1: "."06-23-AA-".mac_to_plus($basemac,2)." | "."06-23-AA-".mac_to_plus($basemac,2)."<br>";
				}else{
					echo "WLAN0-VA1: "."06-23-AA-".mac_to_plus($basemac,2)." | Interface down<br>";
				}
				if(get_json_val($riface,"wireless.vap13.up") == "1"){
					echo "WLAN0-VA2: "."06-23-AA-".mac_to_plus($basemac,3)." | "."06-23-AA-".mac_to_plus($basemac,3)."<br>";
				}else{
					echo "WLAN0-VA2: "."06-23-AA-".mac_to_plus($basemac,3)." | Interface down<br>";
				}
				if(get_json_val($riface,"wireless.vap14.up") == "1"){
					echo "WLAN0-VA3: "."06-23-AA-".mac_to_plus($basemac,4)." | "."06-23-AA-".mac_to_plus($basemac,4)."<br>";
				}else{
					echo "WLAN0-VA3: "."06-23-AA-".mac_to_plus($basemac,4)." | Interface down<br>";
				}
				echo("Channel: ".get_json_val($winfo,"wireless.wifi1.channel")."<br>");
				echo("Status: ");
				echo(get_json_val($winfo,"wireless.wifi1.disabled") == "1" ? "Disabled":"Enabled"."<br>");
			//포트 상태
			$port = switch_port_status();
			$port_status = "<br>WAN : ";
			if($port[1]["link"] == "1"){
				$port_status .= "<span style=\"color:red;\">".$port[1]["speed"]."M</span>";
			}else{
				$port_status .= "<span style=\"color:red;\">Down</span>";
			}
			$port_status .= " LAN1 : ";
			if($port[2]["link"] == "1"){
				$port_status .= "<span style=\"color:red;\">".$port[2]["speed"]."M</span>";
			}else{
				$port_status .= "<span style=\"color:red;\">Down</span>";
			}
			$port_status .= " LAN2 : ";
			if($port[3]["link"] == "1"){
				$port_status .= "<span style=\"color:red;\">".$port[3]["speed"]."M</span>";
			}else{
				$port_status .= "<span style=\"color:red;\">Down</span>";
			}
			$port_status .= " LAN3 : ";
			if($port[4]["link"] == "1"){
				$port_status .= "<span style=\"color:red;\">".$port[4]["speed"]."M</span>";
			}else{
				$port_status .= "<span style=\"color:red;\">Down</span>";
			}
			$port_status .= " LAN4 : ";
			if($port[5]["link"] == "1"){
				$port_status .= "<span style=\"color:red;\">".$port[5]["speed"]."M</span>";
			}else{
				$port_status .= "<span style=\"color:red;\">Down</span>";
			}
			echo($port_status);
			break;
		CASE "info_cal_show_htm":
			if(file_exists("/tmp/caldata_found") == true){
				echo("Success");
			}else{
				echo("Fail");
			}
			break;
		CASE "info_rssi_show_htm":
			$cmd->add("sta_list");
			$cmd->run();
			$sta_list = "";
			$sta = array();
			if(file_exists("/tmp/station.txt") == true){
				$handle = fopen("/tmp/station.txt", "r");
				$contents = fread($handle, filesize("/tmp/station.txt"));
				fclose($handle);
				$sta_list = explode("\n",rtrim($contents));
			}
			if(count($sta_list) == 0){
				echo("After connecting wifi client, Retry command!");
			}else{
				$radio24 = Array("ath1","ath11","ath12","ath13","ath14","ath15","ath16");
				$radio5 = Array("ath0","ath01","ath02","ath03","ath04","ath05","ath06");
				if(dv_get("info_rssi_show_htm") == "2.4"){
					for($i=0 ; $i < count($sta_list); $i++){
						if(preg_match("/^[\s+]{0,}\[\s+(\S+)\s+([\w+\:]{6,})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+[\s+\S+]{0,}\]$/",$sta_list[$i],$d) == true) {
				//			print_r($d);
							$rssi = $d[7];
							if(preg_match("/[\s+]{0,}\d+\((\-\d+)\)/",$rssi,$s) == true){
								$rssi = $s[1];
							}
							$tmp = Array(
								"ifname"	=> $d[1],
								"mac"		=> $d[2],
								"mode"		=> $d[3],
								"tx_kb"		=> (int)$d[4],
								"rx_kb"		=> (int)$d[5],
								"link_rate"	=> $d[6],
								"rssi"		=> $rssi,
								"time"		=> $d[8],
								"scmode"	=> $d[9],
								"use_time"	=> $d[10]
							);
							
							if( array_search($d[1],$radio24) !== false){
								array_push($sta,$tmp);
								if(str_replace("ath1","",$d[1]) == ""){
									$ifname = "wlan1";
								}else{
									$ifname = "wlan1-va".str_replace("ath1","",$d[1]);
								}
								echo($ifname.": client hwaddr: ".$d[2]." rssi: ".$rssi);
							}
						}
					}
//					wlan0-va3: client hwaddr: f4428f501391 rssi: 67 (68 63) 
				}elseif(dv_get("info_rssi_show_htm") == "5"){
					for($i=0 ; $i < count($sta_list); $i++){
						if(preg_match("/^[\s+]{0,}\[\s+(\S+)\s+([\w+\:]{6,})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+[\s+\S+]{0,}\]$/",$sta_list[$i],$d) == true) {
				//			print_r($d);
							$rssi = $d[7];
							if(preg_match("/[\s+]{0,}\d+\((\-\d+)\)/",$rssi,$s) == true){
								$rssi = $s[1];
							}
							$tmp = Array(
								"ifname"	=> $d[1],
								"mac"		=> $d[2],
								"mode"		=> $d[3],
								"tx_kb"		=> (int)$d[4],
								"rx_kb"		=> (int)$d[5],
								"link_rate"	=> $d[6],
								"rssi"		=> $rssi,
								"time"		=> $d[8],
								"scmode"	=> $d[9],
								"use_time"	=> $d[10]
							);
							
							if( array_search($d[1],$radio5) !== false){
								array_push($sta,$tmp);
								if(str_replace("ath0","",$d[1]) == ""){
									$ifname = "wlan0";
								}else{
									$ifname = "wlan0-va".str_replace("ath0","",$d[1]);
								}
								echo($ifname.": client hwaddr: ".$d[2]." rssi: ".$rssi);
							}
						}
					}
				}
			}
			break;
		CASE "diag_Button":
			if(dv_get("diag_Button") == "reset"){
				$fh = fopen("/tmp/factory_reset", "a+") or die("Could not open log file.");
				fwrite($fh,"");
				fclose($fh);
			}
			break;
		CASE "diag_result":
			$contents = "";
			if(file_exists("/tmp/factory_reset") == true){
				$handle = fopen("/tmp/factory_reset", "r");
				$contents = rtrim(fread($handle, filesize("/tmp/factory_reset")));
				fclose($handle);
			}
			if($contents == "1"){
				echo("\"resetDiagPass\"");
			}else{
				echo("\"resetDiagFail\"");
			}
			break;
		CASE "sys_mode":
			$cfg = new dvcfg();
			$cfg->read("dvui");
			$cf = $cfg->result("object");
			$opmode = get_json_val($cf,"dvui.network.opmode");
			if(dv_get("sys_mode") == "0"){
				if($opmode != "nat"){
					setting_opmode("1");
				}
				$cmd->add("reboot");
				$cmd->run();
			}elseif(dv_get("sys_mode") == "1"){
				if($opmode != "bridge"){
					setting_opmode("0");
				}
				$cmd->add("reboot");
				$cmd->run();
			}
			break;
		CASE "sys_usb_test":
			$cmd->add("dvmgmt","/TEST/MOUNT enable");
			$cmd->run();
			echo("Insert USB STORAGE");
			break;
		CASE "sys_usb_result":
			$cmd->add("mount"," | grep usbdisk","!");
			$cmd->run();
			$a = $cmd->result()[0];
			if(strlen($a) > 0 ){
				echo("SUCCESS");
			}else{
				echo("FAIL : DETECT USB STORAGE");
			}
			break;
		CASE "handover_disable":
			$uci->mode("set");
			if(dv_get("handover_disable") == "1"){
				$uci->set("wireless.vap04.disabled","1");
			}else{
				$uci->set("wireless.vap04.disabled","0");
			}
			$uci->run();
			$uci->commit();
			$cmd->add("wifi_restart");
			$cmd->run();
			break;
		CASE "check_wan_link_speed":
			$a = switch_port_status(" | grep wan");
			$wan = $a[0];
			$link = get_array_val($wan,"link") == "1" ? "UP" : "DOWN";
			$speed =  get_array_val($wan,"speed");
			$deplex = get_array_val($wan,"duplex") == "1" ? "FULL" : "HALF";
			if($link == "UP"){
				echo "Link state is ".$link.". Duplex is ".$deplex." with ".$speed."Mbps";
			}else{
				echo "Link state is ".$link;
			}
			break;
		CASE "cal_factory_reset":
			//캘 데이터는 삭제후 무조건 재부팅이 필요함.
			if(dv_get("cal_factory_reset") == "1"){
				$cmd->add("clearcaldata");
				$cmd->run();
				$result = json_decode($cmd->result()[0],true);
				IF($result == "1"){
					echo("Success");
					$cmd->add("reboot");
					$cmd->run();
				}else{
					echo("Fail<br>");
					echo("Please retry.");
				}
				
			}
			break;
		CASE "setting_factory_mode":
			if(dv_get("setting_factory_mode") == "1"){
				if(file_exists("/etc/fac.config") == true){
//					echo "fac.config exists";
					$cmd->add("file_remove"," /etc/config -r","!");
					$cmd->add("file_copy"," /etc/fac.config /etc/config -r","!");
					$cmd->add("fw_setenv","fac_boot_mode 1","!");
					$cmd->run();
					$cmd->add("reboot");
					$cmd->run();
				}else{
					echo "fac.config not exists";
				}
			}
			break;
		Default:
			echo("Error");
			break;
	}
	
	$cmd->close();
?>
</body>
</html>
