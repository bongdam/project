<?php
	$isAdmin = dv_session("user_lvl");
	if(DEF_MODEL == "QCA_REF" && DEF_ANT == "2x2"){
		$firmTime = 6.5;
	}else{
		$firmTime = 2.5;
	}
	define("DEF_MAX_LAN",4);
	define("DEF_MAX_PORT",5);
	$wan_port = "";
	$lan_port = "";
	function check_admin($isAdmin_){
		if($isAdmin_ == "1"){
			header("Location:/skb_logout.php");
			EXIT;
		}
	}
	function rtn_reboot_page($submit_url_,$action_){
		$tmp = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html\" charset=\"utf-8\"><link href=\"/style.css\" rel=\"stylesheet\" type=\"text/css\"></head><body><blockquote><b><font size=3 face=\"arial\" color=\"#3c7A95\"><br>재시작이 필요합니다.</font></b><table border=0 width=\"540\" cellspacing=4 cellpadding=0><tr><td><font size=2><br>변경된 설정이 저장되었습니다. 설정을 적용하려면 재시작해야 합니다.<br>지금 장비를 재시작하거나 설정을 계속 한 후 나중에 재시작하셔도 됩니다.</font></td></tr><tr><td><hr size=1 noshade align=top></td></tr><tr><td><form action=\"/skb_restart.php\" method=\"POST\" name=\"rebootForm\"><input type=\"hidden\" name=\"act\" value=\"".$action_."\"><input type=\"hidden\" value=\"".$submit_url_."\" name=\"submit-url\"><input id=\"restartNow\" type=\"submit\" value=\"지금 재시작\" onclick=\"return true\" />&nbsp;&nbsp;<input id=\"restartLater\" type=\"button\" value=\"나중에 재시작\" onclick='location.assign( \"".$submit_url_."\")'></form></td></tr></table></blockquote></body></html>";
		return $tmp;
	}
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
	function network_ipaddr_info($filter_){
		$syscall = new dvcmd();
		$syscall->add("ifconfig", $filter_,"!");
		$syscall->run();
		$rtn = $syscall->result()[0];
		$syscall->close();
		$syscall = null;
		$arrif = explode("\n",$rtn);
		print_r($arrif);
		$net = Array();
		$ifface = array();
		for($i = 0 ; $i < count($arrif) ; $i++ ){
			if($arrif[$i] == "" ){
				if(gettype($ifface) == "array"){
					if(count($ifface) > 0){
						array_push($net,$ifface);
						$ifface = array();
					}
				}
				continue;
			}
			if(preg_match("/^([\w\d-]{1,})\s+\w+\s+\w+:\w+\s+\w+\s+(\w+:\w+:\w+:\w+:\w+:\w+)/",$arrif[$i],$d) == true) {
				//ifname mac
				$ifface["ifname"] = $d[1];
				$ifface["mac"] = $d[2];
			}
			if(preg_match("/^\s+\w+\s+\w+:(\d+.\d+.\d+.\d+)\s+\w+:\d+.\d+.\d+.\d+\s+\w+:(\d+.\d+.\d+.\d+)/",$arrif[$i],$d) == true) {
				//IP
				$ifface["ipaddr"] = $d[1];
				$ifface["netmask"] = $d[2];
			}
		}
		return $net;
	}
	function get_network_dns(){
		$syscall = new dvcmd();
		$syscall->add("cat", "/tmp/resolv.conf.auto | sed '1,1d' | sed 's/nameserver //'","!");
		$syscall->run();
		$rtn = $syscall->result()[0];
		$syscall->close();
		$result = explode("\n",rtrim($rtn));
		return $result;
	}
	function run_wifi_scan($ifname_){
		$syscall = new dvcmd();
//		$syscall->set_buf(1024*20);
		$syscall->add("wifi_scan", $ifname_);
		$syscall->run();
		$rtn = $syscall->result()[0];
		$syscall->close();
		return $rtn;
	}
	function get_scan_result($ifname_, $type_ = "ap"){
		$syscall = new dvcmd();
//		$syscall->set_buf(1024*20);
		$syscall->add("wlanconfig", " ".$ifname_." list ".$type_." | sed '1,1d' ","!");
		$syscall->run();
		$rtn = $syscall->result()[0];
		$syscall->close();
		return $rtn;
	}
	if(strpos($_SERVER['SCRIPT_NAME'],"skb_sub_menu")=== false && strpos($_SERVER['SCRIPT_NAME'],"skb_login_proc")=== false){
		if(dv_session("wan_port") == ""){
			$syscall = new dvcmd();
		//wireless | grep ifname | sed -E "s/(\w+).(\w+).(\w+)=//"
	//		$syscall->add("cat"," /tmp/state/network | grep ifname | sed -E \"s/(\\w+).(\\w+).(\\w+)=//\" ","!");
			$syscall->add("cat"," /tmp/state/network | grep network.wan | sed -E 's/(\w+.\w+.)//'","!");
			$syscall->add("cat"," /tmp/state/network | grep network.lan | sed -E 's/(\w+.\w+.)//'","!");
	//		$syscall->add("cat"," /tmp/state/wireless | grep ifname | sed -E \"s/(\\w+).(\\w+).(\\w+)=//\" ","!");
//			$syscall->add("cat"," /tmp/state/wireless  ","!");
			$syscall->run();
			$wan_data = $syscall->result()[0];
			$wan_data = explode("\n",rtrim($wan_data));
			$lan_data = $syscall->result()[1];
			$lan_data = explode("\n",rtrim($lan_data));
			if(count($wan_data) == 3){
				$wan_port = substr(str_replace("ifname='","",$wan_data[2]),0,-1);
			}else{
				$wan_port = substr(str_replace("device='","",$wan_data[1]),0,-1);
			}
			if(count($lan_data) == 3){
				$lan_port = substr(str_replace("ifname='","",$lan_data[2]),0,-1);
			}else{
				$lan_port = substr(str_replace("device='","",$lan_data[1]),0,-1);
			}
			$syscall->close();
			$syscall = null;
			dv_set_session("wan_port",$wan_port);
			dv_set_session("lan_port",$lan_port);
		}else{
			$wan_port = dv_session("wan_port");
			$lan_port = dv_session("lan_port");
		}
		if(dv_session("wlan_id") == ""){
			dv_set_session("wlan_id",0);
		}
		$port_info = switch_port_status("");
		for($i=0; $i < count($port_info); $i++){
			if($port_info[$i]["name"] == "wan"){
				$wan_no = $port_info[$i]["port"];
			}elseif($port_info[$i]["name"] == "lan1"){
				$lan1_no = $port_info[$i]["port"];
			}else{
				continue;
			}
		}
		$port_info = null;
		dv_set_session("wan_no",$wan_no);
		dv_set_session("lan_no",$lan1_no);
	}
?>