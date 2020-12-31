<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$act_ = dv_post("act");
	switch($act_){
		case "get_system_info":
			$cmd = new dvcmd();
//			$cmd->add("cpuusage");
			$cmd->add("cat","/proc/meminfo | grep -e \"MemTotal\" -e \"MemFree\" -e \"MemAvailable\" -e \"Buffers\" -e \"Cached\" | sed 's/MemTotal://' | sed 's/MemFree://' | sed 's/MemAvailable://' | sed 's/Buffers://'| sed 's/Cached://' | sed 's/kB//'","!");
			$cmd->add("cat","/proc/uptime ");
			$cmd->add("channel_info");
			$cmd->add("sta_list");
			$cmd->run();
//			$cpu_info = rtrim($cmd->result()[0]);
			$meminfo = explode("\n",rtrim($cmd->result()[0]));
			$uptime = explode(" ",rtrim($cmd->result()[1]))[0];
			$mem_total = trim($meminfo[0]);
			$mem_free = trim($meminfo[1]);
			$mem_available = trim($meminfo[2]);
			$mem_buf = trim($meminfo[3]);
			$mem_cache = trim($meminfo[4]);
			if(!is_numeric($mem_total)){
				$mem_total = 0;
			}
			if(!is_numeric($mem_free)){
				$mem_free = 0;
			}
			if(!is_numeric($mem_buf)){
				$mem_buf = 0;
			}
			if(!is_numeric($mem_cache)){
				$mem_cache = 0;
			}
			$channel_info = explode(",",rtrim($cmd->result()[2]));
			$channel_5 = $channel_info[0];
			$channel_24 = $channel_info[1];
			$sta_list = "";
			if(file_exists("/tmp/station.txt") == true){
				$handle = fopen("/tmp/station.txt", "r");
				$contents = fread($handle, filesize("/tmp/station.txt"));
				fclose($handle);
				$sta_list = explode("\n",rtrim($contents));
			}
			$sta = array();
			$wifi2_cnt = 0;
			$wifi21_cnt = 0;
			$wifi22_cnt = 0;
			$wifi5_cnt = 0;
			$wifi51_cnt = 0;
			$wifi52_cnt = 0;
			for($i=0 ; $i < count($sta_list); $i++){
				if(preg_match("/^[\s+]{0,}\[\s+(\S+)\s+([\w+\:]{6,})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+[\s+\S+]{0,}\]$/",$sta_list[$i],$d) == true) {
		//			print_r($d);
					if($d[1] == "ath1"){
						$wifi2_cnt += 1;
					}elseif($d[1] == "ath0" || $d[1] == "ath04"){
						$wifi5_cnt += 1;
					}elseif($d[1] == "ath01"){
						$wifi51_cnt += 1;
					}elseif($d[1] == "ath02"){
						$wifi52_cnt += 1;
					}elseif($d[1] == "ath11"){
						$wifi21_cnt += 1;
					}elseif($d[1] == "ath12"){
						$wifi22_cnt += 1;
					}
				}
			}
			$system_info = Array(
				"cpu"=>$cpu_info,
				"meminfo"=>Array(
					"total"=>$mem_total,
					"free" =>$mem_free,
					"available"=>$mem_available,
					"buffer"=>$mem_buf,
					"cache"=>$mem_cache
				),
				"uptime"=>sec_to_date($uptime),
				"channel"=>Array(
					"ch24"=>$channel_24,
					"ch5"=>$channel_5
				),
				"sta_cnt"=>Array(
					"cnt24"=>$wifi2_cnt,
					"cnt241"=>$wifi21_cnt,
					"cnt242"=>$wifi22_cnt,
					"cnt5"=>$wifi5_cnt,
					"cnt51"=>$wifi51_cnt,
					"cnt52"=>$wifi52_cnt
				)
			);
			echo array_to_json($system_info);
			break;
		case "get_cpu_info":
			$cmd = new dvcmd();
			$cmd->add("cpuusage");
			$cmd->run();
			$cpu_info = rtrim($cmd->result()[0]);
			echo($cpu_info);
			$cmd->close();
			break;
		case "get_network_info":
			$syscall = new dvcmd();
//			$syscall->add("ifconfig", "","!");
			$syscall->add("ifconfig", dv_session("wan_port"),"!");
			$syscall->add("ifconfig", dv_session("lan_port"),"!");
			$syscall->run();
			$rtn = $syscall->result()[0].$syscall->result()[1];
			$arrif = explode("\n",$rtn);
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
//				print_r($arrif[$i]);
				if(preg_match("/^([\w\d-\.]{1,})\s+\w+\s+\w+:\w+\s+\w+\s+(\w+:\w+:\w+:\w+:\w+:\w+)\s+/",$arrif[$i],$d) == true) {
					//ifname mac
					$ifface["ifname"] = $d[1];
					$ifface["mac"] = $d[2];
				}
				if(preg_match("/^\s+\w+\s+\w+:(\d+.\d+.\d+.\d+)\s+\w+:\d+.\d+.\d+.\d+\s+\w+:(\d+.\d+.\d+.\d+)/",$arrif[$i],$d) == true) {
					$ifface["ipaddr"] = $d[1];
					$ifface["netmask"] = $d[2];
				}
			}
			set_head_json();
			echo json_encode($net);
			break;
		case "get_lan_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("network.lan");
			$uci->get("dhcp.lan");
			$uci->run();
			$uci_lan = $uci->result();
			echo($uci_lan);
			$uci->close();
			break;
		case "get_wan_info":
			$uci = new uci();
			$uci->mode("get");
			$uci->get("network.wan");
			$uci->run();
			$uci_wan = $uci->result();
			echo($uci_wan);
			$uci->close();
			break;
		case "get_wan_gateway":
			$syscall = new dvcmd();
			$syscall->add("ip_route","");
			$syscall->run();
			$wan_info = $syscall->result()[0];
			$syscall->close();
			$wan_info = explode("\n",rtrim($wan_info."\n"))[0];
			$info = Array();
			if(preg_match("/^\w+\s+\w+\s+(\d+.\d+.\d+.\d+)/",$wan_info,$d) == true) {
				$info["gateway"] = $d[1];
			}
			$dns = get_network_dns();
			for($i =0 ; $i < count($dns); $i++){
				$info["dns".($i+1)] = $dns[$i];
			}
			echo json_encode($info);
			break;
		case "get_network_port_status":
			$a = switch_port_status();
			$d[] = $a[1];
			$d[] = $a[2];
			$d[] = $a[3];
			$d[] = $a[4];
			$d[] = $a[5];

			echo(json_encode($d));
			break;
		case "ip_refresh":
			$syscall = new dvcmd();
			$syscall->add("ifconfig", $wan_port." down","!");
			$syscall->add("ifconfig", $wan_port." up","!");
			$syscall->run();
			$syscall->result();
			$syscall->close();
			break;
		default:
			echo("error");
			break;
	}
?>