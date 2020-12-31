<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");

	$act_ = dv_post("act");
	$scan = "";
	Switch($act_){
		CASE "ap_scan":
			$flag =  dv_post("flag");
			if(dv_session("wlan_id") == "1"){
				if(file_exists("/tmp/ath0_scan.txt") == false){
					run_wifi_scan("ath0");
				}else{
					if($flag == "rescan"){
						run_wifi_scan("ath0");
					}
				}
				$scanfile = "/tmp/ath0_scan.txt";
			}else{
				if(file_exists("/tmp/ath1_scan.txt") == false){
					run_wifi_scan("ath1");
				}else{
					if($flag == "rescan"){
						run_wifi_scan("ath1");
					}
				}
				$scanfile = "/tmp/ath1_scan.txt";
			}
			$handle = fopen($scanfile, "r");
			$contents = fread($handle, filesize($scanfile));
			fclose($handle);
			$scan = explode("\n",rtrim($contents));
			$result = Array();
			for($i=0; $i < count($scan); $i++){
		//		echo $scan[$i]."<br>";
				if(preg_match("/^\[\s+([\w+\:]{6,})\s+(\d+)\s+([\d\-]{1,})\s+([\w+\-\/]{1,})\s+([\w+\-\/\.]{1,})\s+(\w+)\s+\"([\s+\S]{0,})\"\s+[\s+\S+]{0,}\]$/",$scan[$i],$d) == true) {
					$tmp = Array(
						"mac" => $d[1],
						"channel" => $d[2],
						"rssi" => $d[3],
						"mode" => $d[4],
						"security" => str_replace("open","OPEN",str_replace("wep","WEP",str_replace("WAP","WPA",$d[5]))),
						"ap_mode" => $d[6],
						"ssid" => $d[7]
					);
					$result[] = $tmp;
				}
			}
			echo array_to_json($result);
			break;
		CASE "repeater_ap_scan":
			if(dv_session("wlan_id") == "1"){
				run_wifi_scan("ath0");
				$scanfile = "/tmp/ath0_scan.txt";
			}else{
				run_wifi_scan("ath1");
				$scanfile = "/tmp/ath1_scan.txt";
			}
			$handle = fopen($scanfile, "r");
			$contents = fread($handle, filesize($scanfile));
			fclose($handle);
			$scan = explode("\n",rtrim($contents));
			$result = Array();
			for($i=0; $i < count($scan); $i++){
		//		echo $scan[$i]."<br>";
				if(preg_match("/^\[\s+([\w+\:]{6,})\s+(\d+)\s+([\d\-]{1,})\s+([\w+\-\/]{1,})\s+([\w+\-\/\.]{1,})\s+(\w+)\s+\"([\s+\S]{0,})\"\s+[\s+\S+]{0,}\]$/",$scan[$i],$d) == true) {
					$tmp = Array(
						"mac" => $d[1],
						"channel" => $d[2],
						"rssi" => $d[3],
						"mode" => $d[4],
						"security" => str_replace("open","OPEN",str_replace("wep","WEP",str_replace("WAP","WPA",$d[5]))),
						"ap_mode" => $d[6],
						"ssid" => $d[7]
					);
					$result[] = $tmp;
				}
			}
			echo array_to_json($result);
			break;
	}
?>