<?php
	class dc_dev{
		private $device = '';
		private $res = Array(
			"os"		=> "", //window, ios, android, osx
			"type"		=> "", //pc, mobile, tablet
			"version"	=> "",
			"browser"	=> "",
			"etc"		=> ""
		);
		public function __construct()
		{
			$res = $this->res;
			$device = $_SERVER["HTTP_USER_AGENT"];
//			print_r($device)."<br>";
			if(stripos($device,"iphone") !== false){
				$res["os"] = "ios";
				$res["type"] = "mobile";
				$res["etc"] = "iphone";
			}
			if(stripos($device,"ipad") !== false){
				$res["os"] = "ios";
				$res["type"] = "tablet";
				$res["etc"] = "ipad";
			}
			if(stripos($device,"iPod") !== false){
				$res["os"] = "ios";
				$res["type"] = "mobile";
				$res["etc"] = "ipod";
			}
			if(stripos($device,"Android") !== false){
				$res["os"] = "android";
				$res["type"] = "mobile";
				//$res["etc"] = "iphone";
				if(stripos($device,"mobile") !== false){
					$res["type"] = "mobile";
				}else{
					$res["type"] = "tablet";
				}
			}
			if(stripos($device,"windows") !== false){
				$res["os"] = "windows";
			}
			if($res["type"] == ""){
				$res["type"] = "pc";
			}
			if(stripos($device,"Trident") !== false){
				$res["browser"] = "ie";
			}
			if(stripos($device,"Firefox") !== false){
				$res["browser"] = "firefox";
			}
			if(stripos($device,"Chrome") !== false){
				$res["browser"] = "chrome";
			}
			if(stripos($device,"Chrome") === false && stripos($device,"Safari") !== false){
				$res["browser"] = "safari";
			}
//			var_dump($res);
			$this->res = $res;
		}
		public function isMobile(){
			$res = $this->res;
//			var_dump($res);
			if($res["os"] == "ios" || $res["os"] == "android"){
				return true;
			}else{
				return false;
			}
		}
	}
?>