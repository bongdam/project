<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/captcha/simple-php-captcha.php");
	session_start();
	include("simple-php-captcha.php");
	
	$user_id_ = dv_post("user_id");
	$user_pwd_ = dv_post("user_pwd");
	$act_ = dv_post("act");
	function authenticate($user, $pass){
		$syscall = new dvcmd();
		if($syscall->add("getpasswd",$user) === false){
			echo("error");
			return false;
		}
		$syscall->run();
		$shaw = $syscall->result()[0];
		
		$shad =  preg_split("/[$:]/",$shaw);
		if (!isset($shad[2]) || !isset($shad[3])){
			$syscall->add("dvmgmt","/log/output/web WEB: Login fail. (".$user.":".$_SERVER['REMOTE_ADDR'].")");
			$syscall->run();
			return false;
		}
		$mkps = preg_split("/[$:]/",crypt($pass, '$'.$shad[2].'$'.$shad[3].'$'));
		if($shad[4] == $mkps[3]){
			$uci = new uci();
			$uci->mode("get");
			$uci->get("network.lan");
			$uci->run();
			$b = json_decode($uci->result(),true);
			$lanip = get_array_val($b,"network.lan.ipaddr","1");
			$local_ = explode(".",$lanip);
			$user_ = explode(".",$_SERVER['REMOTE_ADDR']);
			if($local_[0] == $user_[0] && $local_[1] == $user_[1] && $local_[2] == $user_[2]){
				if($user_[3] != "254"){
					if($user == "root"){
						$syscall->add("dvmgmt","/log/output/web WEB: Login fail. (".$user.":".$_SERVER['REMOTE_ADDR'].")");
						$syscall->run();
						return "0";
					}
				}
			}
			$user_ip = $_SERVER['REMOTE_ADDR'];
			$secritKey = create_random_str(10).$user.getTimestamp().create_random_str(10);
			$param = Array(
				"type"			=> 0,
				"id"			=> $user,
				"ip"			=> $_SERVER['REMOTE_ADDR'],
				"flag"			=> 1,
				"sec_key"		=> $secritKey,
				"session_file"	=> "/tmp/php/session/sess_".session_id()
			);
			$sock = new rcqm();
			$sock->connect();
			if($sock->con()){
			}else{
				return "0";
			}
			$sock->write("session_check",$param);
			$json = $sock->read();
			$temp = json_decode($json,true);
			if($temp["success"] == false){
				$syscall->add("dvmgmt","/log/output/web WEB: Login fail. (".$user.":".$_SERVER['REMOTE_ADDR'].")");
				$syscall->run();
				return "0";
			}else{
				dv_set_session("login_flag","1");
				dv_set_session("user_id",$user);
				dv_set_session("secritkey",$secritKey);
				$shard_key_ = dv_post("shard_key");
				dv_set_session("shard_key",$shard_key_);
				if($user == "root"){
					
					dv_set_session("user_lvl","0");
				}else{
					dv_set_session("user_lvl","1");
				}
				dv_set_session("session_time",getTimestamp());
				$syscall->add("dvmgmt","/log/output/web WEB: Login success. (".$user.":".$_SERVER['REMOTE_ADDR'].")");
				$syscall->run();
				return "1";
			}
			$syscall->close();
			$sock->disconnect();
//			dv_set_session("login_flag","1");
//			if($user == "root"){
//				dv_set_session("user_lvl","0");
//			}else{
//				dv_set_session("user_lvl","1");
//			}
//			return "1";
		}else{
			$syscall->add("dvmgmt","/log/output/web WEB: Login fail. (".$user.":".$_SERVER['REMOTE_ADDR'].")");
			$syscall->run();
			$syscall->close();
			return "0";
		}
	}
	if($act_ == "login"){
		$user_pwd_ = base64_decode($user_pwd_);
		$result = authenticate($user_id_, $user_pwd_);
		if($result == "1"){
		
			if($user_id_ == "root" && $user_pwd_ == "skb_iptvswitch"){
				echo("1");
				return;
			}elseif($user_id_ == "admin"){
				$default_pwd = "";
				if(file_exists("/sys/class/net/".$wan_port."/address") == true){
					$handle = fopen("/sys/class/net/".$wan_port."/address", "r");
					$contents = fread($handle, filesize("/sys/class/net/".$wan_port."/address"));
					fclose($handle);
					$default_pwd = substr(str_replace(":","",strtoupper(rtrim($contents))),-6)."_admin";
				}
				if($default_pwd == $user_pwd_){
					echo("1");
					return;
				}
			}
			echo("1");
		}else{
			echo("0");
		}
	}elseif($act_ == "captcha"){
		$captcha_text_ = dv_post("captcha_text");
		if($captcha_text_ == dv_session('captcha')["code"]){
			echo("1");
		}else{
			echo("0");
		}
		
	}elseif($act_ == "server_check"){
		if($_SESSION['captcha']['code'] != ""){
			echo("1");
		}else{
			dv_set_session('captcha',simple_php_captcha( array(
				'characters' => 'abcdefghjkmnprstuvwxyz23456789',
				'min_length' => 5,
				'max_length' => 5,
				'min_font_size' => 22,
				'max_font_size' => 22,
				'color' => '#666',
				'angle_min' => 0,
				'angle_max' => 25,
				'shadow' => true,
				'shadow_color' => '#fff',
				'shadow_offset_x' => -1,
				'shadow_offset_y' => 1
			)));
			echo(dv_session('captcha')["image_src"]);
		}
	}elseif($act_ == "create_captcha"){
		dv_set_session('captcha',simple_php_captcha( array(
			'characters' => 'abcdefghjkmnprstuvwxyz23456789',
			'min_length' => 5,
			'max_length' => 5,
			'min_font_size' => 22,
			'max_font_size' => 22,
			'color' => '#666',
			'angle_min' => 0,
			'angle_max' => 25,
			'shadow' => true,
			'shadow_color' => '#fff',
			'shadow_offset_x' => -1,
			'shadow_offset_y' => 1
		)));
		echo(dv_session('captcha')["image_src"]);
	}
?>