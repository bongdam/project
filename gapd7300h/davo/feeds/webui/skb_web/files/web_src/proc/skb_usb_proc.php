<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$act_ = dv_post("act");
	if($act_ == "samba_setting"){
		$samba_enable_ = dv_post("samba_enable");
		$server_port_ = dv_post("server_port");
		$allow_wan_ = dv_post("allow_wan");

		$cfg = new dvcfg();
		$cfg->read("dvui");
		$cfg->read("samba");
		$pre_samba = $cfg->search("samba.smb_config.enabled");
		$pre_port = $cfg->search("dvui.nas.port");
		$pre_allow_wan = $cfg->search("dvui.nas.allow_wan");
		$cfg->close();
		$uci = new uci();
		$uci->mode("set");
		$uci->set("dvui.nas.port",$server_port_);
		$uci->set("dvui.nas.allow_wan",$allow_wan_);
		$uci->run();
		$uci->commit();
		$cmd = new dvcmd();
		if($samba_enable_ == "1"){
//			$cmd->add("nginx_restart");
			$cmd->add("firewall_restart");
			$cmd->add("dvmgmt","/TEST/MOUNT enable");
		}else{
//			$cmd->add("nginx_restart");
			$cmd->add("firewall_restart");
			$cmd->add("dvmgmt","/TEST/MOUNT disable");
		}
		$cmd->run();
		$cmd->result();
		$cmd->close();
		sleep(1.6);
//		header("Location:".dv_post("submit-url"));
		echo("1");
	}elseif($act_ == "set_user"){
		$uci = new uci();
		$uci->mode("set");
		$user = Array();
		$pass = Array();
		$permission = Array();
		$comment = Array();

		$user_ = dv_post("user");
		$pass_ = dv_post("pass");
		$permission_ = dv_post("permission");
		$comment_ = dv_post("comment");

		$cfg = new dvcfg();
		$cfg->read("dvui","nas");
		$arr_user = $cfg->search("dvui.nas.user","array");
		$arr_pass = $cfg->search("dvui.nas.pass","array");
		$arr_per = $cfg->search("dvui.nas.permission","array");
		$arr_com = $cfg->search("dvui.nas.comment","array");
		if($arr_user == ""){
			$arr_user = Array($user_);
			$arr_pass = Array(AES_Encode($pass_));
			$arr_per = Array($permission_);
			$arr_com = Array($comment_);
		}else{
			$arr_user[] = $user_;
			$arr_pass[] = AES_Encode($pass_);
			$arr_per[] = $permission_;
			$arr_com[] = $comment_;
		}

		$uci->set("dvui.nas.user",$arr_user);
		$uci->set("dvui.nas.pass",$arr_pass);
		$uci->set("dvui.nas.permission",$arr_per);
		$uci->set("dvui.nas.comment",$arr_com);
		$uci->run();
		$uci->commit();
		echo("1");
	}elseif($act_ == "get_user"){
		$cfg = new dvcfg();
		$cfg->read("dvui","nas");
		echo($cfg->result("json_string"));
		$cfg->close();
	}elseif($act_ == "del_user"){
		$user_id_ = dv_post("user_id");
		$cfg = new dvcfg();
		$cfg->read("dvui","nas");
		$arr_user = $cfg->search("dvui.nas.user","array");
		$arr_pass = $cfg->search("dvui.nas.pass","array");
		$arr_per = $cfg->search("dvui.nas.permission","array");
		$arr_com = $cfg->search("dvui.nas.comment","array");
		$del_index = array_search($user_id_, $arr_user);
		if($del_index === false){
			echo("0");
			return;
		}else{
			array_splice($arr_user,$del_index,1);
			array_splice($arr_pass,$del_index,1);
			array_splice($arr_per,$del_index,1);
			array_splice($arr_com,$del_index,1);
		}
		$uci = new uci();
		$uci->mode("set");
		$uci->set("dvui.nas.user",$arr_user);
		$uci->set("dvui.nas.pass",$arr_pass);
		$uci->set("dvui.nas.permission",$arr_per);
		$uci->set("dvui.nas.comment",$arr_com);
		$uci->run();
		$uci->commit();
		echo("1");
	}elseif($act_ == "web_server_restart"){
		$cmd = new dvcmd();
		$cmd->add("nginx_restart");
		$cmd->run();
		$cmd->result();
		$cmd->close();
		echo("1");
	}
	
?>