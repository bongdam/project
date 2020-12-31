<?php
//	define("DEF_VERSION","v0.0.1");
	$cfg = new dvcfg();
	$cfg->read("dvui");
	$enckey = $cfg->search("dvui.system.enc_key");
	define("DEF_JS_VERSION",$cfg->search("dvui.system.version"));
	define("DEF_CSS_VERSION",$cfg->search("dvui.system.version"));
	define("DEF_UI_DEBUG",$cfg->search("dvui.system.debug"));
	$version = "v0.0.2";
	$jsVersion = "v0.0.2";
	$cssVersion = "v0.0.2";
	$spl = "｜";
	
	/*
		[Key]
			[
				no : MOM서버에서 인식하는 명령어 번호
				type : info -> 정보성 데이터, setting -> 설정관련, system -> 시스템 동작
				name : 로그에 남을 이름
				desc : 해당 RCQM의 명령의 설명을 기입 (선택)
			]
	*/
	$rcqm_command = array(
		"uci_get"			=>["no"=>0,"type"=>"info","name"=>"","desc"=>""],
		"uci_add"			=>["no"=>1,"type"=>"info","name"=>"","desc"=>""],
		"uci_set"			=>["no"=>2,"type"=>"info","name"=>"","desc"=>""],
		"uci_del"			=>["no"=>3,"type"=>"info","name"=>"","desc"=>""],
		"uci_commit"		=>["no"=>4,"type"=>"info","name"=>"","desc"=>""],
		"uci_realname"		=>["no"=>5,"type"=>"info","name"=>"","desc"=>""],
		"syscall"			=>["no"=>6,"type"=>"info","name"=>"","desc"=>""],
		"session_check"		=>["no"=>7,"type"=>"info","name"=>"","desc"=>""],
		"dhcp_list"			=>["no"=>8,"type"=>"info","name"=>"","desc"=>""],
		"traffic_stats"		=>["no"=>9,"type"=>"info","name"=>"","desc"=>""],
		"connection_stats"	=>["no"=>10,"type"=>"info","name"=>"","desc"=>""],
		"wifi_auto_reboot"	=>["no"=>11,"type"=>"info","name"=>"","desc"=>""],
		"diagnosis"			=>["no"=>12,"type"=>"info","name"=>"","desc"=>""],
		"snmp_cfg_reload"	=>["no"=>13,"type"=>"info","name"=>"","desc"=>""]
	);

	$error_msg = "Server Error";
	define("DEF_MOBILE_PATH","");
	define("DEF_UPLOAD_PATH",$cfg->search("dvui.system.upload_path"));
	$fp = fopen("/proc/fwinfo/version","r");
	$fr = fread($fp,100);
	fclose($fp);
	define("DEF_VERSION",trim($fr));
	$fp = fopen("/proc/fwinfo/ant","r");
	$fr = fread($fp,100);
	fclose($fp);
	define("DEF_ANT",trim($fr));
	$fp = fopen("/proc/fwinfo/model","r");
	$fr = fread($fp,100);
	fclose($fp);
	define("DEF_MODEL",trim($fr));
	define("DEF_MAX_TIMEOUT",$cfg->search("dvui.system.ses_timeout"));
	$cfg->close();
?>