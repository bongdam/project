<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	$act_ = dv_post("act");
	switch($act_){
		case "upload":
			$fileName = $_FILES["binary"]["name"];
			if (file_exists('/tmp/firmware.img')) {
				@unlink('/tmp/firmware.img');
			}
			@move_uploaded_file($_FILES["binary"]["tmp_name"],"/tmp/firmware.img");
			header("Location:/skb_upload_time.php");
			break;
		case "tftp":
			$server = dv_post("server");
			$file = dv_post("file");
			$param = Array();
			$cmd = Array("cmd"=>"tftp -l /tmp/firmware.img -r ".$file." -g ".$server);
			$param[] = $cmd;
			$sock = new rcqm();
			$sock->set_config("timeout",300);
			$sock->connect();
			if($sock->con()){
			}else{
				return "0";
			}
//			print_r($sock->get_meta());
			$sock->write("syscall",$param);
//			print_r($sock->get_meta());
			$result = json_decode($sock->read(),true);
			if($result["success"] == true){
				header("Location:/skb_upload_time.php");
			}else{
				echo("업그레이드를 실패했습니다.<br>");
				echo("<input type=\"button\" name=\"btn_ok\" id=\"btn_ok\" value=\"확인\" onclick=\"window.location.href='".dv_post("submit-url")."';\">");
//				header("Location:/skb_upload.php");
			}
			break;
		case "apply":
			$syscall = new dvcmd();
			$syscall->add("firmware_upgrade");
			$syscall->run("fast");
			$syscall->close();
			echo("1");
	}
	
	
?>