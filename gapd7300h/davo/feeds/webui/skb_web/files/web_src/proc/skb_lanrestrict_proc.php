<?php
	require_once($_SERVER["DOCUMENT_ROOT"]."/inc/default_ssi.php");
	require_once($_SERVER["DOCUMENT_ROOT"]."/skb_common.php");
	$uci = new uci();
	$uci->mode("set");
	for($i=1; $i <= 4; $i++){
		$status = "";
		$action = "";
		if(dv_post("skip_port".$i) == false){
			if( dv_post("lan_restrict_port_enable".$i) != ""){
				//Enable
				$status = "enable";
				$action = "drop";
			}else{
				//Disable
				$status = "disable";
				$action = "forward";
			}
	//		lan4_no
	//		lan_restrict_num
			$uci->set("network.fdbptlearnlimit_".dv_post("lan".$i."_no"),"switch_ext");
			$uci->set("network.fdbptlearnlimit_".dv_post("lan".$i."_no").".device","switch0");
			$uci->set("network.fdbptlearnlimit_".dv_post("lan".$i."_no").".name","FdbPtlearnlimit");
			$uci->set("network.fdbptlearnlimit_".dv_post("lan".$i."_no").".port_id",dv_post("lan".$i."_no"));
			$uci->set("network.fdbptlearnlimit_".dv_post("lan".$i."_no").".learn_limit_status",$status);
			$uci->set("network.fdbptlearnlimit_".dv_post("lan".$i."_no").".learn_limit_counter",dv_post("lan_restrict_num".$i));

			$uci->set("network.fdbptlearnexceedcmd_".dv_post("lan".$i."_no"),"switch_ext");
			$uci->set("network.fdbptlearnexceedcmd_".dv_post("lan".$i."_no").".device","switch0");
			$uci->set("network.fdbptlearnexceedcmd_".dv_post("lan".$i."_no").".name","FdbPtlearnexceedcmd");
			$uci->set("network.fdbptlearnexceedcmd_".dv_post("lan".$i."_no").".port_id",dv_post("lan".$i."_no"));
			$uci->set("network.fdbptlearnexceedcmd_".dv_post("lan".$i."_no").".learn_exceed_cmd",$action);
		}
	}
	$uci->run();
	$uci->commit();
	echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));

?>