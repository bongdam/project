<?
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
//	create_post_value();
	$uci = new uci();

	$wan_no_ = dv_post("wan_no"); 
	$lan1_no_ = dv_post("lan1_no"); 
	$igmpfast_ = dv_post("igmpfast");
	if($igmpfast_ == "1"){
		//SET
		$uci->mode("set");
		$uci->set("igmpproxy.igmpproxy.quickleave","1");
	}else{
		$uci->mode("set");
		$uci->set("igmpproxy.igmpproxy.quickleave","0");
	}
	$uci->mode("set");
	$dv_igmp_joinlimit_enable_ = dv_post("dv_igmp_joinlimit_enable");
	
	//enable
	$igmp_querier_enable_ = dv_post("igmp_querier_enable") ? dv_post("igmp_querier_enable") : "0";
	if($igmp_querier_enable_ == "1"){
		$uci->set("mcsd.config.query_mode",dv_post("igmp_querier_mode"));
	}else{
		$uci->set("mcsd.config.query_mode","0");
	}
	if($dv_igmp_joinlimit_enable_ == "1"){
		$uci->set("mcsd.config.port_limit","1");
	}else{
		$uci->set("mcsd.config.port_limit","0");
	}
	$uci->set("mcsd.config.query_interval",dv_post("igmp_querier_interval") ? dv_post("igmp_querier_interval") : 125);
	
	$port_no = $lan1_no_;
	for($i=1; $i < 5 ;$i++){
		$port_no = ($lan1_no + ($i-1));
		$uci->set("network.igmpPtlearnlimit_".$port_no,"switch_ext");
		$uci->set("network.igmpPtlearnlimit_".$port_no.".device","switch0");
		$uci->set("network.igmpPtlearnlimit_".$port_no.".name","IgmpPtlearnlimit");
		$uci->set("network.igmpPtlearnlimit_".$port_no.".port_id",$port_no);
		if($dv_igmp_joinlimit_enable_ == "1"){
			$uci->set("network.igmpPtlearnlimit_".$port_no.".learn_limit_status","enable");
		}else{
			$uci->set("network.igmpPtlearnlimit_".$port_no.".learn_limit_status","disable");
		}
		$uci->set("network.igmpPtlearnlimit_".$port_no.".learn_limit_counter",dv_post("dv_igmp_limite_lan".$i));
//		echo("lan".$i);
	}
	$uci->set("network.igmpPtlearnlimit_".$wan_no_,"switch_ext");
	$uci->set("network.igmpPtlearnlimit_".$wan_no_.".device","switch0");
	$uci->set("network.igmpPtlearnlimit_".$wan_no_.".name","IgmpPtlearnlimit");
	$uci->set("network.igmpPtlearnlimit_".$wan_no_.".port_id",$wan_no_);
	if($dv_igmp_joinlimit_enable_ == "1"){
		$uci->set("network.igmpPtlearnlimit_".$wan_no_.".learn_limit_status","enable");
	}else{
		$uci->set("network.igmpPtlearnlimit_".$wan_no_.".learn_limit_status","disable");
	}
	$uci->set("network.igmpPtlearnlimit_".$wan_no_.".learn_limit_counter","0");

	$uci->run();
	$uci->commit();	
	echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));
?>