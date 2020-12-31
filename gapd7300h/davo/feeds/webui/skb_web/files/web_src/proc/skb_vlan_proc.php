<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
//	create_post_value();
$wan_pvid_ = dv_post("wan_pvid");
$lan1_pvid_ = dv_post("lan1_pvid");
$lan2_pvid_ = dv_post("lan2_pvid");
$lan3_pvid_ = dv_post("lan3_pvid");
$lan4_pvid_ = dv_post("lan4_pvid");

$wan_port_no_ = dv_post("wan_port_no");
$lan_port_no_ = dv_post("lan_port_no");

$pvid_wan_ = dv_post("pvid_wan");
$pvid_lan1_ = dv_post("pvid_lan1");
$pvid_lan2_ = dv_post("pvid_lan2");
$pvid_lan3_ = dv_post("pvid_lan3");
$pvid_lan4_ = dv_post("pvid_lan4");


//exit;
$uci = new uci();
$uci->mode("get");
$uci->get("network.lan._orig_ipaddr");
$uci->run();
$lan = json_decode($uci->result(),true);
$opmode = 1;
if(array_key_exists("network.lan._orig_ipaddr",$lan) == false){
	$opmode = 0;
}

$uci->mode("del");
for($i = 1 ; $i <= 16 ; $i++){
//	echo("network.@switch_vlan[".$i."]");
	$uci->del("network.switch_vlan_".$i);
}
for($i = 0 ; $i < 6 ; $i++){
//	echo("network.@switch_vlan[".$i."]");
	$uci->del("network.switch_port_".$i);
}
$uci->run();
$uci->mode("set");
$eq = 1;
for($i =1 ; $i <= 16 ; $i++){
	if(dv_post("use".($i)) == "1"){
		$uci->set("network.switch_vlan_".$eq,"switch_vlan");
		$uci->set("network.switch_vlan_".$eq.".device","switch0");
		$uci->set("network.switch_vlan_".$eq.".vlan",dv_post("vid".$i));
		if(dv_post("vlan_ports".($i)) != ""){
			$uci->set("network.switch_vlan_".$eq.".ports",dv_post("vlan_ports".$i));
		}
		$uci->set("network.switch_vlan_".$eq.".vid",dv_post("vid".$i));
		$eq = $eq + 1;
	}
}
//$uci->run();
////PVID SET

/*
	$pvid_wan_ = dv_post("pvid_wan");
	$pvid_lan1_ = dv_post("pvid_lan1");
	$pvid_lan2_ = dv_post("pvid_lan2");
	$pvid_lan3_ = dv_post("pvid_lan3");
	$pvid_lan4_ = dv_post("pvid_lan4");
*/
/*
	switch_port
        option device 'switch0'
        option pvid '3'
        option port '4'
*/
//$eqs = 0;
//$uci->mode("set");
$uci->set("network.switch_port_0","switch_port");
$uci->set("network.switch_port_0.device","switch0");
$uci->set("network.switch_port_0.pvid","0");
$uci->set("network.switch_port_0.port","0");
if($pvid_wan_ != ""){
	$uci->set("network.switch_port_1","switch_port");
	$uci->set("network.switch_port_1.device","switch0");
	$uci->set("network.switch_port_1.pvid",$pvid_wan_);
	$uci->set("network.switch_port_1.port",$wan_port_no_);
}else{
	$uci->set("network.switch_port_1","switch_port");
	$uci->set("network.switch_port_1.device","switch0");
	if($opmode == 1){
		$uci->set("network.switch_port_1.pvid","1");
	}else{
		$uci->set("network.switch_port_1.pvid","2");
	}
	$uci->set("network.switch_port_1.port",$wan_port_no_);
}
for($i=2; $i <= 5; $i++){
	if(dv_post("pvid_lan".($i-1)) != ""){
		$uci->set("network.switch_port_".$i,"switch_port");
		$uci->set("network.switch_port_".$i.".device","switch0");
		$uci->set("network.switch_port_".$i.".pvid",dv_post("pvid_lan".($i-1)));
		$uci->set("network.switch_port_".$i.".port",($lan_port_no_+($i-2)));
	}else{
		$uci->set("network.switch_port_".$i."","switch_port");
		$uci->mode("set");
		$uci->set("network.switch_port_".$i.".device","switch0");
		$uci->set("network.switch_port_".$i.".pvid","1");
		$uci->set("network.switch_port_".$i.".port",($lan_port_no_+($i-2)));
	}
}
$uci->run();
$uci->commit();
echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));
?>