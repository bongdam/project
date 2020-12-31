<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");

$port_ = dv_post("port");
$rate_ = dv_post("rate");
if($rate_ > 1048544){
	$rate_ = 1048544;
}
if($rate_ > 524288){
	$rate1 = 524288;
}else{
	$rate1 = $rate_;
}
$uci = new uci();
$uci->mode("del");
$uci->del("network.bstorm_ctrl_acl");
$uci->del("network.bstorm_ctrl_rule");
$uci->run();
if(dv_post("broadcast_storm_ctrl_enable") == "1"){
	$uci->mode("set");

	$uci->set("network.bstorm_ctrl_acl","switch_ext");
	$uci->set("network.bstorm_ctrl_acl.device","switch0");

	$uci->set("network.bstorm_ctrl_acl.name","RateAclPolicer");
	$uci->set("network.bstorm_ctrl_acl.policer_id","1");
	$uci->set("network.bstorm_ctrl_acl.counter_mode","no");
	$uci->set("network.bstorm_ctrl_acl.byte_based","yes");
	$uci->set("network.bstorm_ctrl_acl.couple_flag","no");
	$uci->set("network.bstorm_ctrl_acl.color_aware","no");
	$uci->set("network.bstorm_ctrl_acl.deficit_flag","yes");
	$uci->set("network.bstorm_ctrl_acl.cir",$rate_);
	$uci->set("network.bstorm_ctrl_acl.cbs",$rate1);
	$uci->set("network.bstorm_ctrl_acl.eir","0");
	$uci->set("network.bstorm_ctrl_acl.ebs","0");
	$uci->set("network.bstorm_ctrl_acl.meter_interval","1ms");


	$uci->set("network.bstorm_ctrl_rule","switch_ext");
	$uci->set("network.bstorm_ctrl_rule.device","switch0");
	$uci->set("network.bstorm_ctrl_rule.name","AclRule");

	$uci->set("network.bstorm_ctrl_rule.rule_id","33");
	$uci->set("network.bstorm_ctrl_rule.priority","1");
	$uci->set("network.bstorm_ctrl_rule.rule_type","mac");
	$uci->set("network.bstorm_ctrl_rule.port_bitmap",$port_);
	$uci->set("network.bstorm_ctrl_rule.packet_drop","no");
	$uci->set("network.bstorm_ctrl_rule.dst_mac_address","ff-ff-ff-ff-ff-ff");
	$uci->set("network.bstorm_ctrl_rule.dst_mac_address_mask","ff-ff-ff-ff-ff-ff");
	$uci->set("network.bstorm_ctrl_rule.action_policer_id","1");
	$uci->run();
}
$uci->result();
$uci->commit();
echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));
?>