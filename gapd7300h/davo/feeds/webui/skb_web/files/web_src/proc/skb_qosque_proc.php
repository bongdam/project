<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
//	create_post_value();
	$wan_no = dv_post("wan_no");
	$lan_no = dv_post("lan_no");
	
	$uci = new uci();
	$uci->mode("del");
	for($i=1; $i <= 5 ; $i++){
		$uci->del("network.qosptschmode_".$i);
		$uci->del("network.rateportpolicer_".$i);
		$uci->del("network.rateportshaper_".$i);
	}
	$uci->del("network.qosptschmode_6");
	$uci->del("network.rateportpolicer_6");
	$uci->del("network.rateportshaper_6");
	if(DEF_MODEL == "QCA_REF" && DEF_ANT == "4x4"){
		$uci->del("network.qosptschmode_0");
		$uci->del("network.rateportpolicer_0");
		$uci->del("network.rateportshaper_0");
	}

	$uci->run();
	$uci->mode("set");
	for($i=1; $i <= 5 ; $i++){
		if($wan_no == $i){
			if(dv_post("qos_enable".$i) == "1"){
				$uci->set("network.qosptschmode_".$i,"switch_ext");
				$uci->set("network.qosptschmode_".$i.".device","switch0");
				$uci->set("network.qosptschmode_".$i.".name","QosPtschMode");
				$uci->set("network.qosptschmode_".$i.".port_id",dv_post("qos_port_no").$i);
				$uci->set("network.qosptschmode_".$i.".mode",dv_post("qos_mode".$i));
				$wan_we_temp = dv_post("qos_weight".$i);
				$wan_we_temp = explode(",",$wan_we_temp);
	//			echo count($wan_we_temp);
				$wan_weight = $wan_we_temp[0].",".$wan_we_temp[0].",".$wan_we_temp[1].",".$wan_we_temp[1].",".$wan_we_temp[2].",".$wan_we_temp[3];
				$uci->set("network.qosptschmode_".$i.".weight",dv_post("qos_weight".$i));
			}else{
				$uci->set("network.qosptschmode_".$i,"switch_ext");
				$uci->set("network.qosptschmode_".$i.".device","switch0");
				$uci->set("network.qosptschmode_".$i.".name","QosPtschMode");
				$uci->set("network.qosptschmode_".$i.".port_id",dv_post("qos_port_no").$i);
				$uci->set("network.qosptschmode_".$i.".mode","sp");
				$wan_we_temp = dv_post("qos_weight".$i);
				$wan_we_temp = explode(",",$wan_we_temp);
	//			echo count($wan_we_temp);
				$wan_weight = "3,3,7,7,0,0";
				$uci->set("network.qosptschmode_".$i.".weight",dv_post("qos_weight".$i));
			}
			if(dv_post("qos_rate".$i) == "1"){
				$uci->set("network.rateportpolicer_".$i,"switch_ext");
				$uci->set("network.rateportpolicer_".$i.".device","switch0");
				$uci->set("network.rateportpolicer_".$i.".name","RatePortPolicer");
				$uci->set("network.rateportpolicer_".$i.".port_id",$wan_no);
				$uci->set("network.rateportpolicer_".$i.".combine_enable","no");
				$uci->set("network.rateportpolicer_".$i.".byte_based","yes");
				$uci->set("network.rateportpolicer_".$i.".couple_flag","no");
				$uci->set("network.rateportpolicer_".$i.".color_aware","no");
				$uci->set("network.rateportpolicer_".$i.".deficit_flag","yes");
				$uci->set("network.rateportpolicer_".$i.".c_bucket_enable","yes");//no
				$qos_in_rate = dv_post("qos_in_rate".$i);
				if($qos_in_rate == ""){
					$qos_in_rate_ir  = "0";
					$qos_in_rate_bs  = "0";
				}else{
					$qos_in_rate_ir  = $qos_in_rate;
					if((int)$qos_in_rate_ir > 1048544){
						$qos_in_rate_ir = "1048544";
					}
					$qos_in_rate_bs  = $qos_in_rate;
					if((int)$qos_in_rate_bs > 524288){
						$qos_in_rate_bs = "524288";
					}
				}
				$uci->set("network.rateportpolicer_".$i.".cir",$qos_in_rate_ir);//
				$uci->set("network.rateportpolicer_".$i.".cbs",$qos_in_rate_bs);//
				$uci->set("network.rateportpolicer_".$i.".c_rate_flag","0xfe");
				$uci->set("network.rateportpolicer_".$i.".c_meter_interval","1ms");
				$uci->set("network.rateportpolicer_".$i.".e_bucket_enable","yes");//no
				$uci->set("network.rateportpolicer_".$i.".eir",$qos_in_rate_ir);//
				$uci->set("network.rateportpolicer_".$i.".ebs",$qos_in_rate_bs);//
				$uci->set("network.rateportpolicer_".$i.".e_rate_flag","0xfe");
				$uci->set("network.rateportpolicer_".$i.".e_meter_interval","1ms");

				$uci->set("network.rateportshaper_".$i,"switch_ext");
				$uci->set("network.rateportshaper_".$i.".device","switch0");
				$uci->set("network.rateportshaper_".$i.".name","RatePortShaper");
				$uci->set("network.rateportshaper_".$i.".port_id",$wan_no);
				$uci->set("network.rateportshaper_".$i.".status","enable");//disable
				$uci->set("network.rateportshaper_".$i.".byte_based","yes");
				$qos_out_rate = dv_post("qos_out_rate".$i);
				if($qos_out_rate == ""){
					$qos_out_rate_ir = "0";
					$qos_out_rate_bs = "0";
				}else{
					$qos_out_rate_ir  = $qos_out_rate;
					if((int)$qos_out_rate_ir > 1048544){
						$qos_out_rate_ir = "1048544";
					}
					$qos_out_rate_bs  = $qos_out_rate;
					if((int)$qos_out_rate_bs > 524288){
						$qos_out_rate_bs = "524288";
					}
				}
				$uci->set("network.rateportshaper_".$i.".cir",$qos_out_rate_ir);//
				$uci->set("network.rateportshaper_".$i.".cbs",$qos_out_rate_bs);//
				$uci->set("network.rateportshaper_".$i.".eir","0");//
				$uci->set("network.rateportshaper_".$i.".ebs","0");//
			}else{
				$uci->set("network.rateportpolicer_".$i,"switch_ext");
				$uci->set("network.rateportpolicer_".$i.".device","switch0");
				$uci->set("network.rateportpolicer_".$i.".name","RatePortPolicer");
				$uci->set("network.rateportpolicer_".$i.".port_id",$wan_no);
				$uci->set("network.rateportpolicer_".$i.".combine_enable","no");
				$uci->set("network.rateportpolicer_".$i.".byte_based","yes");
				$uci->set("network.rateportpolicer_".$i.".couple_flag","no");
				$uci->set("network.rateportpolicer_".$i.".color_aware","no");
				$uci->set("network.rateportpolicer_".$i.".deficit_flag","yes");
				$uci->set("network.rateportpolicer_".$i.".c_bucket_enable","no");//no
				$uci->set("network.rateportpolicer_".$i.".cir","0");//
				$uci->set("network.rateportpolicer_".$i.".cbs","0");//
				$uci->set("network.rateportpolicer_".$i.".c_rate_flag","0xfe");
				$uci->set("network.rateportpolicer_".$i.".c_meter_interval","1ms");
				$uci->set("network.rateportpolicer_".$i.".e_bucket_enable","no");//no
				$uci->set("network.rateportpolicer_".$i.".eir","0");//
				$uci->set("network.rateportpolicer_".$i.".ebs","0");//
				$uci->set("network.rateportpolicer_".$i.".e_rate_flag","0xfe");
				$uci->set("network.rateportpolicer_".$i.".e_meter_interval","1ms");

				$uci->set("network.rateportshaper_".$i,"switch_ext");
				$uci->set("network.rateportshaper_".$i.".device","switch0");
				$uci->set("network.rateportshaper_".$i.".name","RatePortShaper");
				$uci->set("network.rateportshaper_".$i.".port_id",$wan_no);
				$uci->set("network.rateportshaper_".$i.".status","disable");//disable
				$uci->set("network.rateportshaper_".$i.".byte_based","yes");
				$uci->set("network.rateportshaper_".$i.".cir","0");//
				$uci->set("network.rateportshaper_".$i.".cbs","0");//
				$uci->set("network.rateportshaper_".$i.".eir","0");//
				$uci->set("network.rateportshaper_".$i.".ebs","0");//
			}
			if(dv_post("qos_enable".$i) == "1"){
				$uci->set("network.qosptschmode_0","switch_ext");
					$uci->set("network.qosptschmode_0.device","switch0");
					$uci->set("network.qosptschmode_0.name","QosPtschMode");
					$uci->set("network.qosptschmode_0.port_id","0");
					$uci->set("network.qosptschmode_0.mode",dv_post("qos_mode".$wan_no));
					$uci->set("network.qosptschmode_0.weight",$wan_weight);
				if(DEF_MODEL == "QCA_REF" && DEF_ANT == "4x4"){
					$uci->set("network.qosptschmode_6","switch_ext");
					$uci->set("network.qosptschmode_6.device","switch0");
					$uci->set("network.qosptschmode_6.name","QosPtschMode");
					$uci->set("network.qosptschmode_6.port_id","6");
					$uci->set("network.qosptschmode_6.mode",dv_post("qos_mode".$wan_no));
					$uci->set("network.qosptschmode_6.weight",$wan_weight);
				}
			}else{
				$uci->set("network.qosptschmode_0","switch_ext");
				$uci->set("network.qosptschmode_0.device","switch0");
				$uci->set("network.qosptschmode_0.name","QosPtschMode");
				$uci->set("network.qosptschmode_0.port_id","0");
				$uci->set("network.qosptschmode_0.mode",dv_post("qos_mode".$wan_no));
				$uci->set("network.qosptschmode_0.weight",$wan_weight);
				if(DEF_MODEL == "QCA_REF" && DEF_ANT == "4x4"){
					$uci->set("network.qosptschmode_6","switch_ext");
					$uci->set("network.qosptschmode_6.device","switch0");
					$uci->set("network.qosptschmode_6.name","QosPtschMode");
					$uci->set("network.qosptschmode_6.port_id","6");
					$uci->set("network.qosptschmode_6.mode",dv_post("qos_mode".$wan_no));
					$uci->set("network.qosptschmode_6.weight",$wan_weight);
				}
			}
		}else{
			if(dv_post("qos_enable".$i) == "1"){
				$uci->set("network.qosptschmode_".$i,"switch_ext");
				$uci->set("network.qosptschmode_".$i.".device","switch0");
				$uci->set("network.qosptschmode_".$i.".name","QosPtschMode");
				$uci->set("network.qosptschmode_".$i.".port_id",dv_post("qos_port_no").$i);
				$uci->set("network.qosptschmode_".$i.".mode",dv_post("qos_mode".$i));
				if($i == 5){
					$lan_we_tmp = dv_post("qos_weight".$i);
					$lan_we_tmp = explode(",",$lan_we_tmp);
					$lan_we_tmp = $lan_we_tmp[0].",".$lan_we_tmp[0].",".$lan_we_tmp[1].",".$lan_we_tmp[1].",".$lan_we_tmp[2].",".$lan_we_tmp[3];
					$uci->set("network.qosptschmode_".$i.".weight",$lan_we_tmp);
				}else{
					$uci->set("network.qosptschmode_".$i.".weight",dv_post("qos_weight".$i));
				}
			}else{
				$uci->set("network.qosptschmode_".$i,"switch_ext");
				$uci->set("network.qosptschmode_".$i.".device","switch0");
				$uci->set("network.qosptschmode_".$i.".name","QosPtschMode");
				$uci->set("network.qosptschmode_".$i.".port_id",dv_post("qos_port_no").$i);
				$uci->set("network.qosptschmode_".$i.".mode","sp");
				if($i == 5){
					$uci->set("network.qosptschmode_".$i.".weight","3,3,7,7,0,0");
				}else{
					$uci->set("network.qosptschmode_".$i.".weight","3,7,0,0,0,0");
				}
			}
			if(dv_post("qos_rate".$i) == "1"){
				$uci->set("network.rateportpolicer_".$i,"switch_ext");
				$uci->set("network.rateportpolicer_".$i.".device","switch0");
				$uci->set("network.rateportpolicer_".$i.".name","RatePortPolicer");
				$uci->set("network.rateportpolicer_".$i.".port_id",dv_post("qos_port_no".$i));
				$uci->set("network.rateportpolicer_".$i.".combine_enable","no");
				$uci->set("network.rateportpolicer_".$i.".byte_based","yes");
				$uci->set("network.rateportpolicer_".$i.".couple_flag","no");
				$uci->set("network.rateportpolicer_".$i.".color_aware","no");
				$uci->set("network.rateportpolicer_".$i.".deficit_flag","yes");
				$uci->set("network.rateportpolicer_".$i.".c_bucket_enable","yes");//no
				$qos_in_rate = dv_post("qos_in_rate".$i);
				if($qos_in_rate == ""){
					$qos_in_rate_ir  = "0";
					$qos_in_rate_bs  = "0";
				}else{
					$qos_in_rate_ir  = $qos_in_rate;
					if((int)$qos_in_rate_ir > 1048544){
						$qos_in_rate_ir = "1048544";
					}
					$qos_in_rate_bs  = $qos_in_rate;
					if((int)$qos_in_rate_bs > 524288){
						$qos_in_rate_bs = "524288";
					}
				}
				$uci->set("network.rateportpolicer_".$i.".cir",$qos_in_rate_ir);//
				$uci->set("network.rateportpolicer_".$i.".cbs",$qos_in_rate_bs);//
				$uci->set("network.rateportpolicer_".$i.".c_rate_flag","0xfe");
				$uci->set("network.rateportpolicer_".$i.".c_meter_interval","1ms");
				$uci->set("network.rateportpolicer_".$i.".e_bucket_enable","yes");//no
				$uci->set("network.rateportpolicer_".$i.".eir",$qos_in_rate_ir);//
				$uci->set("network.rateportpolicer_".$i.".ebs",$qos_in_rate_bs);//
				$uci->set("network.rateportpolicer_".$i.".e_rate_flag","0xfe");
				$uci->set("network.rateportpolicer_".$i.".e_meter_interval","1ms");

				$uci->set("network.rateportshaper_".$i,"switch_ext");
				$uci->set("network.rateportshaper_".$i.".device","switch0");
				$uci->set("network.rateportshaper_".$i.".name","RatePortShaper");
				$uci->set("network.rateportshaper_".$i.".port_id",dv_post("qos_port_no".$i));
				$uci->set("network.rateportshaper_".$i.".status","enable");//disable
				$uci->set("network.rateportshaper_".$i.".byte_based","yes");
				$qos_out_rate = dv_post("qos_out_rate".$i);
				if($qos_out_rate == ""){
					$qos_out_rate_ir = "0";
					$qos_out_rate_bs = "0";
				}else{
					$qos_out_rate_ir  = $qos_out_rate;
					if((int)$qos_out_rate_ir > 1048544){
						$qos_out_rate_ir = "1048544";
					}
					$qos_out_rate_bs  = $qos_out_rate;
					if((int)$qos_out_rate_bs > 524288){
						$qos_out_rate_bs = "524288";
					}
				}
				$uci->set("network.rateportshaper_".$i.".cir",$qos_out_rate_ir);//
				$uci->set("network.rateportshaper_".$i.".cbs",$qos_out_rate_bs);//
				$uci->set("network.rateportshaper_".$i.".eir","0");//
				$uci->set("network.rateportshaper_".$i.".ebs","0");//
			}else{
				$uci->set("network.rateportpolicer_".$i,"switch_ext");
				$uci->set("network.rateportpolicer_".$i.".device","switch0");
				$uci->set("network.rateportpolicer_".$i.".name","RatePortPolicer");
				$uci->set("network.rateportpolicer_".$i.".port_id",dv_post("qos_port_no".$i));
				$uci->set("network.rateportpolicer_".$i.".combine_enable","no");
				$uci->set("network.rateportpolicer_".$i.".byte_based","yes");
				$uci->set("network.rateportpolicer_".$i.".couple_flag","no");
				$uci->set("network.rateportpolicer_".$i.".color_aware","no");
				$uci->set("network.rateportpolicer_".$i.".deficit_flag","yes");
				$uci->set("network.rateportpolicer_".$i.".c_bucket_enable","no");//no
				$uci->set("network.rateportpolicer_".$i.".cir","0");//
				$uci->set("network.rateportpolicer_".$i.".cbs","0");//
				$uci->set("network.rateportpolicer_".$i.".c_rate_flag","0xfe");
				$uci->set("network.rateportpolicer_".$i.".c_meter_interval","1ms");
				$uci->set("network.rateportpolicer_".$i.".e_bucket_enable","no");//no
				$uci->set("network.rateportpolicer_".$i.".eir","0");//
				$uci->set("network.rateportpolicer_".$i.".ebs","0");//
				$uci->set("network.rateportpolicer_".$i.".e_rate_flag","0xfe");
				$uci->set("network.rateportpolicer_".$i.".e_meter_interval","1ms");

				$uci->set("network.rateportshaper_".$i,"switch_ext");
				$uci->set("network.rateportshaper_".$i.".device","switch0");
				$uci->set("network.rateportshaper_".$i.".name","RatePortShaper");
				$uci->set("network.rateportshaper_".$i.".port_id",dv_post("qos_port_no".$i));
				$uci->set("network.rateportshaper_".$i.".status","disable");//disable
				$uci->set("network.rateportshaper_".$i.".byte_based","yes");
				$uci->set("network.rateportshaper_".$i.".cir","0");//
				$uci->set("network.rateportshaper_".$i.".cbs","0");//
				$uci->set("network.rateportshaper_".$i.".eir","0");//
				$uci->set("network.rateportshaper_".$i.".ebs","0");//
			}
		}
		$uci->run();
	}
	

	$uci->commit();
	echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));


?>
