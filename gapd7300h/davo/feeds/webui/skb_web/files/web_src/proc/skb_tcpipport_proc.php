<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$act_ = dv_post("act");
	$wan_no = dv_post("wan_no");
	$lan_no = dv_post("lan_no");

	if($act_ == "form_save"){

//	create_post_value();
		

		$uci = new uci();
		$uci->mode("del");
		for($i=1; $i <= DEF_MAX_PORT; $i++){
			$uci->del("network.portautonegenable_".$i);
			$uci->del("network.portautoadv_".$i);
			$uci->del("network.portspeed_".$i);
			$uci->del("network.portduplex_".$i);
			$uci->del("network.portflowctrl_".$i);
			$uci->del("network.portflowctrlforcemode_".$i);
			$uci->del("network.portpoweron_".$i);
			$uci->del("network.portpoweroff_".$i);
		}
		$uci->run();
		$uci->mode("set");
		for($i=0; $i < DEF_MAX_PORT; $i++){
			if($i == 4){
				$port_no = $wan_no;
			}else{
				$port_no = $lan_no + $i;
			}
			if(dv_post("nego".$i) == "0"){
				//Manual
				$uci->set("network.portspeed_".$port_no,"switch_ext");
				$uci->set("network.portspeed_".$port_no.".device","switch0");
				$uci->set("network.portspeed_".$port_no.".name","PortSpeed");
				$uci->set("network.portspeed_".$port_no.".port_id",$port_no);
				$uci->set("network.portspeed_".$port_no.".speed",dv_post("speed".$i));
				
				
				$uci->set("network.portduplex_".$port_no,"switch_ext");
				$uci->set("network.portduplex_".$port_no.".device","switch0");
				$uci->set("network.portduplex_".$port_no.".name","PortDuplex");
				$uci->set("network.portduplex_".$port_no.".port_id",$port_no);
				if(dv_post("duplex".$i) == "0"){
					$uci->set("network.portduplex_".$port_no.".duplex","half");
				}else{
					$uci->set("network.portduplex_".$port_no.".duplex","full");
				}
			}else{
				//Auto
		//		PortAutoNegEnable
				$uci->set("network.portautonegenable_".$port_no,"switch_ext");
				$uci->set("network.portautonegenable_".$port_no.".device","switch0");
				$uci->set("network.portautonegenable_".$port_no.".name","PortAutoNegEnable");
				$uci->set("network.portautonegenable_".$port_no.".port_id",$port_no);

				$adv = "";
				$p010h = dv_post("p".$i."10h") == "" ? "0": "1";
				$p010f = dv_post("p".$i."10f") == "" ? "0": "1";
				$p0100h = dv_post("p".$i."100h") == "" ? "0": "1";
				$p0100f = dv_post("p".$i."100f") == "" ? "0": "1";
				$p01000f = dv_post("p".$i."1000f") == "" ? "0": "1";
				$p0pause = dv_post("p".$i."pause") == "" ? "0": "1";
				$p0apause = dv_post("p".$i."apause") == "" ? "0": "1";
				$adv = "0x".dechex(bindec(sprintf("%s000%s%s%s%s%s%s",$p01000f,$p0apause,$p0pause,$p0100f,$p0100h,$p010f,$p010h)));

				$uci->set("network.portautoadv_".$port_no,"switch_ext");
				$uci->set("network.portautoadv_".$port_no.".device","switch0");
				$uci->set("network.portautoadv_".$port_no.".name","PortAutoAdv");
				$uci->set("network.portautoadv_".$port_no.".port_id",$port_no);
				$uci->set("network.portautoadv_".$port_no.".auto_adv",$adv);
			}
			
			$uci->set("network.portflowctrl_".$port_no,"switch_ext");
			$uci->set("network.portflowctrl_".$port_no.".device","switch0");
			$uci->set("network.portflowctrl_".$port_no.".name","PortFlowCtrl");
			$uci->set("network.portflowctrl_".$port_no.".port_id",$port_no);
			if(dv_post("rx".$i."_pause") == "1"){
				$uci->set("network.portflowctrl_".$port_no.".flow_control_status","enable");
			}else{
				$uci->set("network.portflowctrl_".$port_no.".flow_control_status","disable");
			}
			$uci->set("network.portflowctrlforcemode_".$port_no,"switch_ext");
			$uci->set("network.portflowctrlforcemode_".$port_no.".device","switch0");
			$uci->set("network.portflowctrlforcemode_".$port_no.".name","PortFlowCtrlForceMode");
			$uci->set("network.portflowctrlforcemode_".$port_no.".port_id",$port_no);
			if(dv_post("rx".$i."_fpause") == "1"){
				$uci->set("network.portflowctrlforcemode_".$port_no.".flow_control_force_mode_status","enable");
			}else{
				$uci->set("network.portflowctrlforcemode_".$port_no.".flow_control_force_mode_status","disable");
			}

			if(dv_post("power".$i) == "0"){
				$uci->set("network.portpoweron_".$port_no,"switch_ext");
				$uci->set("network.portpoweron_".$port_no.".device","switch0");
				$uci->set("network.portpoweron_".$port_no.".name","PortPoweron");
				$uci->set("network.portpoweron_".$port_no.".port_id",$port_no);
			}else{
				$uci->set("network.portpoweroff_".$port_no,"switch_ext");
				$uci->set("network.portpoweroff_".$port_no.".device","switch0");
				$uci->set("network.portpoweroff_".$port_no.".name","PortPoweroff");
				$uci->set("network.portpoweroff_".$port_no.".port_id",$port_no);
			}
			
		}
		$uci->run();
		$uci->commit();
		echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));
	}elseif($act_ == "port_reset"){
		$syscall = new dvcmd();
		$port_no = dv_post("port_no");
		$syscall->add("ssdk_sh"," port poweroff set ".$port_no."; sleep 1 ; ssdk_sh port poweron set ".$port_no."","!");
		$syscall->run();
		$syscall->close();
		echo "1";
	}
?>