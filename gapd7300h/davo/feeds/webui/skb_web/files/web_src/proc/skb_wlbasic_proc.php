<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$act_ = dv_post("act");
	$radio_ = dv_post("radio");
	if(DEF_MODEL != "QCA_REF" && DEF_ANT == "4x4"){
		if($radio_ == "0"){
			$radio = "1";
		}else{
			$radio = "0";
		}
	}else{
//		exit;
	}
	Switch($act_){
		case "set_wifi":
			$uci = new uci();
			$wifi_enable_ = dv_post("wlan_enable");
			
			$seq_ = dv_post("seq");
			$wifi = "wifi".$radio;
			$vap = "vap".$radio.$seq_;
			$vap1 = "vap".$radio."1";
			$vap2 = "vap".$radio."2";

			$band_ = dv_post("band");
			$ssid_ = dv_post("ssid");
			$band_width_ = dv_post("band_width");
			$sideband_ = dv_post("sideband");
			$channel_ = dv_post("channel");
			$cfreq2_ = dv_post("cfreq2");
			$hidden_ssid_ = dv_post("hidden_ssid");
			$wlan_max_conn_ = dv_post("wlan_max_conn");
			$data_rate_ = dv_post("data_rate");
			$tx_limit_ = dv_post("tx_limit");
			$rx_limit_ = dv_post("rx_limit");
			$wmm_ = dv_post("wmm");

			$wds_ = dv_post("wds");
			
			$uci->mode("del");
			$uci->del("wireless.".$vap.".pureg");
			$uci->del("wireless.".$vap1.".puren");
			$uci->del("wireless.".$vap2.".pureac");
			$uci->del("wireless.vap00.cfreq2");
			$uci->del("wireless.vap01.cfreq2");
			$uci->del("wireless.vap02.cfreq2");
			$uci->del("wireless.vap03.cfreq2");
			$uci->del("wireless.vap04.cfreq2");
			$uci->del("wireless.vap05.cfreq2");
			$uci->run();

			$cfg = new dvcfg();
			$cfg->read("wireless");
			$winfo = $cfg->result("object");

			$uci->mode("set");
			if($wifi_enable_ == "1"){
				if($radio == "1"){
					$uci->set("wireless.vap04.disabled","1");
				}
				$uci->set("wireless.".$wifi.".disabled","1");
			}else{
				$uci->mode("del");
				$uci->del("wireless.".$wifi.".disabled");
				if($radio == "1"){
					if(get_json_val($winfo,"wireless.vap04.handover_rssi_thrshld") != "0"){
						$uci->del("wireless.vap04.disabled");
						$uci->set("wireless.vap10.handover_dn_ssid","1");
					}else{
						$uci->set("wireless.vap04.disabled","1");
						$uci->set("wireless.vap10.handover_dn_ssid","0");
					}
				}
				$uci->run();
				$uci->mode("set");
			}
			if($band_ != ""){
				if($band_ == "11ng"){
		//			$uci->set("wireless.".$wifi.".pureg","1");
					$uci->set("wireless.".$vap.".pureg","1");
					$uci->set("wireless.".$vap1.".pureg","1");
					$uci->set("wireless.".$vap2.".pureg","1");
				}elseif($band_ == "11n"){
		//			$uci->set("wireless.".$wifi.".puren","1");
					$uci->set("wireless.".$vap.".puren","1");
					$uci->set("wireless.".$vap1.".puren","1");
					$uci->set("wireless.".$vap2.".puren","1");
					if($radio == "1"){
						$band_ = "11ng";
					}else{
						$band_ = "11na";
					}
				}elseif($band_ == "11bgn"){
					$band_ = "11ng";
				}elseif($band_ == "11nac"){
					$band_ = "11ac";
					$uci->set("wireless.".$vap.".puren","1");
					$uci->set("wireless.".$vap1.".puren","1");
					$uci->set("wireless.".$vap2.".puren","1");
				}elseif($band_ == "11ac_only"){
					$band_ = "11ac";
					$uci->set("wireless.".$vap.".pureac","1");
					$uci->set("wireless.".$vap1.".pureac","1");
					$uci->set("wireless.".$vap2.".pureac","1");
				}
				$uci->set("wireless.".$wifi.".hwmode",$band_);
				
			}
			if($band_width_ != ""){
				if($sideband_ != ""){
					if($radio_ == "0"){
						if($band_width_ == "dv_auto"){
							$uci->set("dvmgmt.misc.skb_2g_autobw","1");
							$band_width_ = "HT40";
						}else{
							$uci->set("dvmgmt.misc.skb_2g_autobw","0");
						}
					}
					if($band_width_ == "HT40"){
						$uci->set("wireless.".$wifi.".htmode",$band_width_.$sideband_);
					}else{
						$uci->set("wireless.".$wifi.".htmode",$band_width_);
					}
				}else{
					if($radio_ == "0"){
						if($band_width_ == "dv_auto"){
							$uci->set("dvmgmt.misc.skb_2g_autobw","1");
							$band_width_ = "HT40";
						}else{
							$uci->set("dvmgmt.misc.skb_2g_autobw","0");
						}
					}
					$uci->set("wireless.".$wifi.".htmode",$band_width_);
				}
			}
			if($ssid_ != ""){
				if($radio == "1"){
					$uci->set("wireless.vap04.ssid",$ssid_);
				}
				$uci->set("wireless.".$vap.".ssid",$ssid_);
			}
			if($channel_ != ""){
				$uci->set("wireless.".$wifi.".channel",$channel_);
			}
			if($cfreq2_ != "" && $channel_ != "auto" && $radio == "0"){
				$uci->set("wireless.vap00.cfreq2",$cfreq2_);
				$uci->set("wireless.vap01.cfreq2",$cfreq2_);
				$uci->set("wireless.vap02.cfreq2",$cfreq2_);
				$uci->set("wireless.vap03.cfreq2",$cfreq2_);
				$uci->set("wireless.vap04.cfreq2",$cfreq2_);
				$uci->set("wireless.vap05.cfreq2",$cfreq2_);
			}
			if($data_rate_ != ""){
				if($data_rate_ != "auto"){
					$uci->mode("del");
					$uci->del("wireless.".$vap.".setLegacyRates");
					$uci->del("wireless.".$vap.".set11NRates");
					$uci->del("wireless.".$vap.".nss");
					$uci->del("wireless.".$vap.".vhtmcs");

					$uci->del("wireless.".$vap1.".setLegacyRates");
					$uci->del("wireless.".$vap1.".set11NRates");
					$uci->del("wireless.".$vap1.".nss");
					$uci->del("wireless.".$vap1.".vhtmcs");

					$uci->del("wireless.".$vap2.".setLegacyRates");
					$uci->del("wireless.".$vap2.".set11NRates");
					$uci->del("wireless.".$vap2.".nss");
					$uci->del("wireless.".$vap2.".vhtmcs");

					$uci->run();
					$uci->mode("set");
					if(preg_match("/^NSS(\d+)\-MCS(\d+)/",$data_rate_,$d) == true) {
						//AC
						$uci->set("wireless.".$vap.".nss",$d[1]);
						$uci->set("wireless.".$vap.".vhtmcs",$d[2]);
						$uci->set("wireless.".$vap1.".nss",$d[1]);
						$uci->set("wireless.".$vap1.".vhtmcs",$d[2]);
						$uci->set("wireless.".$vap2.".nss",$d[1]);
						$uci->set("wireless.".$vap2.".vhtmcs",$d[2]);
					}elseif(preg_match("/^MCS(\d+)/",$data_rate_,$d) == true){
						//MSC
						$base = hexdec("80");
						$base = $base + $d[1];
						$rate = (string)dechex($base);
						$rate = "0x".$rate.$rate.$rate.$rate;
						$uci->set("wireless.".$vap.".set11NRates",$rate);
						$uci->set("wireless.".$vap1.".set11NRates",$rate);
						$uci->set("wireless.".$vap2.".set11NRates",$rate);
					}elseif(preg_match("/^([\d+\.]{1,})M/",$data_rate_,$d) == true){
						//Legacy
						$uci->set("wireless.".$vap.".setLegacyRates",$data_rate_);
						$uci->set("wireless.".$vap1.".setLegacyRates",$data_rate_);
						$uci->set("wireless.".$vap2.".setLegacyRates",$data_rate_);
					}
				}else{
					$uci->mode("del");
					$uci->del("wireless.".$vap.".setLegacyRates");
					$uci->del("wireless.".$vap.".set11NRates");
					$uci->del("wireless.".$vap.".nss");
					$uci->del("wireless.".$vap.".vhtmcs");

					$uci->del("wireless.".$vap1.".setLegacyRates");
					$uci->del("wireless.".$vap1.".set11NRates");
					$uci->del("wireless.".$vap1.".nss");
					$uci->del("wireless.".$vap1.".vhtmcs");

					$uci->del("wireless.".$vap2.".setLegacyRates");
					$uci->del("wireless.".$vap2.".set11NRates");
					$uci->del("wireless.".$vap2.".nss");
					$uci->del("wireless.".$vap2.".vhtmcs");
					$uci->run();
					$uci->mode("set");
				}
			}
			if($hidden_ssid_ == "1"){
				$uci->set("wireless.".$vap.".hidden",$hidden_ssid_);
			}else{
				$uci->mode("del");
				$uci->del("wireless.".$vap.".hidden");
				$uci->run();
				$uci->mode("set");
			}
			if($wlan_max_conn_ != ""){
				$uci->set("wireless.".$vap.".maxsta",$wlan_max_conn_);
			}
			if($tx_limit_ != ""){
				$uci->set("wireless.".$vap.".tx_limit",$tx_limit_);
			}
			if($rx_limit_ != ""){
				$uci->set("wireless.".$vap.".rx_limit",$rx_limit_);
			}
			if($wmm_ != ""){
				$uci->set("wireless.".$vap.".wmm",$wmm_);
			}else{
				$uci->set("wireless.".$vap.".wmm","1");
			}
			if($wds_ != ""){
				$uci->set("wireless.".$vap.".wds",$wds_);
			}
			$uci->run();
			$uci->commit();
			$uci->close();
			echo(rtn_reboot_page(dv_post("wlan-url"),"network_restart"));
			break;
		case "run_ch_reset":
			$filename = "/tmp/state/wireless";
			$myfile = @fopen($filename, "r");
			$wireless = @fread($myfile,filesize($filename));
			fclose($myfile);
			$dvshow = new dvshow();
			$dvshow->read($wireless);
			if($radio == "1"){
				$dvshow->result_remove("wireless.vap00");
				$dvshow->result_remove("wireless.vap01");
				$dvshow->result_remove("wireless.vap02");
				$dvshow->result_remove("wireless.vap03");
				$dvshow->result_remove("wireless.vap04");
				$dvshow->result_remove("wireless.vap05");
			}else{
				$dvshow->result_remove("wireless.vap10");
				$dvshow->result_remove("wireless.vap11");
				$dvshow->result_remove("wireless.vap12");
				$dvshow->result_remove("wireless.vap13");
				$dvshow->result_remove("wireless.vap14");
			}
//			set_head_json();
			$vap = $dvshow->result("array");
			
			$vap_key = array_keys($vap["wireless"]);
			$reset_vap = str_replace("vap","ath",$vap_key[count($vap_key)-1]);
			if($reset_vap == "ath00" || $reset_vap == "ath10"){
				$reset_vap = substr($reset_vap,0,-1);
			}
			$cmd = new dvcmd();
			$cmd->add("iwconfig",$reset_vap." channel 0");
			$cmd->run();
			$cmd->close();
			echo("1");
			break;
	}
	
?>
