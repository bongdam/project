<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$act_ = dv_post("act");
	$wlan_id = dv_post("radio");
	$radio_ = dv_post("radio");
	if(DEF_MODEL != "QCA_REF" && DEF_ANT == "4x4"){
		if($radio_ == "0"){
			$radio = "1";
		}else{
			$radio = "0";
		}
	}else{
		exit;
	}

	function mast_rate_val($rate_){
		Switch($rate_){
			case "1M":
				return 1000;
				break;
			case "2M":
				return 2000;
				break;
			case "5.5M":
				return 5500;
				break;
			case "11M":
				return 11000;
				break;
			case "6M":
				return 6000;
				break;
			case "9M":
				return 9000;
				break;
			case "12M":
				return 12000;
				break;
			case "18M":
				return 18000;
				break;
			case "24M":
				return 24000;
				break;
			case "36M":
				return 36000;
				break;
			case "48M":
				return 48000;
				break;
			case "54M":
				return 54000;
				break;
			case "MCS0":
			case "NSS1-MCS0":
				return 6500;
				break;
			case "MCS1":
			case "NSS1-MCS1":
				return 13000;
				break;
			case "MCS2":
			case "NSS1-MCS2":
				return 19500;
				break;
			case "MCS3":
			case "NSS1-MCS3":
				return 26000;
				break;
			case "MCS4":
			case "NSS1-MCS4":
				return 39000;
				break;
			case "MCS5":
			case "NSS1-MCS5":
				return 52000;
				break;
			case "MCS6":
			case "NSS1-MCS6":
				return 58500;
				break;
			case "MCS7":
			case "NSS1-MCS7":
				return 65000;
				break;
			case "NSS1-MCS8":
				return 78000;
				break;
			case "MCS8":
			case "NSS2-MCS0":
				return 13000;
				break;
			case "MCS9":
			case "NSS2-MCS1":
				return 26000;
				break;
			case "MCS10":
			case "NSS2-MCS2":
				return 39000;
				break;
			case "MCS11":
			case "NSS2-MCS3":
				return 52000;
				break;
			case "MCS12":
			case "NSS2-MCS4":
				return 78000;
				break;
			case "MCS13":
			case "NSS2-MCS5":
				return 104000;
				break;
			case "MCS14":
			case "NSS2-MCS6":
				return 117000;
				break;
			case "MCS15":
			case "NSS2-MCS7":
				return 130000;
				break;
			case "NSS2-MCS8":
				return 156000;
				break;
			
			case "MCS16":
			case "NSS3-MCS0":
				return 19500;
				break;
			case "MCS17":
			case "NSS3-MCS1":
				return 39000;
				break;
			case "MCS18":
			case "NSS3-MCS2":
				return 58500;
				break;
			case "MCS19":
			case "NSS3-MCS3":
				return 78000;
				break;
			case "MCS20":
			case "NSS3-MCS4":
				return 117000;
				break;
			case "MCS21":
			case "NSS3-MCS5":
				return 156000;
				break;
			case "MCS22":
			case "NSS3-MCS6":
				return 175500;
				break;
			case "MCS23":
			case "NSS3-MCS7":
				return 195000;
				break;
			case "NSS3-MCS8":
				return 234000;
				break;
			case "NSS3-MCS9":
				return 260000;
				break;
			case "MCS24":
			case "NSS4-MCS0":
				return 26000;
				break;
			case "MCS25":
			case "NSS4-MCS1":
				return 52000;
				break;
			case "MCS26":
			case "NSS4-MCS2":
				return 78000;
				break;
			case "MCS27":
			case "NSS4-MCS3":
				return 104000;
				break;
			case "MCS28":
			case "NSS4-MCS4":
				return 156000;
				break;
			case "MCS29":
			case "NSS4-MCS5":
				return 208000;
				break;
			case "MCS30":
			case "NSS4-MCS6":
				return 234000;
				break;
			case "MCS31":
			case "NSS4-MCS7":
				return 260000;
				break;
			case "NSS4-MCS8":
				return 312000;
				break;
			
		}
	}
	Switch($act_){
		case "get_wl_config":
			$cfg = new dvcfg();
			if($wlan_id == "0"){
				$cfg->read("wireless","vap1");
				$cfg->read("wireless","wifi1");
				$cfg->result_remove("wireless.vap10.key");
				$cfg->result_remove("wireless.vap11.key");
				$cfg->result_remove("wireless.vap12.key");
				$cfg->result_remove("wireless.vap13.key");
				$cfg->result_remove("wireless.vap14.key");

				$wifi = $cfg->result("json_string");
			}else{
				$cfg->read("wireless","vap0");
				$cfg->read("wireless","wifi0");
				$cfg->result_remove("wireless.vap00.key");
				$cfg->result_remove("wireless.vap01.key");
				$cfg->result_remove("wireless.vap02.key");
				$cfg->result_remove("wireless.vap03.key");
				$cfg->result_remove("wireless.vap04.key");
				$cfg->result_remove("wireless.vap05.key");
				$wifi = $cfg->result("json_string");
			}
			set_head_json();
			echo($wifi);
			$cfg->close();
			break;
		case "set_wl_config":
			$wifi = "wifi".$radio;
			$vap0 = "vap".$radio."0";
			$vap1 = "vap".$radio."1";
			$vap2 = "vap".$radio."2";
			$vap3 = "vap".$radio."3";
			$vap4 = "vap".$radio."4";
			$frag_ = dv_post("frag");
			$rts_ = dv_post("rts");
			$beacon_ = dv_post("beacon");
			$inact_ = dv_post("inact");
			$shpreamble_ = dv_post("shpreamble");
			$iapp_enable_ = dv_post("iapp_enable");
			$protmode_ = dv_post("protmode");
			$ampdu_ = dv_post("ampdu");
			$shortgi_ = dv_post("shortgi");
			$isolate_ = dv_post("isolate");
			$tx_stbc_ = dv_post("tx_stbc");
			$ldpc_ = dv_post("ldpc");
			$disablecoext_ = dv_post("disablecoext");
			$vhtsubfer_ = dv_post("vhtsubfer");
			$vhtmubfer_ = dv_post("vhtmubfer");
			$dfs_ = dv_post("dfs");
			$mcastenhance_ = dv_post("mcastenhance");
			$mcast_rate_ = dv_post("mcast_rate");
			if($mcast_rate_ != ""){
				$mcast_rate_ = mast_rate_val($mcast_rate_);
			}
			$min_rssi0_ = dv_post("min_rssi0");
			$min_rssi1_ = dv_post("min_rssi1");
			$min_rssi2_ = dv_post("min_rssi2");
			$txpower_ = dv_post("txpower");

			$handover_rssi_thrshld_ = dv_post("handover_rssi_thrshld");
			$handover_allow_rssi_ = dv_post("handover_allow_rssi");
			$handover_check_intv_sec_ = dv_post("handover_check_intv_sec");
			$handover_pps_trshld_ = dv_post("handover_pps_trshld");

			$uci = new uci();
			$uci->mode("set");
			if($frag_ != ""){
				$uci->set("wireless.".$vap0.".frag",$frag_);
				$uci->set("wireless.".$vap1.".frag",$frag_);
				$uci->set("wireless.".$vap2.".frag",$frag_);
				$uci->set("wireless.".$vap3.".frag",$frag_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".frag",$frag_);
				}
			}
			if($rts_ != ""){
				$uci->set("wireless.".$vap0.".rts",$rts_);
				$uci->set("wireless.".$vap1.".rts",$rts_);
				$uci->set("wireless.".$vap2.".rts",$rts_);
				$uci->set("wireless.".$vap3.".rts",$rts_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".rts",$rts_);
				}
			}
			if($beacon_ != ""){
				$uci->set("wireless.".$vap0.".intval",$beacon_);
				$uci->set("wireless.".$vap1.".intval",$beacon_);
				$uci->set("wireless.".$vap2.".intval",$beacon_);
				$uci->set("wireless.".$vap3.".intval",$beacon_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".intval",$beacon_);
				}
			}
			if($inact_ != ""){
				$uci->set("wireless.".$vap0.".inact",$inact_);
				$uci->set("wireless.".$vap1.".inact",$inact_);
				$uci->set("wireless.".$vap2.".inact",$inact_);
				$uci->set("wireless.".$vap3.".inact",$inact_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".inact",$inact_);
				}
			}
			if($shpreamble_ != ""){
				$uci->set("wireless.".$vap0.".shpreamble",$shpreamble_);
				$uci->set("wireless.".$vap1.".shpreamble",$shpreamble_);
				$uci->set("wireless.".$vap2.".shpreamble",$shpreamble_);
				$uci->set("wireless.".$vap3.".shpreamble",$shpreamble_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".shpreamble",$shpreamble_);
				}
			}
			if($iapp_enable_ != ""){
				$uci->set("wireless.".$vap0.".iapp_enable",$iapp_enable_);
				$uci->set("wireless.".$vap1.".iapp_enable",$iapp_enable_);
				$uci->set("wireless.".$vap2.".iapp_enable",$iapp_enable_);
				$uci->set("wireless.".$vap3.".iapp_enable",$iapp_enable_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".iapp_enable",$iapp_enable_);
				}
			}
			if($protmode_ != ""){
				$uci->set("wireless.".$vap0.".protmode",$protmode_);
				$uci->set("wireless.".$vap1.".protmode",$protmode_);
				$uci->set("wireless.".$vap2.".protmode",$protmode_);
				$uci->set("wireless.".$vap3.".protmode",$protmode_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".protmode",$protmode_);
				}
			}
			if($ampdu_ != ""){
				$uci->set("wireless.".$vap0.".ampdu",$ampdu_);
			}
			if($isolate_ != ""){
				$uci->set("wireless.".$vap0.".isolate",$isolate_);
//				$uci->set("wireless.".$vap1.".isolate",$isolate_);
//				$uci->set("wireless.".$vap2.".isolate",$isolate_);
//				$uci->set("wireless.".$vap3.".isolate",$isolate_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".isolate",$isolate_);
				}
			}
			if($tx_stbc_ != ""){
				$uci->set("wireless.".$vap0.".tx_stbc",$tx_stbc_);
				$uci->set("wireless.".$vap0.".rx_stbc",$tx_stbc_);
				$uci->set("wireless.".$vap1.".tx_stbc",$tx_stbc_);
				$uci->set("wireless.".$vap1.".rx_stbc",$tx_stbc_);
				$uci->set("wireless.".$vap2.".tx_stbc",$tx_stbc_);
				$uci->set("wireless.".$vap2.".rx_stbc",$tx_stbc_);
				$uci->set("wireless.".$vap3.".tx_stbc",$tx_stbc_);
				$uci->set("wireless.".$vap3.".rx_stbc",$tx_stbc_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".tx_stbc",$tx_stbc_);
					$uci->set("wireless.".$vap4.".rx_stbc",$tx_stbc_);
				}
			}
			if($ldpc_ != ""){
				$uci->set("wireless.".$vap0.".ldpc",$ldpc_);
				$uci->set("wireless.".$vap1.".ldpc",$ldpc_);
				$uci->set("wireless.".$vap2.".ldpc",$ldpc_);
				$uci->set("wireless.".$vap3.".ldpc",$ldpc_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".ldpc",$ldpc_);
				}
			}
			if($disablecoext_ != ""){
				$uci->set("wireless.".$vap0.".disablecoext",$disablecoext_);
				$uci->set("wireless.".$vap1.".disablecoext",$disablecoext_);
				$uci->set("wireless.".$vap2.".disablecoext",$disablecoext_);
				$uci->set("wireless.".$vap3.".disablecoext",$disablecoext_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".disablecoext",$disablecoext_);
				}
			}
			if($vhtsubfer_ != ""){
				$uci->set("wireless.".$vap0.".vhtsubfer",$vhtsubfer_);
				$uci->set("wireless.".$vap1.".vhtsubfer",$vhtsubfer_);
				$uci->set("wireless.".$vap2.".vhtsubfer",$vhtsubfer_);
				$uci->set("wireless.".$vap3.".vhtsubfer",$vhtsubfer_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".vhtsubfer",$vhtsubfer_);
				}
			}
			if($vhtmubfer_ != ""){
				$uci->set("wireless.".$vap0.".vhtmubfer",$vhtmubfer_);
				$uci->set("wireless.".$vap1.".vhtmubfer",$vhtmubfer_);
				$uci->set("wireless.".$vap2.".vhtmubfer",$vhtmubfer_);
				$uci->set("wireless.".$vap3.".vhtmubfer",$vhtmubfer_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".vhtmubfer",$vhtmubfer_);
				}
			}
			if($radio == "0"){
				if($dfs_ == "enable"){
					$uci->set("wireless.wifi0.dfs","enable");
				}else{
					$uci->set("wireless.wifi0.dfs","disable");
				}
			}
			if($mcastenhance_ != ""){
				$uci->set("wireless.".$vap0.".mcastenhance",$mcastenhance_);
				$uci->set("wireless.".$vap1.".mcastenhance",$mcastenhance_);
				$uci->set("wireless.".$vap2.".mcastenhance",$mcastenhance_);
				$uci->set("wireless.".$vap3.".mcastenhance",$mcastenhance_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".mcastenhance",$mcastenhance_);
				}
			}
			if($mcast_rate_ != ""){
				$uci->set("wireless.".$vap0.".mcast_rate",$mcast_rate_);
				$uci->set("wireless.".$vap1.".mcast_rate",$mcast_rate_);
				$uci->set("wireless.".$vap2.".mcast_rate",$mcast_rate_);
				$uci->set("wireless.".$vap3.".mcast_rate",$mcast_rate_);
				if($radio == "0"){
					$uci->set("wireless.".$vap4.".mcast_rate",$mcast_rate_);
				}
			}
			if($min_rssi0_ != ""){
				if($min_rssi0_ != "0"){
					$min_rssi0_ = "-".$min_rssi0_;
				}
				$uci->set("wireless.".$vap0.".min_rssi",$min_rssi0_);
			}
			if($min_rssi1_ != ""){
				if($min_rssi1_ != "0"){
					$min_rssi1_ = "-".$min_rssi1_;
				}
				$uci->set("wireless.".$vap1.".min_rssi",$min_rssi1_);
			}
			if($min_rssi2_ != ""){
				if($min_rssi2_ != "0"){
					$min_rssi2_ = "-".$min_rssi2_;
				}
				$uci->set("wireless.".$vap2.".min_rssi",$min_rssi2_);
			}
			if($txpower_ != ""){
				$uci->set("wireless.wifi".$radio.".txpower",$txpower_);
			}
			if($handover_rssi_thrshld_ != ""){
				if($handover_rssi_thrshld_ == "0"){
					$uci->set("wireless.vap04.disabled","1");
					$uci->set("wireless.vap04.handover_rssi_thrshld",$handover_rssi_thrshld_);
					$uci->set("wireless.vap10.handover_dn_ssid","0");

				}else{
					$uci->set("wireless.vap04.disabled","0");
					$uci->set("wireless.vap04.handover_rssi_thrshld",$handover_rssi_thrshld_);
					$uci->set("wireless.vap10.handover_dn_ssid","1");
				}
			}
			if($handover_allow_rssi_ != ""){
				$uci->set("wireless.vap04.handover_allow_rssi",$handover_allow_rssi_);
			}
			if($handover_check_intv_sec_ != ""){
				$uci->set("wireless.vap04.handover_check_intv_sec",$handover_check_intv_sec_);
			}
			if($handover_pps_trshld_ != ""){
				$uci->set("wireless.vap04.handover_pps_trshld",$handover_pps_trshld_);
			}
			$uci->run();
			$uci->result();
			$uci->commit();
			$uci->close();
			echo("1");
			break;
	}
?>