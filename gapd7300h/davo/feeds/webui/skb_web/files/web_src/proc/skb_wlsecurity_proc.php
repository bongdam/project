<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	function cipher_clean($val_){
		$val = "";
		$val = str_replace("+tkip+aes","",$val_);
		$val = str_replace("+tkip","",$val);
		$val = str_replace("+aes","",$val);
		$val = str_replace("+shared","",$val);
		$val = str_replace("+open","",$val);
		$val = str_replace("+mixed","",$val);
//		$val = str_replace("psk","wpa",$val);
		return $val;
	}
	$radio_ = dv_post("frm_radio");
	$seq_ = dv_post("frm_seq");
	$auth_ = dv_post("frm_auth");
	$auth_type_ = dv_post("frm_auth_type");
	$key_type_ = dv_post("frm_key_type");
	$key_ = dv_post("frm_key");

	$radius_ip_ = dv_post("frm_radius_ip");
	$radius_port_ = dv_post("frm_radius_port");
	$radius_passwd_ = dv_post("frm_radius_passwd");
	$radius_retry_ = dv_post("frm_radius_retry");
	$radius_intv_ = dv_post("frm_radius_intv");

	$acct_use_ = dv_post("frm_acct_use");
	$acct_ip_ = dv_post("frm_acct_ip");
	$acct_port_ = dv_post("frm_acct_port");
	$acct_passwd_ = dv_post("frm_acct_passwd");
	$acct_retry_use_ =  dv_post("frm_acct_retry_use");
	$acct_delay_time_ = dv_post("frm_acct_delay_time");

	$auth_type1_ = dv_post("frm_auth_type1");
	$rsn_pairwise_ = dv_post("frm_rsn_pairwise");
	$wep_radius_ = dv_post("frm_wep_radius");
	if($wep_radius_ == false){
		$wep_radius_ = "0";
	}
	$wep_len_ = dv_post("frm_wep_len");
	$wep_type_ = dv_post("frm_wep_type");
	$wep_key_ = dv_post("frm_wep_key");
	$key1_ = dv_post("frm_key1");
	$key2_ = dv_post("frm_key2");
	$key3_ = dv_post("frm_key3");
	$key4_ = dv_post("frm_key4");

	$mac_auth_ = dv_post("frm_mac_auth");

	if($radio_ == "1" && $seq_ == "0"){
		$handover = true;
	}else{
		$handover = false;
	}

	$uci = new uci();
	$uci->mode("get");
	$uci->get("wireless.vap".$radio_.$seq_."._orig_key");
	$uci->get("wireless.vap".$radio_.$seq_.".key");
	$uci->get("wireless.vap".$radio_.$seq_.".auth_secret");
	$uci->get("wireless.vap".$radio_.$seq_.".acct_secret");

	$uci->get("wireless.vap".$radio_.$seq_.".key1");
	$uci->get("wireless.vap".$radio_.$seq_.".key2");
	$uci->get("wireless.vap".$radio_.$seq_.".key3");
	$uci->get("wireless.vap".$radio_.$seq_.".key4");

	$uci->get("wireless.vap".$radio_.$seq_.".encryption");


	$uci->run();
	$tmp_key = json_decode($uci->result(),true);
	$pre_orig_key = get_array_val($tmp_key,"wireless.vap".$radio_.$seq_."._orig_key");
	$pre_key = get_array_val($tmp_key,"wireless.vap".$radio_.$seq_.".key");
	$pre_radius_passwd = get_array_val($tmp_key,"wireless.vap".$radio_.$seq_.".auth_secret");
	$pre_acct_passwd = get_array_val($tmp_key,"wireless.vap".$radio_.$seq_.".acct_secret");
	$pre_key1 = get_array_val($tmp_key,"wireless.vap".$radio_.$seq_.".key1");
	$pre_key2 = get_array_val($tmp_key,"wireless.vap".$radio_.$seq_.".key2");
	$pre_key3 = get_array_val($tmp_key,"wireless.vap".$radio_.$seq_.".key3");
	$pre_key4 = get_array_val($tmp_key,"wireless.vap".$radio_.$seq_.".key4");
	$pre_macaddr_acl = get_array_val($tmp_key,"wireless.vap".$radio_.$seq_.".macaddr_acl");

	$pre_enc = cipher_clean(get_array_val($tmp_key,"wireless.vap".$radio_.$seq_.".encryption"));
	$uci->mode("del");
	//Radius
	$uci->del("wireless.vap".$radio_.$seq_.".auth_server");
	$uci->del("wireless.vap".$radio_.$seq_.".auth_port");
	$uci->del("wireless.vap".$radio_.$seq_.".auth_secret");
	$uci->del("wireless.vap".$radio_.$seq_.".radius_server_retries");
	$uci->del("wireless.vap".$radio_.$seq_.".radius_max_retry_wait");
	
	$uci->del("wireless.vap".$radio_.$seq_.".acct_server_use");
	$uci->del("wireless.vap".$radio_.$seq_.".acct_server");
	$uci->del("wireless.vap".$radio_.$seq_.".acct_port");
	$uci->del("wireless.vap".$radio_.$seq_.".acct_secret");
	$uci->del("wireless.vap".$radio_.$seq_.".acct_interim_use");
	$uci->del("wireless.vap".$radio_.$seq_.".radius_acct_interim_interval");
	//WEP
	$uci->del("wireless.vap".$radio_.$seq_.".wep_key_len");
	$uci->del("wireless.vap".$radio_.$seq_.".wep_key");
	$uci->del("wireless.vap".$radio_.$seq_.".wep_radius");
//	$uci->del("wireless.vap".$radio_.$seq_.".key1");
//	$uci->del("wireless.vap".$radio_.$seq_.".key2");
//	$uci->del("wireless.vap".$radio_.$seq_.".key3");
//	$uci->del("wireless.vap".$radio_.$seq_.".key4");
	//PSK
	$uci->del("wireless.vap".$radio_.$seq_.".key_type");
	$uci->del("wireless.vap".$radio_.$seq_.".key");
	$uci->del("wireless.vap".$radio_.$seq_.".rsn_pairwise");
	//NO
	if($pre_macaddr_acl != "0" && $pre_macaddr_acl != "1"){
		$uci->del("wireless.vap".$radio_.$seq_.".macaddr_acl");
	}
	if($handover == true){
		$uci->del("wireless.vap04.auth_server");
		$uci->del("wireless.vap04.auth_port");
		$uci->del("wireless.vap04.auth_secret");
		$uci->del("wireless.vap04.radius_server_retries");
		$uci->del("wireless.vap04.radius_max_retry_wait");
		
		$uci->del("wireless.vap04.acct_server_use");
		$uci->del("wireless.vap04.acct_server");
		$uci->del("wireless.vap04.acct_port");
		$uci->del("wireless.vap04.acct_secret");
		$uci->del("wireless.vap04.acct_interim_use");
		$uci->del("wireless.vap04.radius_acct_interim_interval");
		//WEP
		$uci->del("wireless.vap04.wep_key_len");
		$uci->del("wireless.vap04.wep_key");
		//PSK
		$uci->del("wireless.vap04.key_type");
		$uci->del("wireless.vap04.key");
		if($pre_macaddr_acl != "0" && $pre_macaddr_acl != "1"){
			$uci->del("wireless.vap04.macaddr_acl");
		}
	}
	$uci->run();
	$uci->mode("set");
	if($auth_type_ == "wpa"){
		$uci->set("wireless.vap".$radio_.$seq_.".encryption",$auth_);
		$uci->set("wireless.vap".$radio_.$seq_."._orig_encryption",$auth_);
		if($rsn_pairwise_ != ""){
			$uci->set("wireless.vap".$radio_.$seq_.".rsn_pairwise",$rsn_pairwise_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_rsn_pairwise",$rsn_pairwise_);
		}
		$uci->set("wireless.vap".$radio_.$seq_.".key_type",$key_type_);
		$uci->set("wireless.vap".$radio_.$seq_."._orig_key_type",$key_type_);
		$uci->set("wireless.vap".$radio_.$seq_.".auth_server",$radius_ip_);
		$uci->set("wireless.vap".$radio_.$seq_."._orig_auth_server",$radius_ip_);
		$uci->set("wireless.vap".$radio_.$seq_.".auth_port",$radius_port_);
		$uci->set("wireless.vap".$radio_.$seq_."._orig_auth_port",$radius_port_);
		if($radius_passwd_ != "********" && $radius_passwd_ != ""){
			$uci->set("wireless.vap".$radio_.$seq_.".auth_secret",$radius_passwd_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_auth_secret",$radius_passwd_);
		}else{
			$uci->set("wireless.vap".$radio_.$seq_.".auth_secret",$pre_radius_passwd);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_auth_secret",$pre_radius_passwd);
		}
		$uci->set("wireless.vap".$radio_.$seq_.".radius_server_retries",$radius_retry_);
		$uci->set("wireless.vap".$radio_.$seq_."._orig_radius_server_retries",$radius_retry_);
		$uci->set("wireless.vap".$radio_.$seq_.".radius_max_retry_wait",$radius_intv_);
		$uci->set("wireless.vap".$radio_.$seq_."._orig_radius_max_retry_wait",$radius_intv_);
		if($acct_use_ == "1"){
			$uci->set("wireless.vap".$radio_.$seq_.".acct_server_use","1");
			$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_server_use","1");
			$uci->set("wireless.vap".$radio_.$seq_.".acct_server",$acct_ip_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_server",$acct_ip_);
			$uci->set("wireless.vap".$radio_.$seq_.".acct_port",$acct_port_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_port",$acct_port_);
			if($acct_passwd_ != "********" && $acct_passwd_ != ""){
				$uci->set("wireless.vap".$radio_.$seq_.".acct_secret",$acct_passwd_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_secret",$acct_passwd_);
			}else{
				$uci->set("wireless.vap".$radio_.$seq_.".acct_secret",$pre_acct_passwd);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_secret",$pre_acct_passwd);
			}
			if($acct_retry_use_ == "1"){
				$uci->set("wireless.vap".$radio_.$seq_.".acct_interim_use",$acct_retry_use_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_interim_use",$acct_retry_use_);
				$uci->set("wireless.vap".$radio_.$seq_.".radius_acct_interim_interval",$acct_delay_time_ );
				$uci->set("wireless.vap".$radio_.$seq_."._orig_radius_acct_interim_interval",$acct_delay_time_ );
			}
		}
		if($handover == true){
			$uci->set("wireless.vap04.encryption",$auth_);
			$uci->set("wireless.vap04._orig_encryption",$auth_);
			if($rsn_pairwise_ != ""){
				$uci->set("wireless.vap04.rsn_pairwise",$rsn_pairwise_);
				$uci->set("wireless.vap04._orig_rsn_pairwise",$rsn_pairwise_);
			}
			$uci->set("wireless.vap04.key_type",$key_type_);
			$uci->set("wireless.vap04._orig_key_type",$key_type_);
			$uci->set("wireless.vap04.auth_server",$radius_ip_);
			$uci->set("wireless.vap04._orig_auth_server",$radius_ip_);
			$uci->set("wireless.vap04.auth_port",$radius_port_);
			$uci->set("wireless.vap04._orig_auth_port",$radius_port_);
			if($radius_passwd_ != "********" && $radius_passwd_ != ""){
				$uci->set("wireless.vap04.auth_secret",$radius_passwd_);
				$uci->set("wireless.vap04._orig_auth_secret",$radius_passwd_);
			}else{
				$uci->set("wireless.vap04.auth_secret",$pre_radius_passwd);
				$uci->set("wireless.vap04._orig_auth_secret",$pre_radius_passwd);
			}
			$uci->set("wireless.vap04.radius_server_retries",$radius_retry_);
			$uci->set("wireless.vap04._orig_radius_server_retries",$radius_retry_);
			$uci->set("wireless.vap04.radius_max_retry_wait",$radius_intv_);
			$uci->set("wireless.vap04._orig_radius_max_retry_wait",$radius_intv_);
			if($acct_use_ == "1"){
				$uci->set("wireless.vap04.acct_server_use","1");
				$uci->set("wireless.vap04._orig_acct_server_use","1");
				$uci->set("wireless.vap04.acct_server",$acct_ip_);
				$uci->set("wireless.vap04._orig_acct_server",$acct_ip_);
				$uci->set("wireless.vap04.acct_port",$acct_port_);
				$uci->set("wireless.vap04._orig_acct_port",$acct_port_);
				if($acct_passwd_ != "********" && $acct_passwd_ != ""){
					$uci->set("wireless.vap04.acct_secret",$acct_passwd_);
					$uci->set("wireless.vap04._orig_acct_secret",$acct_passwd_);
				}else{
					$uci->set("wireless.vap04.acct_secret",$pre_acct_passwd);
					$uci->set("wireless.vap04._orig_acct_secret",$pre_acct_passwd);
				}
				if($acct_retry_use_ == "1"){
					$uci->set("wireless.vap04.acct_interim_use",$acct_retry_use_);
					$uci->set("wireless.vap04._orig_acct_interim_use",$acct_retry_use_);
					$uci->set("wireless.vap04.radius_acct_interim_interval",$acct_delay_time_ );
					$uci->set("wireless.vap04._orig_radius_acct_interim_interval",$acct_delay_time_ );
				}
			}
		}
	}elseif($auth_type_ == "psk"){
		$uci->set("wireless.vap".$radio_.$seq_.".encryption",$auth_);
		$uci->set("wireless.vap".$radio_.$seq_."._orig_encryption",$auth_);
		$uci->set("wireless.vap".$radio_.$seq_.".key_type",$key_type_);
		$uci->set("wireless.vap".$radio_.$seq_."._orig_key_type",$key_type_);
		if($rsn_pairwise_ != ""){
			$uci->set("wireless.vap".$radio_.$seq_.".rsn_pairwise",$rsn_pairwise_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_rsn_pairwise",$rsn_pairwise_);
		}
		if($key_ != "********" && $key_ != ""){
			$uci->set("wireless.vap".$radio_.$seq_.".key",$key_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_key",$key_);
		}else{
			if($pre_enc != $auth_type_){
				$pre_key = $pre_orig_key;
			}
			$uci->set("wireless.vap".$radio_.$seq_.".key",$pre_key);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_key",$pre_key);
		}
		if($handover == true){
			$uci->set("wireless.vap04.encryption",$auth_);
			$uci->set("wireless.vap04._orig_encryption",$auth_);
			$uci->set("wireless.vap04.key_type",$key_type_);
			$uci->set("wireless.vap04._orig_key_type",$key_type_);
			if($rsn_pairwise_ != ""){
				$uci->set("wireless.vap04.rsn_pairwise",$rsn_pairwise_);
				$uci->set("wireless.vap04._orig_rsn_pairwise",$rsn_pairwise_);
			}
			if($key_ != "********" && $key_ != ""){
				$uci->set("wireless.vap04.key",$key_);
				$uci->set("wireless.vap04._orig_key",$key_);
			}else{
				if($pre_enc != $auth_type_){
					$pre_key = $pre_orig_key;
				}
				$uci->set("wireless.vap04.key",$pre_key);
				$uci->set("wireless.vap04._orig_key",$pre_key);
			}
		}
	}elseif($auth_type_ == "wep"){
		if($wep_radius_ == "1"){
			$uci->set("wireless.vap".$radio_.$seq_.".encryption","8021x");
			$uci->set("wireless.vap".$radio_.$seq_.".orig_encryption","8021x");
		}else{
			$uci->set("wireless.vap".$radio_.$seq_.".encryption",$auth_type1_);
			$uci->set("wireless.vap".$radio_.$seq_.".orig_encryption",$auth_type1_);
		}
		$uci->set("wireless.vap".$radio_.$seq_.".wep_key_len",$wep_len_);
		$uci->set("wireless.vap".$radio_.$seq_."._orig_wep_key_len",$wep_len_);
		$uci->set("wireless.vap".$radio_.$seq_.".wep_radius",$wep_radius_);
		$uci->set("wireless.vap".$radio_.$seq_."._orig_wep_radius",$wep_radius_);
		if( $wep_radius_ != "1"){
			$uci->set("wireless.vap".$radio_.$seq_.".wep_key_type",$wep_type_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_wep_key_type",$wep_type_);
			$uci->set("wireless.vap".$radio_.$seq_.".key",$wep_key_);
			$uci->set("wireless.vap".$radio_.$seq_.".wep_key",$wep_key_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_wep_key",$wep_key_);
			$wek_prefix = "";
			if($wep_len_ == "64" && $wep_type_ == "ascii"){
				$prefix = "*****";
				$wek_prefix = "s:";
			}elseif($wep_len_ == "64" && $wep_type_ == "hex"){
				$prefix = "**********";
				$wek_prefix = "";
			}elseif($wep_len_ == "128" && $wep_type_ == "ascii"){
				$prefix = "*************";
				$wek_prefix = "s:";
			}elseif($wep_len_ == "128" && $wep_type_ == "hex"){
				$prefix = "**************************";
				$wek_prefix = "";
			}

			if($key1_ != $prefix && $key1_ != ""){
				$uci->set("wireless.vap".$radio_.$seq_.".key1",$wek_prefix.$key1_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_key1",$wek_prefix.$key1_);
			}else{
				$uci->set("wireless.vap".$radio_.$seq_.".key1",$pre_key1);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_key1",$pre_key1);
			}
			if($key2_ != $prefix && $key2_ != ""){
				$uci->set("wireless.vap".$radio_.$seq_.".key2",$wek_prefix.$key2_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_key2",$wek_prefix.$key2_);
			}else{
				$uci->set("wireless.vap".$radio_.$seq_.".key2",$pre_key2);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_key2",$pre_key2);
			}
			if($key3_ != $prefix && $key3_ != ""){
				$uci->set("wireless.vap".$radio_.$seq_.".key3",$wek_prefix.$key3_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_key3",$wek_prefix.$key3_);
			}else{
				$uci->set("wireless.vap".$radio_.$seq_.".key3",$pre_key3);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_key3",$pre_key3);
			}
			if($key4_ != $prefix && $key4_ != ""){
				$uci->set("wireless.vap".$radio_.$seq_.".key4",$wek_prefix.$key4_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_key4",$wek_prefix.$key4_);
			}else{
				$uci->set("wireless.vap".$radio_.$seq_.".key4",$pre_key4);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_key4",$pre_key4);
			}
			if($handover == true){
				$uci->set("wireless.vap04.encryption",$auth_type1_);
				$uci->set("wireless.vap04.orig_encryption",$auth_type1_);
				$uci->set("wireless.vap04.wep_key_len",$wep_len_);
				$uci->set("wireless.vap04._orig_wep_key_len",$wep_len_);
				$uci->set("wireless.vap04.wep_key_type",$wep_type_);
				$uci->set("wireless.vap04._orig_wep_key_type",$wep_type_);
				$uci->set("wireless.vap04.key",$wep_key_);
				$uci->set("wireless.vap04.wep_key",$wep_key_);
				$uci->set("wireless.vap04._orig_wep_key",$wep_key_);
				$uci->set("wireless.vap04.wep_radius",$wep_radius_);
				$uci->set("wireless.vap04._orig_wep_radius",$wep_radius_);
				$wek_prefix = "";
				if($wep_len_ == "64" && $wep_type_ == "ascii"){
					$prefix = "*****";
					$wek_prefix = "s:";
				}elseif($wep_len_ == "64" && $wep_type_ == "hex"){
					$prefix = "**********";
					$wek_prefix = "";
				}elseif($wep_len_ == "128" && $wep_type_ == "ascii"){
					$prefix = "*************";
					$wek_prefix = "s:";
				}elseif($wep_len_ == "128" && $wep_type_ == "hex"){
					$prefix = "**************************";
					$wek_prefix = "";
				}

				if($key1_ != $prefix && $key1_ != ""){
					$uci->set("wireless.vap04.key1",$wek_prefix.$key1_);
					$uci->set("wireless.vap04._orig_key1",$wek_prefix.$key1_);
				}else{
					$uci->set("wireless.vap04.key1",$pre_key1);
					$uci->set("wireless.vap04._orig_key1",$pre_key1);
				}
				if($key2_ != $prefix && $key2_ != ""){
					$uci->set("wireless.vap04.key2",$wek_prefix.$key2_);
					$uci->set("wireless.vap04._orig_key2",$wek_prefix.$key2_);
				}else{
					$uci->set("wireless.vap04.key2",$pre_key2);
					$uci->set("wireless.vap04._orig_key2",$pre_key2);
				}
				if($key3_ != $prefix && $key3_ != ""){
					$uci->set("wireless.vap04.key3",$wek_prefix.$key3_);
					$uci->set("wireless.vap04._orig_key3",$wek_prefix.$key3_);
				}else{
					$uci->set("wireless.vap04.key3",$pre_key3);
					$uci->set("wireless.vap04._orig_key3",$pre_key3);
				}
				if($key4_ != $prefix && $key4_ != ""){
					$uci->set("wireless.vap04.key4",$wek_prefix.$key4_);
					$uci->set("wireless.vap04._orig_key4",$wek_prefix.$key4_);
				}else{
					$uci->set("wireless.vap04.key4",$pre_key4);
					$uci->set("wireless.vap04._orig_key4",$pre_key4);
				}
			}
		}else{
			$uci->set("wireless.vap".$radio_.$seq_.".auth_server",$radius_ip_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_auth_server",$radius_ip_);
			$uci->set("wireless.vap".$radio_.$seq_.".auth_port",$radius_port_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_auth_port",$radius_port_);
			if($radius_passwd_ != "********" && $radius_passwd_ != ""){
				$uci->set("wireless.vap".$radio_.$seq_.".auth_secret",$radius_passwd_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_auth_secret",$radius_passwd_);
			}else{
				$uci->set("wireless.vap".$radio_.$seq_.".auth_secret",$pre_radius_passwd);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_auth_secret",$pre_radius_passwd);
			}
			$uci->set("wireless.vap".$radio_.$seq_.".radius_server_retries",$radius_retry_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_radius_server_retries",$radius_retry_);
			$uci->set("wireless.vap".$radio_.$seq_.".radius_max_retry_wait",$radius_intv_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_radius_max_retry_wait",$radius_intv_);
			if($acct_use_ == "1"){
				$uci->set("wireless.vap".$radio_.$seq_.".acct_server_use","1");
				$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_server_use","1");
				$uci->set("wireless.vap".$radio_.$seq_.".acct_server",$acct_ip_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_server",$acct_ip_);
				$uci->set("wireless.vap".$radio_.$seq_.".acct_port",$acct_port_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_port",$acct_port_);
				if($acct_passwd_ != "********" && $acct_passwd_ != ""){
					$uci->set("wireless.vap".$radio_.$seq_.".acct_secret",$acct_passwd_);
					$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_secret",$acct_passwd_);
				}else{
					$uci->set("wireless.vap".$radio_.$seq_.".acct_secret",$pre_acct_passwd);
					$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_secret",$pre_acct_passwd);
				}
				if($acct_retry_use_ == "1"){
					$uci->set("wireless.vap".$radio_.$seq_.".acct_interim_use",$acct_retry_use_);
					$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_interim_use",$acct_retry_use_);
					$uci->set("wireless.vap".$radio_.$seq_.".radius_acct_interim_interval",$acct_delay_time_ );
					$uci->set("wireless.vap".$radio_.$seq_."._orig_radius_acct_interim_interval",$acct_delay_time_ );
				}
			}
			if($handover == true){
				if($wep_radius_ == "1"){
					$uci->set("wireless.vap04.encryption","8021x");
					$uci->set("wireless.vap04.orig_encryption","8021x");
				}else{
					$uci->set("wireless.vap04.encryption",$auth_type1_);
					$uci->set("wireless.vap04.orig_encryption",$auth_type1_);
				}
				$uci->set("wireless.vap04.wep_key_len",$wep_len_);
				$uci->set("wireless.vap04._orig_wep_key_len",$wep_len_);
				$uci->set("wireless.vap04.wep_radius",$wep_radius_);
				$uci->set("wireless.vap04._orig_wep_radius",$wep_radius_);

				$uci->set("wireless.vap04.auth_server",$radius_ip_);
				$uci->set("wireless.vap04._orig_auth_server",$radius_ip_);
				$uci->set("wireless.vap04.auth_port",$radius_port_);
				$uci->set("wireless.vap04._orig_auth_port",$radius_port_);
				if($radius_passwd_ != "********" && $radius_passwd_ != ""){
					$uci->set("wireless.vap04.auth_secret",$radius_passwd_);
					$uci->set("wireless.vap04._orig_auth_secret",$radius_passwd_);
				}else{
					$uci->set("wireless.vap04.auth_secret",$pre_radius_passwd);
					$uci->set("wireless.vap04._orig_auth_secret",$pre_radius_passwd);
				}
				$uci->set("wireless.vap04.radius_server_retries",$radius_retry_);
				$uci->set("wireless.vap04._orig_radius_server_retries",$radius_retry_);
				$uci->set("wireless.vap04.radius_max_retry_wait",$radius_intv_);
				$uci->set("wireless.vap04._orig_radius_max_retry_wait",$radius_intv_);
				if($acct_use_ == "1"){
					$uci->set("wireless.vap04.acct_server_use","1");
					$uci->set("wireless.vap04._orig_acct_server_use","1");
					$uci->set("wireless.vap04.acct_server",$acct_ip_);
					$uci->set("wireless.vap04._orig_acct_server",$acct_ip_);
					$uci->set("wireless.vap04.acct_port",$acct_port_);
					$uci->set("wireless.vap04._orig_acct_port",$acct_port_);
					if($acct_passwd_ != "********" && $acct_passwd_ != ""){
						$uci->set("wireless.vap04.acct_secret",$acct_passwd_);
						$uci->set("wireless.vap04._orig_acct_secret",$acct_passwd_);
					}else{
						$uci->set("wireless.vap04.acct_secret",$pre_acct_passwd);
						$uci->set("wireless.vap04._orig_acct_secret",$pre_acct_passwd);
					}
					if($acct_retry_use_ == "1"){
						$uci->set("wireless.vap04.acct_interim_use",$acct_retry_use_);
						$uci->set("wireless.vap04._orig_acct_interim_use",$acct_retry_use_);
						$uci->set("wireless.vap04.radius_acct_interim_interval",$acct_delay_time_ );
						$uci->set("wireless.vap04._orig_radius_acct_interim_interval",$acct_delay_time_ );
					}
				}
			}
		}
	}elseif($auth_type_ == "none"){
		$uci->set("wireless.vap".$radio_.$seq_.".encryption","none");
		$uci->set("wireless.vap".$radio_.$seq_."._ori_encryption","none");
		if($mac_auth_ == "2"){
			if($pre_macaddr_acl != "0" && $pre_macaddr_acl != "1"){
				$uci->set("wireless.vap".$radio_.$seq_.".macaddr_acl",$mac_auth_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_macaddr_acl",$mac_auth_);
			}
//			$uci->set("wireless.vap".$radio_.$seq_.".key_type",$key_type_);
			$uci->set("wireless.vap".$radio_.$seq_.".auth_server",$radius_ip_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_auth_server",$radius_ip_);
			$uci->set("wireless.vap".$radio_.$seq_.".auth_port",$radius_port_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_auth_port",$radius_port_);
			if($radius_passwd_ != "********" && $radius_passwd_ != ""){
				$uci->set("wireless.vap".$radio_.$seq_.".auth_secret",$radius_passwd_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_auth_secret",$radius_passwd_);
			}else{
				$uci->set("wireless.vap".$radio_.$seq_.".auth_secret",$pre_radius_passwd);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_auth_secret",$pre_radius_passwd);
			}
			$uci->set("wireless.vap".$radio_.$seq_.".radius_server_retries",$radius_retry_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_radius_server_retries",$radius_retry_);
			$uci->set("wireless.vap".$radio_.$seq_.".radius_max_retry_wait",$radius_intv_);
			$uci->set("wireless.vap".$radio_.$seq_."._orig_radius_max_retry_wait",$radius_intv_);
			if($acct_use_ == "1"){
				$uci->set("wireless.vap".$radio_.$seq_.".acct_server_use","1");
				$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_server_use","1");
				$uci->set("wireless.vap".$radio_.$seq_.".acct_server",$acct_ip_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_server",$acct_ip_);
				$uci->set("wireless.vap".$radio_.$seq_.".acct_port",$acct_port_);
				$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_port",$acct_port_);
				if($acct_passwd_ != "********" && $acct_passwd_ != ""){
					$uci->set("wireless.vap".$radio_.$seq_.".acct_secret",$acct_passwd_);
					$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_secret",$acct_passwd_);
				}else{
					$uci->set("wireless.vap".$radio_.$seq_.".acct_secret",$pre_acct_passwd);
					$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_secret",$pre_acct_passwd);
				}
				if($acct_retry_use_ == "1"){
					$uci->set("wireless.vap".$radio_.$seq_.".acct_interim_use",$acct_retry_use_);
					$uci->set("wireless.vap".$radio_.$seq_."._orig_acct_interim_use",$acct_retry_use_);
					$uci->set("wireless.vap".$radio_.$seq_.".radius_acct_interim_interval",$acct_delay_time_ );
					$uci->set("wireless.vap".$radio_.$seq_."._orig_radius_acct_interim_interval",$acct_delay_time_ );
				}
			}
		}
		if($handover == true){
			$uci->set("wireless.vap04.encryption","none");
			$uci->set("wireless.vap04._ori_encryption","none");
			if($mac_auth_ == "2"){
				if($pre_macaddr_acl != "0" && $pre_macaddr_acl != "1"){
					$uci->set("wireless.vap04.macaddr_acl",$mac_auth_);
					$uci->set("wireless.vap04._orig_macaddr_acl",$mac_auth_);
				}
	//			$uci->set("wireless.vap04.key_type",$key_type_);
				$uci->set("wireless.vap04.auth_server",$radius_ip_);
				$uci->set("wireless.vap04._orig_auth_server",$radius_ip_);
				$uci->set("wireless.vap04.auth_port",$radius_port_);
				$uci->set("wireless.vap04._orig_auth_port",$radius_port_);
				if($radius_passwd_ != "********" && $radius_passwd_ != ""){
					$uci->set("wireless.vap04.auth_secret",$radius_passwd_);
					$uci->set("wireless.vap04._orig_auth_secret",$radius_passwd_);
				}else{
					$uci->set("wireless.vap04.auth_secret",$pre_radius_passwd);
					$uci->set("wireless.vap04._orig_auth_secret",$pre_radius_passwd);
				}
				$uci->set("wireless.vap04.radius_server_retries",$radius_retry_);
				$uci->set("wireless.vap04._orig_radius_server_retries",$radius_retry_);
				$uci->set("wireless.vap04.radius_max_retry_wait",$radius_intv_);
				$uci->set("wireless.vap04._orig_radius_max_retry_wait",$radius_intv_);
				if($acct_use_ == "1"){
					$uci->set("wireless.vap04.acct_server_use","1");
					$uci->set("wireless.vap04._orig_acct_server_use","1");
					$uci->set("wireless.vap04.acct_server",$acct_ip_);
					$uci->set("wireless.vap04._orig_acct_server",$acct_ip_);
					$uci->set("wireless.vap04.acct_port",$acct_port_);
					$uci->set("wireless.vap04._orig_acct_port",$acct_port_);
					if($acct_passwd_ != "********" && $acct_passwd_ != ""){
						$uci->set("wireless.vap04.acct_secret",$acct_passwd_);
						$uci->set("wireless.vap04._orig_acct_secret",$acct_passwd_);
					}else{
						$uci->set("wireless.vap04.acct_secret",$pre_acct_passwd);
						$uci->set("wireless.vap04._orig_acct_secret",$pre_acct_passwd);
					}
					if($acct_retry_use_ == "1"){
						$uci->set("wireless.vap04.acct_interim_use",$acct_retry_use_);
						$uci->set("wireless.vap04._orig_acct_interim_use",$acct_retry_use_);
						$uci->set("wireless.vap04.radius_acct_interim_interval",$acct_delay_time_ );
						$uci->set("wireless.vap04._orig_radius_acct_interim_interval",$acct_delay_time_ );
					}
				}
			}
		}
		
	}
	$uci->run();
	$uci->result();
	$uci->commit();
	$uci->close();
	echo(rtn_reboot_page(dv_post("submit-url"),"network_restart"));
?>