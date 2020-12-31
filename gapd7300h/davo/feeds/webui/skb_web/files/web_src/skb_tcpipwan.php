<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
/*
	[igmp (ping)]
	firewall.allow_icmp
	[IPsec/ESP passthrough]
	firewall.allow_esp
	firewall.allow_ipsec
	[PPTP passthrough]
	firewall.allow_pptp
	[L2TP passthrough]
	firewall.allow_l2tp 
	[ telnet]
	firewall.rd_telnet
	firewall.allow_telnet
	[NetBeui, NetBios, NBT filtering]
	firewall.allow_netbios 
	[Microsoft-ds (CIFS)]
	firewall.allow_msds 
	[LLTD(Link Layer Topology Discovery) 기능 차단]
	network.allow_lltd
*/
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>WAN Interface Setup </title>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<style type="text/css">
.on {display:on}
.off {display:none}
</style>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<script type="text/javascript">
var initialDnsMode, pppConnectStatus=0;
var ppp2ConnectStatus=0,ppp3ConnectStatus=0,ppp4ConnectStatus=0;
var MultiPppoeEnable= 0;
var wan_connection_type=0;
var dynamicWanIP=1;
var curLoginUser = <?=$isAdmin?>;

function macTblClick(url) {
	openWindow(url, 'skb_macTbl', 600, 400 );
}

function updateMacClone(flag) {
	var macEnabled;

	if(flag) {
		macEnabled = "0";
		if(macEnabled.indexOf("1",0)>-1) {
			document.tcpip.macCloneEnable.checked = true;
			document.tcpip.wan_macAddr.disabled=false;
			document.tcpip.macSearch.disabled=false;
		} else {
			document.tcpip.macCloneEnable.checked = false;
			document.tcpip.wan_macAddr.disabled=true;
			document.tcpip.macSearch.disabled=true;
		}
	} else {
		if(document.tcpip.macCloneEnable.checked) {
			document.tcpip.wan_macAddr.disabled=false;
			document.tcpip.macSearch.disabled=false;
		} else {
			document.tcpip.wan_macAddr.disabled=true;
			document.tcpip.macSearch.disabled=true;
		}
	}
}
function macValueModify(str, flag) {
	var tmp="";

	if ( str.length != 12 && str.length != 17) {
		alert("MAC 주소가 올바르지 않습니다. 16진수 12자리 또는 콜론을 포함한 17자리를 입력해야 합니다");
		return "0";
	}

	for (var i=0; i<str.length; i++) {
			if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
				(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
				(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') ||
				(str.charAt(i) == ':')) {
						if( (flag==1) & (i!=0) && (i%2)==0 )
							tmp += ':';
	  				if(str.charAt(i) != ':')
							tmp += str.charAt(i);
	  				continue;
		}
		alert("MAC 주소가 올바르지 않습니다. 16진수를 입력해야 합니다. (0-9 또는 a-f 또는 :)");
		return "0";
	}
	return tmp;
}



function getMacValue(flag) {
	var macVal;
	var tmp;
	var macEnable;
	var result;

	if (flag == 0) {
		document.tcpip.save.disabled=true;
		document.tcpip.reset.disabled=true;
	}

	if(flag) {
		macVal = '000000000000';
		tmp = macValueModify(macVal,1); // add colon
	} else {
		macVal = document.tcpip.wan_macAddr.value;
		tmp = macValueModify(macVal,0); // delete colon
	}

	if(tmp == '0') // 0 = error
		return false;
	else {
		document.tcpip.wan_macAddr.value = tmp;
		if(flag==0) {
			result = saveChanges_wan(document.tcpip,MultiPppoeEnable,dynamicWanIP);
			if (result == false) {
				document.tcpip.save.disabled=false;
				document.tcpip.reset.disabled=false;
			}
			else
				document.tcpip.submit();
		}
	}
}
var check_macaddr = function(){
	document.tcpip.save.disabled=true;
	document.tcpip.reset.disabled=true;
	var wan_proto_ = $("#wan_proto").children(":selected").val();
	var wan_ip_ = $("#wan_ip").val();
	var netmask_ = $("#wan_netmask").val();
	var gateway_ = $("#wan_gateway").val();
	var mtu_ = $("#wan_mtu").val();
	var dns_mode_ = $("[name='dnsMode']:checked").val();
	var dns1_ = $("#wan_dns1").val();
	var dns2_ = $("#wan_dns2").val();
	if(wan_proto_ == "static"){
		if(!ipCheck(wan_ip_)){
			alert("IP 주소가 올바르지 않습니다");
			$("#wan_ip").focus();
			document.tcpip.save.disabled=false;
			document.tcpip.reset.disabled=false;
			return false;
		}
		if(!maskCheck(netmask_)){
			alert("서브넷 마스크가 올바르지 않습니다.");
			$("#wan_netmask").focus();
			document.tcpip.save.disabled=false;
			document.tcpip.reset.disabled=false;
			return false;
		}
		if(!ipCheck(gateway_)){
			alert("게이트웨이 주소가 올바르지 않습니다");
			$("#wan_gateway").focus();
			document.tcpip.save.disabled=false;
			document.tcpip.reset.disabled=false;
			return false;
		}
		if(!check_ip_du_band(wan_ip_,netmask_, gateway_, netmask_)){
			alert("IP 주소 또는 게이트웨이가 서브넷을 벗어났습니다.");
			$("#wan_gateway").focus();
			document.tcpip.save.disabled=false;
			document.tcpip.reset.disabled=false;
			return false;
		}
		
	}
	if(!isNumVal(mtu_)){
		alert("MTU가 올바르지 않습니다.");
		$("#wan_mtu").focus();
		document.tcpip.save.disabled=false;
		document.tcpip.reset.disabled=false;
		return false;
	}
	if(!check_min_max(mtu_,1,12000)){
		alert("MTU가 올바르지 않습니다.");
		$("#wan_mtu").focus();
		document.tcpip.save.disabled=false;
		document.tcpip.reset.disabled=false;
		return false;
	}
	if(dns_mode_ == 1){
		if(!ipCheck(dns1_)){
			alert("DNS 1 주소가 올바르지 않습니다");
			$("#wan_dns1").focus();
			document.tcpip.save.disabled=false;
			document.tcpip.reset.disabled=false;
			return false;
		}
		if(dns2_ != ""){
			if(!ipCheck(dns2_)){
				alert("DNS 2 주소가 올바르지 않습니다");
				$("#wan_dns2").focus();
				document.tcpip.save.disabled=false;
				document.tcpip.reset.disabled=false;
				return false;
			}
		}
	}
	if($("#macCloneEnable").prop("checked") == true){
		var mac = $("#wan_macAddr").val();
		if(mac == "00:00:00:00:00:00"){
			alert("MAC 주소가 올바르지 않습니다. 16진수 12자리 또는 콜론을 포함한 17자리를 입력해야 합니다");
			document.tcpip.save.disabled=false;
			document.tcpip.reset.disabled=false;
			return false;
		}
		if(validation_mac(mac) == false){
			alert("MAC 주소가 올바르지 않습니다. 16진수를 입력해야 합니다. (0-9 또는 a-f 또는 :)");
			document.tcpip.save.disabled=false;
			document.tcpip.reset.disabled=false;
			return false;
		}
	}
	$("#dns_mode").val(dns_mode);
	document.tcpip.submit();
}
function resetClicked()
{
	document.location.assign("skb_tcpipwan.php");
}
function disableDNSinput()
{
   //document.tcpip.dnslist.disabled=true;
   document.tcpip.dns2.value="";
   //document.tcpip.dns3.value="";
   disableTextField(document.tcpip.dns1);
   disableTextField(document.tcpip.dns2);
   //disableTextField(document.tcpip.dns3);
}

function enableDNSinput()
{
   //document.tcpip.dnslist.disabled=false;
  //enableTextField(document.tcpip.dns1);
   enableTextField(document.tcpip.dns2);
   //enableTextField(document.tcpip.dns3);
}

function autoDNSclicked()
{
  disableDNSinput();
}

function manualDNSclicked()
{
  enableDNSinput();
}
function checkSubnet(ip, mask, client)
{
  ip_d = getDigit(ip, 1);
  mask_d = getDigit(mask, 1);
  client_d = getDigit(client, 1);
  if ( (ip_d & mask_d) != (client_d & mask_d ) )
	return false;

  ip_d = getDigit(ip, 2);
  mask_d = getDigit(mask, 2);
  client_d = getDigit(client, 2);
  if ( (ip_d & mask_d) != (client_d & mask_d ) )
	return false;

  ip_d = getDigit(ip, 3);
  mask_d = getDigit(mask, 3);
  client_d = getDigit(client, 3);
  if ( (ip_d & mask_d) != (client_d & mask_d ) )
	return false;

  ip_d = getDigit(ip, 4);
  mask_d = getDigit(mask, 4);
  client_d = getDigit(client, 4);
  if ( (ip_d & mask_d) != (client_d & mask_d ) )
	return false;

  return true;
}
</script>
<script type="text/javascript">
var proc = "proc/skb_tcpipwan_proc.php";
var dns_mode = 0;
var get_wan_info = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_wan_info';
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(d != null){
				$("#wan_ip").val(get_obj_val(d,"network.wan.ipaddr"));
				$("#wan_netmask").val(get_obj_val(d,"network.wan.netmask"));
				$("#wan_gateway").val(get_obj_val(d,"network.wan.gateway"));
				$("#wan_ip").val(get_obj_val(d,"network.wan.ipaddr"));
				$("#wan_ip").val(get_obj_val(d,"network.wan.ipaddr"));
				$("#wan_ip").val(get_obj_val(d,"network.wan.ipaddr"));
				$("#wan_proto").val(get_obj_val(d,"network.wan.proto"),1500);
				if(get_obj_val(d,"network.wan.mtu") != ""){
					$("#wan_mtu").val(get_obj_val(d,"network.wan.mtu"));
				}else{
					$("#wan_mtu").val("1500");
				}
				if(get_obj_val(d,"network.wan.dns") == ""){
					$("#wan_dns1").val("210.220.163.82");
					$("#wan_dns2").val("");
					dns_mode = 0;
					$("[name='dnsMode']").eq(0).prop("checked",true);
					$("#dns_status").text("자동모드");
					$("#dns_status_val").text("(210.220.163.82)");
					$("#wan_dns2").prop("disabled",true);
				}else{
					var tmpdns = get_obj_val(d,"network.wan.dns").split(" ");
					var dns_val = "";
					if(tmpdns[0] != undefined){
						$("#wan_dns1").val(tmpdns[0]);
						dns_val += tmpdns[0];
					}
					if(tmpdns[1] != undefined){
						$("#wan_dns2").val(tmpdns[1]);
						dns_val += ", "+tmpdns[1];
					}
					dns_mode = 1;
					$("[name='dnsMode']").eq(1).prop("checked",true);
					$("#dns_status").text("수동모드");
					$("#dns_status_val").text("("+dns_val+")");
					$("#wan_dns2").prop("disabled",false);
				}
				if(get_obj_val(d,"network.wan.macaddr") != ""){
					$("#macCloneEnable").prop("checked",true);
					$("#wan_macAddr").val(get_obj_val(d,"network.wan.macaddr"));
					updateMacClone(0);
				}else{
					$("#macCloneEnable").prop("checked",false);
					updateMacClone(1);
				}
				wan_proto_change();
			}
			
		},complete:function(){
			get_service_info();
		}
	});
}
var dns_change = function(mode_){
	var mode = mode_ != undefined ? mode_ : dns_mode;
	$("#dns_mode").val(mode);
	$("[name='dnsMode']").eq(mode).prop("checked",true);
	if(mode == 0){
		$("#wan_dns2").prop("disabled",true);
		dns_mode = 0;
	}else{
		$("#wan_dns2").prop("disabled",false);
		dns_mode = 1;
	}
}
var wan_proto_change = function(){
	if($("#wan_proto").children(":selected").val() == "dhcp"){
		$(".static_div").hide();
		$(".dhcp_div").show();
		$("#dnsMode_div").show();
		$("#wan_dns2").prop("disabled",true);
		dns_change();
	}else{
		$(".static_div").show();
		$(".dhcp_div").hide();
		$("#dnsMode_div").hide();
		$("#wan_dns2").prop("disabled",false);
	}
}
var get_service_info = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_service_info';
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(d != null){
				if(get_obj_val(d,"igmpproxy.igmpproxy.enabled") == "1"){
					$("#igmp_enabled").prop("checked",true);
				}else{
					$("#igmp_enabled").prop("checked",false);
				}
				if(get_obj_val(d,"firewall.allow_icmp.target") == "ACCEPT"){
					$("#ping_enabled").prop("checked",true);
				}else{
					$("#ping_enabled").prop("checked",false);
				}
				if(get_obj_val(d,"firewall.allow_ipsec.target") == "ACCEPT"){
					$("#ipsec_enabled").prop("checked",true);
				}else{
					$("#ipsec_enabled").prop("checked",false);
				}
				if(get_obj_val(d,"firewall.allow_pptp.target") == "ACCEPT"){
					$("#pptp_enabled").prop("checked",true);
				}else{
					$("#pptp_enabled").prop("checked",false);
				}
				if(get_obj_val(d,"firewall.allow_l2tp.target") == "ACCEPT"){
					$("#l2tp_enabled").prop("checked",true);
				}else{
					$("#l2tp_enabled").prop("checked",false);
				}
				if(get_obj_val(d,"firewall.allow_netbios.target") == "ACCEPT"){
					$("#netbios_enabled").prop("checked",true);
				}else{
					$("#netbios_enabled").prop("checked",false);
				}
				if(get_obj_val(d,"firewall.allow_msds.target") == "ACCEPT"){
					$("#cifs_enabled").prop("checked",true);
				}else{
					$("#cifs_enabled").prop("checked",false);
				}
				if(get_obj_val(d,"network.allow_lltd.packet_drop") == "yes"){
					$("#lltd_enabled").prop("checked",false);
				}else{
					$("#lltd_enabled").prop("checked",true);
				}
				if(get_obj_val(d,"dvmgmt.starcraft.enable") == "1"){
					$("#battle_enabled").prop("checked",true);
				}else{
					$("#battle_enabled").prop("checked",false);
				}
				if(get_obj_val(d,"firewall.allow_lan_telnet.target") == "ACCEPT"){
					$("#telnet_enabled").prop("checked",true);
				}else{
					$("#telnet_enabled").prop("checked",false);
				}
			}
		}
	});
}
var get_ping_info = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_ping_info';
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(get_obj_val(d,"firewall.allow_icmp.target") == "ACCEPT"){
				$("#ping_enabled").prop("checked",true);
			}else{
				$("#ping_enabled").prop("checked",false);
			}
		},complete:function(){
			get_ipsec_info();
		}
	});
}
var get_ipsec_info = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_ipsec_info';
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(get_obj_val(d,"firewall.allow_ipsec.target") == "ACCEPT"){
				$("#ipsec_enabled").prop("checked",true);
			}else{
				$("#ipsec_enabled").prop("checked",false);
			}
		},complete:function(){
			get_pptp_info();
		}
	});
}
var get_pptp_info = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_pptp_info';
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(get_obj_val(d,"firewall.allow_pptp.target") == "ACCEPT"){
				$("#pptp_enabled").prop("checked",true);
			}else{
				$("#pptp_enabled").prop("checked",false);
			}
		},complete:function(){
			get_l2tp_info();
		}
	});
}
var get_l2tp_info = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_l2tp_info';
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(get_obj_val(d,"firewall.allow_l2tp.target") == "ACCEPT"){
				$("#l2tp_enabled").prop("checked",true);
			}else{
				$("#l2tp_enabled").prop("checked",false);
			}
		},complete:function(){
			get_netbios_info();
		}
	});
}
var get_netbios_info = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_netbios_info';
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(get_obj_val(d,"firewall.allow_netbios.target") == "ACCEPT"){
				$("#netbios_enabled").prop("checked",true);
			}else{
				$("#netbios_enabled").prop("checked",false);
			}
		},complete:function(){
			get_cifs_info();
		}
	});
}
var get_cifs_info = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_cifs_info';
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(get_obj_val(d,"firewall.allow_msds.target") == "ACCEPT"){
				$("#cifs_enabled").prop("checked",true);
			}else{
				$("#cifs_enabled").prop("checked",false);
			}
		},complete:function(){
			get_lltd_info();
		}
	});
}
var get_lltd_info = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_lltd_info';
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(get_obj_val(d,"network.allow_lltd.packet_drop") == "yes"){
				$("#lltd_enabled").prop("checked",true);
			}else{
				$("#lltd_enabled").prop("checked",false);
			}
		},complete:function(){
			get_telnet_info();
		}
	});
}
var get_telnet_info = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_telnet_info';
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(get_obj_val(d,"firewall.allow_lan_telnet.target") == "ACCEPT"){
				$("#telnet_enabled").prop("checked",true);
			}else{
				$("#telnet_enabled").prop("checked",false);
			}
		}
	});
}
$(document).ready(function(){
//	checkUser();
	get_wan_info();
});
</script>
</head>

<body>
<blockquote>
<h2>인터넷 설정</h2>
<form action="/proc/skb_tcpipwan_proc.php" method="POST" name="tcpip">
<input type="hidden" name="act" id="act" value="set_wan_info">
<table border=0 width="550" cellspacing=0 cellpadding=0>
  <tr><font size="2">
   고정 IP, 유동 IP, DHCP 설정 등 인터넷 접속을 위한 페이지입니다.
  </tr>
  <tr><hr size=1 noshade align=top></tr>
  <tr>
</table>
<input type="hidden" name="dns_mode" id="dns_mode" value="0">
<fieldset style="border-right: #000000 1px solid; padding-right: 10px; border-top: #000000 1px solid; padding-left: 10px; padding-bottom: 5px; border-left: #000000 1px solid; width: 480px; padding-top: 0px; border-bottom: #000000 1px solid; "><legend>모드 설정</legend>
	<table border="0" width="480">
		<tr>
			<td width="30%" height="40"><font size="2">&nbsp;&nbsp;&nbsp;<b>IP획득 방법:</b></td>
			<td width="70%"><font size="2"><select name="wan_proto" id="wan_proto" size="1" onChange="wan_proto_change()">
				<option value="static">고정 IP</option>
				<option value="dhcp">유동 IP</option>
			</select></td>
		<tr>
	</table>
	<table border="0" width="480">
		<tr class="static_div">
			<td width="30%"><font size="2">&nbsp;&nbsp;&nbsp;<b>IP 주소:</b></td>
			<td width="70%"><font size="2"><input type="text" name="wan_ip" id="wan_ip" size="18" maxlength="15" value=""></td>
		</tr>
		<tr class="static_div">
			<td><font size="2">&nbsp;&nbsp;&nbsp;<b>서브넷 마스크:</b></td>
			<td><font size="2"><input type="text" name="wan_netmask" id="wan_netmask" size="18" maxlength="15" value=""></td>
		</tr>
		<tr class="static_div">
			<td><font size="2">&nbsp;&nbsp;&nbsp;<b>게이트 웨이:</b></td>
			<td><font size="2"><input type="text" name="wan_gateway" id="wan_gateway" size="18" maxlength="15" value=""></td>
		</tr>
		<tr class="dhcp_div">
			<td><font size="2">&nbsp;&nbsp;&nbsp;<b>호스트 이름:</b></td>
			<td><font size="2"><input type="text" name="wan_hostname" id="wan_hostname" size="10" maxlength="10" value="H824G" readonly></td>
		</tr>
		<tr>
			<td><font size="2">&nbsp;&nbsp;&nbsp;<b>MTU 크기:</b></td>
			<td><font size="2"><input type="text" name="wan_mtu" id="wan_mtu" size="10" maxlength="10" value="1500">&nbsp;(1400-1500 bytes)</td>
		</tr>
	</table>
	<span id="dnsMode_div" class="off" >
	<table border="0" width="480">
		<tr>
			<td width="100%" colspan="2"><font size="2"><b>&nbsp;<input type="radio" name="dnsMode" value="0" onclick="dns_change(0);">자동으로 DNS 주소 받기</b></td>
		</tr>
		<tr>
			<td width="100%" colspan="2"><font size="2"><b>&nbsp;<input type="radio" name="dnsMode" value="1" onclick="dns_change(1);">다음 DNS 서버 주소 사용</b></td>
		</tr>
	</table>
	</span>
	<span id="dns_div" class="on" >
	<table border="0" width="480">
		<tr>
			<td width="30%"><font size="2"><b>&nbsp;&nbsp;&nbsp;DNS 1:</b></td>
			<td width="70%"><font size="2"><input type="text" name="wan_dns1" id="wan_dns1" size="18" maxlength="15" value="210.220.163.82" readonly>&nbsp;&nbsp;</td>
		</tr>
		<tr>
			<td width="30%"><font size="2"><b>&nbsp;&nbsp;&nbsp;DNS 2:</b></td>
			<td width="70%"><font size="2"><input type="text" name="wan_dns2" id="wan_dns2" size="18" maxlength="15" value=""></td>
		</tr>
		<tr>
			<td width="30%" height="40"><font size="2"><b>&nbsp;&nbsp;&nbsp;DNS 동작상태:</b></td>
			<td width="70%"><font size="2"><font color="blue"><b id="dns_status">수동모드</b></font> <span id="dns_status_val">(210.220.163.82)</span></td>
		</tr>
	</table>
	</span>
	<br>
	<span id="always_div" class="on" >
	<fieldset style="border-right: #000000 1px solid; padding-right: 10px; border-top: #000000 1px solid; padding-left: 10px; padding-bottom: 5px; border-left: #000000 1px solid; width: 480px; padding-top: 0px; border-bottom: #000000 1px solid; "><LEGEND>MAC Clone</LEGEND>
		<table border="0" width="480">
			<tr>
				 <td colspan="2"><font size="2"><b>
				 <input type="checkbox" name="macCloneEnable" id="macCloneEnable" value="1" onclick='updateMacClone(0);'>&nbsp;&nbsp;사용</b></font></td>
			</tr>
			<tr>
				<td width="30%"><font size="2"><b>MAC :</b></td>
				<td width="70%"><font size="2"><input type="text" name="wan_macAddr" id="wan_macAddr" size="18" maxlength="17" value="">
				<input type="button" id="macSearch" name="macSearch" value="MAC search" onclick="macTblClick('/skb_mactbl.php#form')" >
					<script>updateMacClone(1); getMacValue(1);</script>
				</td>
			</tr>
		</table>
	</fieldset>
	<br>
	<fieldset style="border-right: #000000 1px solid; padding-right: 10px; border-top: #000000 1px solid; padding-left: 10px; padding-bottom: 5px; border-left: #000000 1px solid; width: 480px; padding-top: 0px; border-bottom: #000000 1px solid; "><LEGEND>서비스</LEGEND>
		<table border="0" width="480">
			<tr>
				<td width="100%" colspan="2"><font size="2">
				<b><input type="checkbox" name="igmp_enabled" id="igmp_enabled" value="1">&nbsp;&nbsp;&nbsp;IGMP 프록시</b></font></td>
			</tr>
			<tr>
				<td width="100%" colspan="2"><font size="2">
				<b><input type="checkbox" name="ping_enabled" id="ping_enabled" value="1">&nbsp;&nbsp;&nbsp;Ping 응답</b></font></td>
			</tr>
			<tr>
				<td width="100%" colspan="2"><font size="2">
				<b><input type="checkbox" name="ipsec_enabled" id="ipsec_enabled" value="1">&nbsp;&nbsp; IPsec pass through on VPN 연결</b></font></td>
			</tr>
			<tr>
				<td width="100%" colspan="2"><font size="2">
				<b><input type="checkbox" name="pptp_enabled" id="pptp_enabled" value="1">&nbsp;&nbsp; PPTP pass through on VPN 연결</b></font></td>
			</tr>
			<tr>
				<td width="100%" colspan="2"><font size="2">
				<b><input type="checkbox" name="l2tp_enabled" id="l2tp_enabled" value="1">&nbsp;&nbsp; L2TP pass through on VPN 연결</b></font></td>
			</tr>
			<tr>
				<td width="100%" colspan="2"><font size="2">
				<b><input type="checkbox" name="netbios_enabled" id="netbios_enabled" value="1">&nbsp;&nbsp; NetBeui, NetBios, NBT filtering</b></font></td>
			</tr>
			<tr>
				<td width="100%" colspan="2"><font size="2">
				<b><input type="checkbox" name="cifs_enabled" id="cifs_enabled" value="1">&nbsp;&nbsp; Microsoft-ds (CIFS)</b></font></td>
			</tr>
			<tr>
				<td width="100%" colspan="2"><font size="2">
				<b><input type="checkbox" name="lltd_enabled" id="lltd_enabled" value="1">&nbsp;&nbsp; LLTD(Link Layer Topology Discovery)</b></font></td>
			</tr>
			<tr>
				<td width="100%" colspan="2"><font size="2">
				<b><input type="checkbox" name="battle_enabled" id="battle_enabled" value="1">&nbsp;&nbsp; ALG Battle.net</b></font></td>
			</tr>
			<?php 
				if($isAdmin == "0"){
			?>
			<tr id="telnet_opt">
				<td width="100%" colspan="2"><font size="2">
				<b><input type="checkbox" name="telnet_enabled" id="telnet_enabled" value="1">&nbsp;&nbsp; Telnet 사용</b></font></td>
			</tr>
			<?
				}
			?>
		</table>
	</fieldset>
	</span>
	<br>
	<input type="hidden" value="skb_tcpipwan.php" name="page">
	<input type="hidden" value="/skb_tcpipwan.php" name="submit-url">
	<p><input type="submit" value="적용" name="save" onclick="return check_macaddr();">&nbsp;&nbsp;
	<input type="reset" value="취소" name="reset" onclick="resetClicked()">
</p>
</form>
</blockquote>
</body>
</html>
