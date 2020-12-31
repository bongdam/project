<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$syscall = new dvcmd();
	$syscall->add("uci_show","network | grep =switch_ext | grep aclrule_ | sed 's/=switch_ext//'","!");
	$syscall->add("uci_show","network | grep aclrule_ | grep -v '=switch_ext' | grep -v '.device' ","!");
	$syscall->add("uci_change"," network","!");
	$syscall->run();
	$aclrule = explode("\n",rtrim($syscall->result()[0]));
	$aclrulelist = explode("\n",rtrim($syscall->result()[1]));
	$changelist = rtrim($syscall->result()[2]);
	$syscall->close();
	$rule_id = preg_replace("/[^0-9]{1,}/","",$aclrule[count($aclrule)-1]) + 1;
	$applybtn = false;
	if(strlen($changelist) != 0){
		$applybtn = true;
	}
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">

<title>ACL 환경 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"> </script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<script type="text/javascript" src="js/skb_util_qos.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">

function xnum_check(e){
	var keyCodes = e.keyCode ? e.keyCode : e.which;
	if(keyCodes == 8 || keyCodes == 9 || keyCodes == 37 || keyCodes == 38 || keyCodes == 39 || keyCodes == 40) //BackSpace
		return true;
	if((keyCodes < 48) || (keyCodes > 57))
	{
		if(((keyCodes < 96) || (keyCodes > 105)) && ((keyCodes < 65) || (keyCodes > 70)))
		{
			alert("0~9 또는 a~f를 입력해 주시기바랍니다");
			e.returnValue = false;
			return false;
		}else{
			return true;
		}
	}
	e.returnValue = true;
}

function num_check(e){
	var keyCodes = e.keyCode ? e.keyCode : e.which;
	if(keyCodes == 8 || keyCodes == 9 || keyCodes == 37 || keyCodes == 38 || keyCodes == 39 || keyCodes == 40) //BackSpace
		return true;
	if((keyCodes < 48) || (keyCodes > 57))
	{
		if(((keyCodes < 96) || (keyCodes > 105)) ) {
			alert("숫자를 입력해야 합니다");
			e.returnValue = false;
			return false;
		}else{
			return true;
		}
	}
	e.returnValue = true;
}

function checkIpV4(str) {
	var pattern = /^(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4])\.(?:(?:[01]?\d\d?|2[0-4]\d|25[0-4])\.){2}(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4])$/;
	return pattern.test(str);
}


function changeProto(sel)
{
	formEnable(document.qos_acl.etc_proto_value)
}

function select_all()
{
//	for(var i = 0; i < document.qos_acl.elements.length; i++)
//	{
//		var e = document.qos_acl.elements[i];
//
//		if (e.type == 'checkbox')
//		{
//			e.checked = true;
//		}
//	}
	$("[name=qlist]").prop("checked",true);
}

function unselect_all()
{
//	for(var i = 0; i < document.qos_acl.elements.length; i++)
//	{
//		var e = document.qos_acl.elements[i];
//
//		if (e.type == 'checkbox')
//		{
//			e.checked = false;
//		}
//	}
	$("[name=qlist]").prop("checked",false);
}

function selectListClear()
{
	var s = document.qos_acl.protocol_val;
	
	while(s.options.length > 0)
		s.options.remove(0);
}

function check_value()
{
	var flag=0;

	if (document.qos_acl.vlan_use.checked && document.qos_acl.vlan_use.disabled == false){
		var vlan_val = parseInt(document.qos_acl.vlan_value.value);
		if (document.qos_acl.vlan_value.value == ""){
			flag += 1;
			alert("VLAN ID가 비어있습니다...");
		}
		else if ( (vlan_val < 0 ) || (vlan_val > 4095)){
			flag += 1;
			alert("VLAN ID가 올바르지 않습니다...");
		}
	}
	if (document.qos_acl.dscp_use.checked && !document.qos_acl.dscp_use.disabled){
		if (document.qos_acl.dscp_value.value == ""){
			flag += 1;
			alert("DSCP가 비어있습니다...");
		}
		else {
			var dscp_value = parseInt(document.qos_acl.dscp_value.value);
			if ( (dscp_value < 0) || (dscp_value > 63)){
				flag += 1;
				alert("DSCP가 올바르지 않습니다...");
			}
		}
	}
	if (!document.qos_acl.tos_use.disabled && document.qos_acl.tos_use.checked){
		var tos_value = parseInt(document.qos_acl.tos_value.value);
		if (document.qos_acl.tos_value.value == ""){
			flag += 1;
			alert("ToS가 비어있습니다...");
		}
	}

	if (!document.qos_acl.srcipv6_use.disabled && document.qos_acl.srcipv6_use.checked){
		if ( (document.qos_acl.srcipv6.value == "") || (document.qos_acl.srcipv6_mask.value == "")) {
			flag += 1;
			alert("출발지 IPv6 또는 Mask가 비어있습니다...");
		}

		if (!IsDigit(document.qos_acl.srcipv6_mask.value)) {
           	alert('출발지 마스크 값은 숫자만 입력하세요.');
           	document.qos_acl.srcipv6_mask.focus();
           	flag += 1;
        }

		if (parseInt(document.qos_acl.srcipv6_mask.value) < 1 ||
			parseInt(document.qos_acl.srcipv6_mask.value) > 128 ) {
			alert("출발지 Ipv6 마스크 값은 1 ~ 128 까지여야 합니다.");
			document.qos_acl.srcipv6_mask.focus();
			flag += 1;
		}
	}

	if (!document.qos_acl.srcip_use.disabled && document.qos_acl.srcip_use.checked){
		if ( (document.qos_acl.srcip0.value == "")
			|| (document.qos_acl.srcip1.value == "")
			|| (document.qos_acl.srcip2.value == "")
			|| (document.qos_acl.srcip3.value == "")
			|| (document.qos_acl.srcip_mask.value == "")){
			flag += 1;
			alert("출발지 IP 또는 Mask가 비어있습니다...");
		} else {
			var srcip = document.qos_acl.srcip0.value + "."
					+ document.qos_acl.srcip1.value + "."
					+ document.qos_acl.srcip2.value + "."
					+ document.qos_acl.srcip3.value;

			if (!checkIpV4(srcip)) {
				flag += 1;
				alert("출발지 IP 주소가 올바르지 않습니다");
			}

			if (!IsDigit(document.qos_acl.srcip_mask.value)) {
           		alert('출발지 IP 마스크 값은 숫자만 입력하세요.');
           		document.qos_acl.srcip_mask.focus();
           		flag += 1;
        	}

			var srcip_mask_val = parseInt(document.qos_acl.srcip_mask.value);
			if (srcip_mask_val < 1 || srcip_mask_val > 32) {
				flag += 1;
				alert("소스 IP 마스크가 올바르지 않습니다");
				document.qos_acl.srcip_mask.focus();
			}
		}
	}

	if (!document.qos_acl.dstipv6_use.disabled && document.qos_acl.dstipv6_use.checked){
		if ( (document.qos_acl.dstipv6.value == "") || (document.qos_acl.dstipv6_mask.value == "")) {
			flag += 1;
			alert("목적지 IPv6 또는 Mask가 비어있습니다...");
		}

		if (!IsDigit(document.qos_acl.dstipv6_mask.value)) {
           	alert('목적지 마스크 값은 숫자만 입력하세요.');
           	document.qos_acl.dstipv6_mask.focus();
           	flag += 1;
        }

		if (parseInt(document.qos_acl.dstipv6_mask.value) < 1 ||
			parseInt(document.qos_acl.dstipv6_mask.value) > 128 ) {
			alert("목적지 IPv6 마스크 값은 1 ~ 128 까지여야 합니다.");
			document.qos_acl.dstipv6_mask.focus();
			flag += 1;
		}
	}


	if (!document.qos_acl.dstip_use.disabled && document.qos_acl.dstip_use.checked){
		if ( (document.qos_acl.dstip0.value == "")
			|| (document.qos_acl.dstip1.value == "")
			|| (document.qos_acl.dstip2.value == "")
			|| (document.qos_acl.dstip3.value == "")
			|| (document.qos_acl.dstip_mask.value == "")){
			flag += 1;
			alert("목적지 IP 또는 Mask가 비어있습니다...");
		} else {
			var dstip = document.qos_acl.dstip0.value + "."
					+ document.qos_acl.dstip1.value + "."
					+ document.qos_acl.dstip2.value + "."
					+ document.qos_acl.dstip3.value;

			if (!checkIpV4(dstip)) {
				flag += 1;
				alert("목적지 IP 주소가 올바르지 않습니다");
			}

			if (!IsDigit(document.qos_acl.dstip_mask.value)) {
           		alert('목적지 IP 마스크 값은 숫자만 입력하세요.');
           		flag += 1;
        	}

			var dstip_mask_val = parseInt(document.qos_acl.dstip_mask.value);
			if (dstip_mask_val < 1 || dstip_mask_val > 32) {
				flag += 1;
				alert("목적지 IP 마스크가 올바르지 않습니다");
			}
		}
	}

	if (document.qos_acl.srcport_use.checked && document.qos_acl.srcport_use.disabled == false){
		var srcport0 = parseInt(document.qos_acl.srcport0.value);
		if (document.qos_acl.srcport0.value == ""){
			flag += 1;
			alert("출발지 포트 1번째 영역의 값이 비어있습니다...");
		}
		else if ( srcport0 > 65535){
		flag += 1;
			alert("출발지 포트 1번째 영역의 값이 올바르지 않습니다...");
		}
		var srcport1 = parseInt(document.qos_acl.srcport1.value);
		if (document.qos_acl.srcport1.value == ""){
			flag += 1;
			alert("출발지 포트 2번째 영역의 값이 비어있습니다...");
		}
		else if ( srcport1 > 65535){
			flag += 1;
			alert("출발지 포트 2번째 영역의 값이 올바르지 않습니다...");
		}
		if ( srcport0 > srcport1)
		{
			flag += 1;
			alert("출발지 포트 2번째 영역의 값이 1번째 영역의 값보다 커야 합니다...");
		}
	}
	if (document.qos_acl.dstport_use.checked && document.qos_acl.dstport_use.disabled == false){
		var dstport0 = parseInt(document.qos_acl.dstport0.value);
		if (document.qos_acl.dstport0.value == ""){
			flag += 1;
			alert("목적지 포트 1번째 영역의 값이 비어있습니다...");
		}
		else if ( dstport0 > 65535){
		flag += 1;
			alert("목적지 포트 1번째 영역의 값이 올바르지 않습니다...");
		}
		var dstport1 = parseInt(document.qos_acl.dstport1.value);
		if (document.qos_acl.dstport1.value == ""){
			flag += 1;
			alert("목적지 포트 2번째 영역의 값이 비어있습니다...");
		}
		else if ( dstport1 > 65535){
			flag += 1;
			alert("목적지 포트 2번째 영역의 값이 올바르지 않습니다...");
		}
		if ( dstport0 > dstport1)
		{
			flag += 1;
			alert("목적지 포트 2번째 영역의 값이 1번째 영역의 값보다 커야 합니다...");
		}
	}

	if(document.qos_acl.qos_action[0].checked && document.qos_acl.l2priority_flag.checked )
	{
		flag += 1;
		alert("Rule 검사 오류");
	}

	if(!flag)
		document.qos_acl.submit();
}


function toggle_l2Protocol()
{
	if (document.qos_acl.protocol_use.checked == false){
		formDisable(document.qos_acl.protocol_val);
		formDisable(document.qos_acl.etc_proto_value);
	}
	else{
		formEnable(document.qos_acl.protocol_val);
		changeProto();
	}

}

function toggle_l2Tos()
{
	document.qos_acl.dscp_use.checked = false;
	formDisable(document.qos_acl.dscp_value);
	if(document.qos_acl.dscp_use.checked == false){
		formDisable(document.qos_acl.dscp_value);
	}else{
		formEnable(document.qos_acl.dscp_value);
	}
	if (document.qos_acl.tos_use.checked == false){
		formDisable(document.qos_acl.tos_value);
	}
	else{
		formEnable(document.qos_acl.tos_value);
	}
}

function toggle_l2Dscp()
{
	if (document.qos_acl.dscp_use[0].checked == false){
		formDisable(document.qos_acl.tos_value);
		formEnable(document.qos_acl.dscp_value);
	}else{
		formEnable(document.qos_acl.tos_value);
		formDisable(document.qos_acl.dscp_value);
	}
	if(document.qos_acl.dscp_use[0].checked == false && document.qos_acl.dscp_use[1].checked == false){
		formDisable(document.qos_acl.tos_value);
		formDisable(document.qos_acl.dscp_value);
	}
}

function toggle_l2SrcIp()
{
	if (document.qos_acl.srcip_use.checked == false){
		formDisable(document.qos_acl.srcip0);
		formDisable(document.qos_acl.srcip1);
		formDisable(document.qos_acl.srcip2);
		formDisable(document.qos_acl.srcip3);
		formDisable(document.qos_acl.srcip_mask);
	}
	else{
		formEnable(document.qos_acl.srcip0);
		formEnable(document.qos_acl.srcip1);
		formEnable(document.qos_acl.srcip2);
		formEnable(document.qos_acl.srcip3);
		formEnable(document.qos_acl.srcip_mask);
	}

//	document.qos_acl.srcipv6_use.checked = false;
}

function toggle_l2SrcIpv6()
{
	if (document.qos_acl.srcipv6_use.checked == false){
		formDisable(document.qos_acl.srcipv6);
		formDisable(document.qos_acl.srcipv6_mask);
	}
	else{
		formEnable(document.qos_acl.srcipv6);
		formEnable(document.qos_acl.srcipv6_mask);
	}

//	document.qos_acl.srcip_use.checked = false;
}

function toggle_l2SrcPort()
{
	if (document.qos_acl.srcport_use.checked == false){
		formDisable(document.qos_acl.srcport0);
		formDisable(document.qos_acl.srcport1);
	}
	else{
		formEnable(document.qos_acl.srcport0);
		formEnable(document.qos_acl.srcport1);
	}
}

function toggle_l2DstIp()
{
	if (document.qos_acl.dstip_use.checked == false){
		formDisable(document.qos_acl.dstip0);
		formDisable(document.qos_acl.dstip1);
		formDisable(document.qos_acl.dstip2);
		formDisable(document.qos_acl.dstip3);
		formDisable(document.qos_acl.dstip_mask);
	}
	else{
		formEnable(document.qos_acl.dstip0);
		formEnable(document.qos_acl.dstip1);
		formEnable(document.qos_acl.dstip2);
		formEnable(document.qos_acl.dstip3);
		formEnable(document.qos_acl.dstip_mask);
	}

//	document.qos_acl.dstipv6_use.checked = false;
}

function toggle_l2DstIpv6()
{
	if (document.qos_acl.dstipv6_use.checked == false){
		formDisable(document.qos_acl.dstipv6);
		formDisable(document.qos_acl.dstipv6_mask);
	}
	else{
		formEnable(document.qos_acl.dstipv6);
		formEnable(document.qos_acl.dstipv6_mask);
	}

//	document.qos_acl.dstip_use.checked = false;
}

function toggle_onload()
{
	toggle_l2DstIp();
	toggle_l2DstIpv6();
	toggle_l2SrcIp();
	toggle_l2SrcIpv6();
}

function toggle_l2DstPort()
{
	if (document.qos_acl.dstport_use.checked == false){
		formDisable(document.qos_acl.dstport0);
		formDisable(document.qos_acl.dstport1);
	}
	else{
		formEnable(document.qos_acl.dstport0);
		formEnable(document.qos_acl.dstport1);
	}
}

function toggle_l1Priority()
{
	if (document.qos_acl.l2priority_flag.checked == false){
		formDisable(document.qos_acl.l2priority);
	}
	else{
		formEnable(document.qos_acl.l2priority);
	}
}

function toggle_l1Vlan()
{
	if (document.qos_acl.vlan_flag.checked == false){
		formDisable(document.qos_acl.vlan_value);
	}
	else{
		formEnable(document.qos_acl.vlan_value);
	}
}

function toggle_l1Port()
{
	if (document.qos_acl.physical_use.checked == false){
		formDisable(document.qos_acl.physical_port);
	}
	else{
		formEnable(document.qos_acl.physical_port);
	}
}

function onload_func()
{
	change_physical();
	change_macfilter();
	change_ether();
//	toggle_l1Port();
	toggle_l1Vlan();
	toggle_l1Priority();
	toggle_l2Protocol();
//	toggle_l2Tos();
	toggle_l2Dscp();
	toggle_l2SrcIp();
//	toggle_l2SrcIpv6();
	toggle_l2SrcPort();
	toggle_l2DstIp();
//	toggle_l2DstIpv6();
	toggle_l2DstPort();
//	changeRule();
}
function change_action()
{
	if (document.qos_acl.qos_action[0].checked == true){
		document.qos_acl.qos_action[1].disabled = true;
		document.qos_acl.qos_action[2].disabled = true;
		document.qos_acl.qos_action[3].disabled = true;
	}else{
		document.qos_acl.qos_action[1].disabled = false;
		document.qos_acl.qos_action[2].disabled = false;
		document.qos_acl.qos_action[3].disabled = false;
	}
	if(document.qos_acl.qos_action[1].checked == true || document.qos_acl.qos_action[2].checked == true || document.qos_acl.qos_action[3].checked == true){
		document.qos_acl.qos_action[0].disabled = true;
	}else{
		document.qos_acl.qos_action[0].disabled = false;
	}
	if(document.qos_acl.qos_action[1].checked == true){
		document.qos_acl.iprio.disabled = false;
	}else{
		document.qos_acl.iprio.disabled = true;
	}
	if(document.qos_acl.qos_action[2].checked == true){
		document.qos_acl.premark.disabled = false;
	}else{
		document.qos_acl.premark.disabled = true;
	}
	if(document.qos_acl.qos_action[3].checked == true){
		document.qos_acl.dscp_remark.disabled = false;
	}else{
		document.qos_acl.dscp_remark.disabled = true;
	}
}
var colorEnabled = '#ffffff';
var colorEnabledText = '#000000';
var colorDisabled = '#e6e6e6';
var colorDisabledText = '#b2b29f';

function frm_disable(e) {
	e = $(e);
	e.prop("disabled",true);
	e.css({"background-color":colorDisabled,"color":colorDisabledText});
}

function frm_enable(e) {
	e = $(e);
	e.prop("disabled",false);
	e.css({"background-color":colorEnabled,"color":colorEnabledText});
}
var changeRule = function(){
	var mode = $("[name=ipmode]:checked").val();
	$("#vlan_flag,#l2priority_flag").prop("checked",false);
	$("#protocol_use,#dscp_use,#srcip_use").prop("checked",false);
	$("#srcport_use,#dstip_use,#dstport_use").prop("checked",false);
	$("#vlan_value").val("");
	$("#l2priority").val("0");
//	frm_disable("#l2priority");
//	frm_disable("#vlan_value");
	
	if(mode == "mac"){
		$(".ip").hide();
		$(".mac").show();
	}else{
		$(".ip").show();
		$(".mac").hide();
		
	}
	onload_func();
}
var port_to_bit = function(){
	var wan = $("#wan_port").prop("checked") ? "1" : "0";
	var lan1 = $("#lan1_port").prop("checked") ? "1" : "0";
	var lan2 = $("#lan2_port").prop("checked") ? "1" : "0";
	var lan3 = $("#lan3_port").prop("checked") ? "1" : "0";
	var lan4 = $("#lan4_port").prop("checked") ? "1" : "0";
//	111110
	var bin = lan4 + lan3 + lan2 + lan1 + wan + "0";
	var hex = "0x"+parseInt(bin,2).toString(16);
	return hex;
}
function bit_for_mask(maskSize) {

	var rtn = int_to_ip(ip_to_int("255.255.255.255") - ((1<<(32-maskSize))-1));
    return rtn;
}
var change_physical = function(){
	if($("#physical_use").prop("checked") == true){
		$("#mac_start_use").prop("disabled",true);
		$("#mac_start").prop("disabled",true);
		$("#mac_end_use").prop("disabled",true);
		$("#mac_end").prop("disabled",true);
	}else{
		$("#mac_start_use").prop("disabled",false);
		$("#mac_start").prop("disabled",false);
		$("#mac_end_use").prop("disabled",false);
		$("#mac_end").prop("disabled",false);
	}
}
var change_macfilter = function(){
	if($("#mac_start_use").prop("checked") == true || $("#mac_end_use").prop("checked") == true){
		$("#physical_use").prop("disabled",true);
		$("#mac_start").prop("disabled",false);
	}else{
		$("#physical_use").prop("disabled",false);
		
	}
	if($("#mac_start_use").prop("checked") == true){
		$("#mac_start").prop("disabled",false);
	}else{
		$("#mac_start").prop("disabled",true);
	}
	if($("#mac_end_use").prop("checked") == true){
		$("#mac_end").prop("disabled",false);
	}else{
		$("#mac_end").prop("disabled",true);
	}
}
var change_ether = function(){
	if($("#ether_use").prop("checked") == true){
		$("#ether").prop("disabled",false);
	}else{
		$("#ether").prop("disabled",true);
	}
}
var proc = "proc/skb_qosacl_proc.php";
var save_data = function(){
/*
	vlan_flag
	protocol_use
	l2priority_flag
	dscp_use
	srcip_use
	srcport_use
	dstip_use
	dstport_use
*/
	var rule_type_ = $("[name=ipmode]:checked").val();
	var ck = false;
	var ck2 = false;
	var packet_drop_ = "no";
	var rule_id = $("#rule_id").val();
	var vlan_id = "";
	var vlan_priority_ = "";
	var phy = "";
	var mac_start_use = "";
	var mac_start = "";
	var mac_end_use = "";
	var mac_end = "";
	var ether_use = "";
	var ether = "";
	var iprio = "";
	var premark = "";
	var dscp_remark = "";
	var protocol_use = "";
	var protocol_val = "";
	var tos = "";
	var dscp = "";
	var srcip = "";
	var srcmask = "";
	var srcport = "";
	var dstip = "";
	var dstmask = "";
	var dstport = "";
	if($("#vlan_flag").prop("checked") == true || $("#l2priority_flag").prop("checked") == true){
		ck = true
	}
	if($("#protocol_use").prop("checked") == true || $("#dscp_use0").prop("checked") == true || $("#physical_use").prop("checked") == true ||
		$("#mac_start_use").prop("checked") == true || $("#mac_end_use").prop("checked") == true || $("#ether_use").prop("checked") == true ||
		$("#dscp_use1").prop("checked") == true ||
		$("#srcip_use").prop("checked") == true || $("#srcport_use").prop("checked") == true ||
		$("#dstip_use").prop("checked") == true || $("#dstport_use").prop("checked") == true){
		ck2 = true;
	}
	if($("#physical_use").prop("checked") == true){
		phy = "1";
	}
	if($("#mac_start_use").prop("checked") == true){
		mac_start_use = "1";
		mac_start = $("#mac_start").val();
		if(!validation_mac(mac_start)){
			alert("MAC 주소가 올바르지 않습니다. 16진수 콜론(:)을 포함한 17자리를 입력하여 주십시오.");
			$("#mac_start").focus();
			return;
		}
		mac_start.replace(/\:/gi,"-");
	}
	if($("#mac_end_use").prop("checked") == true){
		mac_end_use = "1";
		mac_end = $("#mac_end").val();
		if(!validation_mac(mac_end)){
			alert("MAC 주소가 올바르지 않습니다. 16진수 콜론(:)을 포함한 17자리를 입력하여 주십시오.");
			$("#mac_end").focus();
			return;
		}
		mac_end.replace(/\:/gi,"-");
	}
	if($("#ether_use").prop("checked") == true){
		ether_use = "1";
		ether = $("#ether").val();
		if(checkHex(ether) == false){
			alert("16진수를 입력하여 주십시오.");
			$("#ether").focus();
			return;
		}
		ether = "0000" + ether;
		ether = ether.substr(-4);
		ether = "0x"+ether;
	}
	if($("#qos_action0").prop("checked") == true){
		packet_drop_ = "yes";
	}
	if($("#qos_action1").prop("checked") == true){
		iprio = $("#iprio").children(":selected").val();
	}
	if($("#qos_action2").prop("checked") == true){
		premark = $("#premark").children(":selected").val();
	}
	if($("#qos_action3").prop("checked") == true){
		dscp_remark = $("#dscp_remark").val();
	}
	if(port_to_bit() == "0x0"){
		alert("적용할 포트를 선택하세요.");
		return;
	}
	if(ck == false && ck2 == false){
		alert("입력 할 값이 없습니다.");
		return false;
	}
	if($("#vlan_flag").prop("checked") == true){
		vlan_id = $("#vlan_value").val();
		if(vlan_id == ""){
			alert("VID를 입력해주세요.");
			$("#vlan_value").focus();
			return false;
		}
	}
	if($("#l2priority_flag").prop("checked") == true){
		vlan_priority_ = $("#l2priority").children(":selected").val();
	}
	if($("#protocol_use").prop("checked") == true){
		protocol_val = "0x"+$("#etc_proto_value").val();
		if($("#etc_proto_value").val() == ""){
			alert("프로토콜을 입력해주세요.");
			return false;
		}
	}
	if($("#dscp_use0").prop("checked") == true){
		tos = "0x"+$("#tos_value").val();
		if(tos == "0x"){
			alert("ToS를 입력해주세요.");
			return false;
		}
	}
	if($("#dscp_use1").prop("checked") == true){
		dscp = $("#dscp_value").val();
		if(dscp == ""){
			alert("DSCP를 입력해주세요.");
			return false;
		}
		dscp = Number(dscp) << 2;
		dscp = "0x"+dscp.toString(16);
	}
	if($("#srcip_use").prop("checked") == true){
		if ( (document.qos_acl.srcip0.value == "")
			|| (document.qos_acl.srcip1.value == "")
			|| (document.qos_acl.srcip2.value == "")
			|| (document.qos_acl.srcip3.value == "")
			|| (document.qos_acl.srcip_mask.value == "")){
			alert("출발지 IP 또는 Mask가 비어있습니다...");
			return;
		} else {
			srcip = document.qos_acl.srcip0.value + "."
					+ document.qos_acl.srcip1.value + "."
					+ document.qos_acl.srcip2.value + "."
					+ document.qos_acl.srcip3.value;

			if (!checkIpV4(srcip)) {
				alert("출발지 IP 주소가 올바르지 않습니다");
				return;
			}

			if (!IsDigit(document.qos_acl.srcip_mask.value)) {
           		alert('출발지 IP 마스크 값은 숫자만 입력하세요.');
           		document.qos_acl.srcip_mask.focus();
				return;
        	}

			var srcip_mask_val = parseInt(document.qos_acl.srcip_mask.value);
			if (srcip_mask_val < 1 || srcip_mask_val > 32) {
				flag += 1;
				alert("소스 IP 마스크가 올바르지 않습니다");
				document.qos_acl.srcip_mask.focus();
				return;
			}
		}
		srcmask = bit_for_mask(srcip_mask_val);
	}
	if($("#srcport_use").prop("checked") == true){
		
		if (document.qos_acl.srcport0.value == ""){
			alert("출발지 포트 값이 비어있습니다...");
			return;
		}
		srcport = parseInt($("#srcport0").val(),10);
		if ( srcport > 65535){
			alert("출발지 포트 값이 올바르지 않습니다...");
			return;
		}
		
	}
	if($("#dstip_use").prop("checked") == true){
		if ( (document.qos_acl.dstip0.value == "")
			|| (document.qos_acl.dstip1.value == "")
			|| (document.qos_acl.dstip2.value == "")
			|| (document.qos_acl.dstip3.value == "")
			|| (document.qos_acl.dstip_mask.value == "")){
			alert("목적지 IP 또는 Mask가 비어있습니다...");
			return;
		} else {
			dstip = document.qos_acl.dstip0.value + "."
					+ document.qos_acl.dstip1.value + "."
					+ document.qos_acl.dstip2.value + "."
					+ document.qos_acl.dstip3.value;

			if (!checkIpV4(dstip)) {
				alert("목적지 IP 주소가 올바르지 않습니다");
				return;
			}

			if (!IsDigit(document.qos_acl.dstip_mask.value)) {
				alert('목적지 IP 마스크 값은 숫자만 입력하세요.');
				return;
			}

			var dstip_mask_val = parseInt(document.qos_acl.dstip_mask.value);
			if (dstip_mask_val < 1 || dstip_mask_val > 32) {
				alert("목적지 IP 마스크가 올바르지 않습니다");
				return;
			}
		}
		dstmask = bit_for_mask(dstip_mask_val);
	}
	if($("#dstport_use").prop("checked") == true){
		
		if (document.qos_acl.dstport0.value == ""){
			alert("목적지 포트 값이 비어있습니다...");
			return;
		}
		dstport = parseInt($("#dstport0").val(),10);
		if ( dstport > 65535){
			alert("목적지 포트 값이 올바르지 않습니다...");
			return;
		}
		
	}
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'rule_add';
	sobj['rule_id'] = rule_id;
	sobj['rule_type'] = rule_type_;
	sobj["packet_drop"] = packet_drop_;
	sobj["port_bitmap"] = port_to_bit();
	if(vlan_id != ""){
		sobj["vlan_id"] = vlan_id;
	}
	if(vlan_priority_ != ""){
		sobj["vlan_priority"] = vlan_priority_;
	}
	if(phy != ""){
		sobj["phy_port"] = phy;
		if(iprio == "" && packet_drop_ == "no"){
			alert("ACTION를 선택해주세요.");
			return;
		}
	}
	if(mac_start_use != ""){
		sobj["mac_start_use"] = mac_start_use;
		sobj["mac_start"] = mac_start;
	}
	if(mac_end_use != ""){
		sobj["mac_end_use"] = mac_end_use;
		sobj["mac_end"] = mac_end;
	}
	if(ether_use != ""){
		sobj['ether_use'] = ether_use;
		sobj['ether'] = ether;
	}
	if(protocol_val != ""){
		sobj["ip_protocol"] = protocol_val;
	}
	if(tos != ""){
		sobj["ip_tos"] = tos;
	}
	if(dscp != ""){
		sobj["ip_dscp"] = dscp;
		sobj["ip_tos"] = "";
	}
	if(srcip != ""){
		sobj["srcip"] = srcip;
		sobj["srcmask"] = srcmask;
	}
	if(dstip != ""){
		sobj["dstip"] = dstip;
		sobj["dstmask"] = dstmask;
	}
	if(srcport != ""){
		sobj["srcport"] = srcport;
	}
	if(dstport != ""){
		sobj["dstport"] = dstport;
	}


	if(iprio != ""){
		sobj["iprio"] = iprio;
	}
	if(premark != ""){
		sobj["premark"] = premark;
	}
	if(dscp_remark != ""){
		sobj["dscp_remark"] = dscp_remark;
	}
	
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
//			console.log(d);
			$("#rule_id").val(rule_id+1);
			alert("추가되었습니다.");
			location.reload();
		}
	});
}
var rule_list_delete = function(){
	dummyVal = CreateDummy();
	var tobj = $("[name=qlist]:checked");
	var dellist = "";
	for (var i=0;i < tobj.length ; i++)
	{
		dellist += "," + tobj[i].value;
	}
	if(dellist != ""){
		dellist = dellist.substring(1,dellist.length);
	}
	if(dellist == ""){
		alert("삭제 할 룰을 선택해주세요.");
		return;
	}
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'rule_del';
	sobj['dellist'] = dellist;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
//			console.log(d);
//			$("#rule_id").val(rule_id+1);
			alert("삭제되었습니다.");
			location.reload();
		}
	});
}
var apply_data = function(){
	if(!confirm("적용하시겠습니가?\n 네트워크가 재시작됩니다.")){
		return;
	}
	document.qos_acl.submit();
}
$(document).ready(function(){
	$("[name=ipmode]").eq(0).prop("checked",true);
	$(".mac").hide();
	onload_func();
});
</script>
</head>

<body onLoad="">
<blockquote>
<h2>Rules 설정</h2>
<table border=0 width="600" cellspacing="4" cellpadding="0">
<tr><td><font size=2>
 Qos Rules 설정을 위한 페이지입니다.
</font></td></tr>
<tr><td><hr size=1 noshade align="top"></td></tr>
</table>

<form action="proc/skb_qosacl_proc.php" method="POST" name="qos_acl">
<input type="hidden" name="act" id="act" value="qos_apply">
<input type="hidden" name="submit-url" id="submit-url" value="/skb_qosacl.php">
<input type="hidden" name="rule_id" id="rule_id" value="<?=$rule_id?>">
<table cellspacing="1" cellpadding="2" border="0" width="600">
	<tr>
		<td bgcolor="#aaddff" align="center" width="105"><b>IP Mode</b></td>
		<td bgcolor="#DDDDDD">
			<input type="radio" name="ipmode" id="ipmode0" value="ip4" onchange="changeRule();"> IPv4&nbsp;&nbsp;
			<input type="radio" name="ipmode" id="ipmode1" value="ip6" onchange="changeRule();"> IPv6
			<input type="radio" name="ipmode" id="ipmode2" value="mac" onchange="changeRule();"> MAC
		</td>
	</tr>
</table>
<br><br>
<table cellspacing="1" cellpadding="2" border="0" width="600">

	<tr>
		<td bgcolor="#aaddff" align="center" width="105"><b>포트</b></td>
		<td bgcolor="#DDDDDD" width="495"><input type="checkbox" name="wan_port" id="wan_port" value="1">WAN<?php
			for($i=1; $i < 5;$i++){
		?><input type="checkbox" name="lan<?=$i?>_port" id="lan<?=$i?>_port" value="1" onclick="port_to_bit()">LAN <?=$i?><?}?></td>
	</tr>
	<tr class="mac">
		<th bgcolor="#aaddff" align="center">Physical 포트</th>
		<td bgcolor="#DDDDDD">
		<input style="left:10px;top:40px;" type="checkbox" value="1" name="physical_use" id="physical_use" onchange="change_physical();">Physical 포트&nbsp;</td>
  	</tr>
	<tr class="mac">
		<th bgcolor="#aaddff" align="center" rowspan="2">MAC Filter</th>
		<td vAlign="center" bgcolor="#DDDDDD"><input style="left:10px;top:40px;" type="checkbox" value="1" name="mac_start_use" id="mac_start_use" onchange="change_macfilter();">출발지 MAC&nbsp;<input type="text" name="mac_start" id="mac_start" value="" maxlength="17"></td>
	</tr>
	<tr class="mac">
		<td vAlign="center" bgcolor="#DDDDDD"><input style="left:10px;top:40px;" type="checkbox" value="1" name="mac_end_use" id="mac_end_use" onchange="change_macfilter();">목적지 MAC&nbsp;<input type="text" name="mac_end" id="mac_end" value="" maxlength="17"></td>
	</tr>
	<tr class="mac">
		<th bgcolor="#aaddff" align="center">EtherType Filter</th>
		<td vAlign="center" bgcolor="#DDDDDD"><input style="left:10px;top:40px;" type="checkbox" value="1" name="ether_use" id="ether_use" onchange="change_ether();">EtherType Filter&nbsp;&nbsp;0x<input type="text" name="ether" id="ether" value="" maxlength="4" onkeydown="xnum_check(event);"></td>
<!-- 		<select name="ether" id="ether"> -->
<!-- 			<option value="0x0800">IP</option> -->
<!-- 			<option value="0x0806">ARP</option> -->
<!-- 		</select> -->
	</tr>
	<tr class="mac">
		<th bgcolor="#aaddff" align="center">VLAN</th>
		<td vAlign="center" bgcolor="#DDDDDD">
			<input type="checkbox" name="vlan_flag" id="vlan_flag" value="1" style="left:10px;top:40px" onclick="toggle_l1Vlan();">VID&nbsp;&nbsp;&nbsp;&nbsp;
			<input type="text" name="vlan_value" id="vlan_value" value="" style="width:72px;height:22px" size="9" onkeydown="num_check(event);" maxLength="4"><br>
			<input type="checkbox" name="l2priority_flag" id="l2priority_flag" value="1" style="left:10px;top:40px" onclick="toggle_l1Priority();">Priority
			&nbsp;&nbsp;
			<select name="l2priority" id="l2priority">
				<option value="0">0</option>
				<option value="1">1</option>
				<option value="2">2</option>
				<option value="3">3</option>
				<option value="4">4</option>
				<option value="5">5</option>
				<option value="6">6</option>
				<option value="7">7</option>
			</select>
		</td>
	</tr>
	<tr class="ip">
		<th bgcolor="#aaddff" align="center" >프로토콜</th>
		<td bgcolor="#DDDDDD">
			<input type="checkbox" name="protocol_use" id="protocol_use" onclick="toggle_l2Protocol();" value="1">프로토콜&nbsp;&nbsp;0x&nbsp;<input type="text" name="etc_proto_value" id="etc_proto_value" value="" size="6" maxlength="2" onkeydown="xnum_check(event);">
		</td></tr>
	<tr class="ip">
		<th bgcolor="#aaddff" align="center">Tos</th>
		<td bgcolor="#DDDDDD">
			<input onclick="toggle_l2Dscp();" type="radio" name="dscp_use" id="dscp_use0" value="1"> Tos&nbsp;
			0x&nbsp;<input style="left:105px;width:32px;top:16px;height:22px;" maxLength="2" size="8" name="tos_value" id="tos_value" onkeydown="xnum_check(event);">
		</td>
	</tr>
	<tr class="ip">
		<th bgcolor="#aaddff" align="center">DSCP</th>
		<td bgcolor="#DDDDDD">
			<input onclick="toggle_l2Dscp();" type="radio" name="dscp_use" id="dscp_use1" value="1"> DSCP&nbsp;
			<input style="left:105px;width:32px;top:16px;height:22px;" maxLength="2" size="8" name="dscp_value" id="dscp_value" onkeydown="num_check(event);">
		</td>
	</tr>
	<tr class="ip">
		<th bgcolor="#aaddff" align="center" vAlign="center"><p align="center">출발지</p></th>
		<td bgcolor="#DDDDDD">
			<input type="checkbox" name="srcip_use" id="srcip_use" value="1" onclick="toggle_l2SrcIp();" onchange="toggle_l2SrcIp();">출발지 IP 주소/길이 &nbsp;&nbsp;&nbsp;&nbsp;
			<input type="text" maxLength="3" size="3" name="srcip0" onkeydown="num_check(event);">.
			<input type="text" maxLength="3" size="3" name="srcip1" onkeydown="num_check(event);">.
			<input type="text" maxLength="3" size="3" name="srcip2" onkeydown="num_check(event);">.
			<input type="text" maxLength="3" size="3" name="srcip3" onkeydown="num_check(event);">&nbsp;/&nbsp;
			<input type="text" name="srcip_mask" id="srcip_mask" value="" maxlength="2" size="3" onkeydown="num_check(event);"><br>

			<input type="checkbox" value="1" name="srcport_use" id="srcport_use" onclick="toggle_l2SrcPort();">출발지 포트&nbsp;&nbsp;&nbsp;&nbsp;
			<input type="text" name="srcport0" id="srcport0" maxLength="5" size="8" onkeydown="num_check(event);">&nbsp;
<!-- 			<input type="text" name="srcport1" id="srcport1" maxLength="5" size="8" onkeydown="num_check(event);"><br> -->
<!-- 			<input type="checkbox" name="srcipv6_use" value="1" onclick="toggle_l2SrcIpv6();" onchange="toggle_l2SrcIpv6();">출발지 IPv6 주소/길이 &nbsp;&nbsp; -->
<!-- 			<input type="text" maxlength="39" size="32" name="srcipv6">&nbsp;/&nbsp; -->
<!-- 			<input type=text name="srcipv6_mask" maxlength=3 size=3 onkeydown="num_check(event);"><br> -->
		</td>
	</tr>
	<tr class="ip">
		<th bgcolor="#aaddff" align="center" vAlign="center"><P>목적지</P></th>
		<td bgcolor="#DDDDDD"><p>
			<input type="checkbox" name="dstip_use" id="dstip_use" value="1" onclick="toggle_l2DstIp();" onchange="toggle_l2DstIp();">목적지 IP 주소/길이&nbsp;&nbsp;&nbsp;&nbsp;
			<input type="text" name="dstip0" id="dstip0" value="" maxLength="3" size="3" onkeydown="num_check(event);">.
			<input type="text" name="dstip1" id="dstip1" value="" maxLength="3" size="3" onkeydown="num_check(event);">.
			<input type="text" name="dstip2" id="dstip2" value="" maxLength="3" size="3" onkeydown="num_check(event);">.
			<input type="text" name="dstip3" id="dstip3" value="" maxLength="3" size="3" onkeydown="num_check(event);">&nbsp;/&nbsp;
			<input type="text" name="dstip_mask" id="dstip_mask" value="" maxlength="3" size="3" onkeydown="num_check(event);"><br>

			<input type="checkbox" name="dstport_use" id="dstport_use" value="1" onclick="toggle_l2DstPort();">목적지 포트&nbsp;&nbsp;&nbsp;&nbsp;
			<input type="text" name="dstport0" id="dstport0" value="" maxLength="5" size="8" onkeydown="num_check(event);">&nbsp;
<!-- 			<input type="text" name="dstport1" id="dstport1" value="" maxLength="5" size="8" onkeydown="num_check(event);"><br> -->

<!-- 			<input type="checkbox" name="dstipv6_use" value="1" onclick="toggle_l2DstIpv6();" onchange="toggle_l2DstIpv6();">목적지 IPv6 주소/길이 &nbsp;&nbsp; -->
<!-- 			<input type="text" maxLength="39" size="32" name="dstipv6">&nbsp;/&nbsp; -->
<!-- 			<input type=text name="dstipv6_mask" maxlength=3 size=3 onkeydown="num_check(event);"><br> -->
		</P></td>
	</tr>
	<tr>
		<td colspan="2">&nbsp;</td>
	</tr>
	<tr>
		<th bgcolor="#aaddff" align="center">ACTION</th>
		<td colspan='3' bgcolor="#DDDDDD">
		<input type="checkbox" name="qos_action" id="qos_action0" value="0" onclick="change_action();"> 차단<br>
		<input type="checkbox" name="qos_action" id="qos_action1" value="1" onclick="change_action();"> Internal Priority
		<select name="iprio" id="iprio" disabled>
			<option value="7">7</option>
			<option value="6">6</option>
			<option value="5">5</option>
			<option value="4">4</option>
			<option value="3">3</option>
			<option value="2">2</option>
			<option value="1">1</option>
			<option value="0">0</option>
		</select><br>
		<input type="checkbox" name="qos_action" id="qos_action2" value="2" onclick="change_action();"> 802.1p Priority Remarking
		<select name="premark" id="premark" disabled>
			<option value="7">7</option>
			<option value="6">6</option>
			<option value="5">5</option>
			<option value="4">4</option>
			<option value="3">3</option>
			<option value="2">2</option>
			<option value="1">1</option>
			<option value="0">0</option>
		</select><br>
		<input type="checkbox" name="qos_action" id="qos_action3" value="3" onclick="change_action();"> DSCP Remarking
		&nbsp;<input name="dscp_remark" id="dscp_remark" value="" disabled style="left:105px;width:32px;top:16px;height:22px" maxLength="2" size="8" onkeydown="num_check(event);">
		</td>
</table>
<br>
<input type="button" value="추가" onclick="save_data();"><?if($applybtn){?>
&nbsp;&nbsp;<input type="button" value="적용" onclick="apply_data();">
<?}?>
<br><br>
<table cellspacing="1" cellpadding="1" border="0">
	<tr class="tbl_head">
		<td align="center" width="40">번호</td>
		<td align="center" width="80">IP MODE</td>
		<td align="center" width="80">인터페이스</td>
		<td align="center" width="400">설명</td>
		<td align="center" width="50">선택</td>
	</tr>
<?php
	function port_convert($port_){
		$portstr = "";
		if($port_[4] == "1"){
			$portstr .= ",WAN";
		}
		if($port_[3] == "1"){
			$portstr .= ",LAN1";
		}
		if($port_[2] == "1"){
			$portstr .= ",LAN2";
		}
		if($port_[1] == "1"){
			$portstr .= ",LAN3";
		}
		if($port_[0] == "1"){
			$portstr .= ",LAN4";
		}
		$portstr = substr($portstr,1,strlen($portstr));
//		echo($portstr);
		return $portstr;
	}
	for($i=0; $i < count($aclrule); $i++){
		$rule_no = preg_replace("/[^0-9]{1,}/","",$aclrule[$i]);
		$rulelist = "";
		$ruletype = "";
		$port = "";
		$rcnt = 0;
		for($j=0; $j < count($aclrulelist); $j++){
			$first_dot = strpos($aclrulelist[$j],".")+1;
			$second_dot = strpos($aclrulelist[$j],".",$first_dot);
			if(substr($aclrulelist[$j],0,$second_dot) == $aclrule[$i]){
				if( 
					strpos( $aclrulelist[$j],"phy_mac_address" ) !== false || strpos( $aclrulelist[$j],"phy_mac_address_mask" ) !== false || 
					strpos( $aclrulelist[$j],"inverse_check_fields" ) !== false){
					//Igonre
				}elseif( strpos( $aclrulelist[$j],"rule_type" ) === false && strpos( $aclrulelist[$j],"port_bitmap" ) === false){
					$tmp = str_replace($aclrule[$i].".","",$aclrulelist[$j]);
					if($rcnt % 2 == 0){
						$rulelist .= " ". $tmp;
					}else{
						$rulelist .= " ". $tmp."<br>";
					}
					$rcnt++;
				}elseif(strpos( $aclrulelist[$j],"port_bitmap" ) !== false){
					$port = str_replace("'","",str_replace("port_bitmap=","",str_replace($aclrule[$i].".","",$aclrulelist[$j])));
					$port = port_convert(substr("000000".decbin(hexdec($port)),-6));
				}else{
					$ruletype = str_replace("'","",str_replace("rule_type=","",str_replace($aclrule[$i].".","",$aclrulelist[$j])));
				}
			}
		}
		
?>
	<tr bgcolor="#DDDDDD">
		<td align="center"><?=$rule_no?></td>
		<td align="center"><?=$ruletype?></td>
		<td align="center"><?=$port?></td>
		<td><?=$rulelist?></td>
		<td align="center"><input type='checkbox' name='qlist' id="qlist<?=$i?>" value='<?=$aclrule[$i]?>'></td>
	</tr>
<?
	}
?>
	
</table><br>
<input type="button" value="삭제" name="delete" onclick="rule_list_delete();" >
<input type="button" value="전체 선택" onclick="select_all();">
<input type="button" value="전체 선택해제" onclick="unselect_all();">
</form>
</blockquote>
</body>
</html>

