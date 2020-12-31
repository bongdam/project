<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	check_admin($isAdmin );
	$uci = new uci();
	$uci->mode("get");
	$uci->get("firewall.dos_config");
	$uci->run();
	$dos = json_decode($uci->result(),true);
	$fw_enabled = $dos["firewall.dos_config.enabled"];
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>DoS 설정 </title>
<style>
.on {display:on}
.off {display:none}
</style>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var dosinfo = <?=json_encode($dos)?>;
var proc = "proc/skb_dos_proc.php";
function inputEnabledClick(){
//	if(document.formDosCfg.input_policy_accept.checked) {
//		enableTextField(document.formDosCfg.snmp_input_rate);
//		document.formDosCfg.input_policy_accept.checked = true;
//	} else {
//		document.formDosCfg.snmp_input_rate.value = 0;
//		disableTextField(document.formDosCfg.snmp_input_rate);
//		document.formDosCfg.input_policy_accept.checked = false;
//	}
}
function dosEnabledClick(){
	if(document.formDosCfg.dosEnabled.checked){
		enableTextField(document.formDosCfg.sysfloodSYN);
		enableTextField(document.formDosCfg.sysfloodSYNcount);
		enableTextField(document.formDosCfg.TCPUDPPortScan);
//		enableTextField(document.formDosCfg.portscanSensi);
		enableTextField(document.formDosCfg.ICMPSmurfEnabled);
		enableTextField(document.formDosCfg.IPSpoofEnabled);
		enableTextField(document.formDosCfg.PingOfDeathEnabled);
        //enableTextField(document.formDosCfg.sourceIPblock);
		//enableTextField(document.formDosCfg.IPblockTime);
		enableTextField(document.formDosCfg.pingSecEnabled);
		enableTextField(document.formDosCfg.pingSecCount);
		enableTextField(document.formDosCfg.TraceRtEnabled);
        //enableTextField(document.formDosCfg.DNSRelayEnabled);
		//enableTextField(document.formDosCfg.NTPDefEnabled);
	}
	else{
		document.formDosCfg.sysfloodSYN.checked=0;
		document.formDosCfg.TCPUDPPortScan.checked=0;
		document.formDosCfg.ICMPSmurfEnabled.checked=0;
		document.formDosCfg.IPSpoofEnabled.checked=0;
		document.formDosCfg.PingOfDeathEnabled.checked=0;
        //document.formDosCfg.sourceIPblock.checked=0;
		document.formDosCfg.pingSecEnabled.checked=0;
		document.formDosCfg.TraceRtEnabled.checked=0;
        //document.formDosCfg.DNSRelayEnabled.checked=0;
        //document.formDosCfg.NTPDefEnabled.checked=0;

		
		
		disableTextField(document.formDosCfg.sysfloodSYN);
		disableTextField(document.formDosCfg.sysfloodSYNcount);
		disableTextField(document.formDosCfg.TCPUDPPortScan);
//		disableTextField(document.formDosCfg.portscanSensi);
		disableTextField(document.formDosCfg.ICMPSmurfEnabled);
		disableTextField(document.formDosCfg.IPSpoofEnabled);
		disableTextField(document.formDosCfg.PingOfDeathEnabled);
		//disableTextField(document.formDosCfg.sourceIPblock);
		//disableTextField(document.formDosCfg.IPblockTime);
		disableTextField(document.formDosCfg.pingSecEnabled);
		disableTextField(document.formDosCfg.pingSecCount);
		disableTextField(document.formDosCfg.TraceRtEnabled);
        //disableTextField(document.formDosCfg.DNSRelayEnabled);
		//disableTextField(document.formDosCfg.NTPDefEnabled);
	}
}

function SelectAll(){
	if(document.formDosCfg.dosEnabled.checked){
		document.formDosCfg.sysfloodSYN.checked=1;
		document.formDosCfg.TCPUDPPortScan.checked=1;
		document.formDosCfg.ICMPSmurfEnabled.checked=1;
		document.formDosCfg.IPSpoofEnabled.checked=1;
		document.formDosCfg.PingOfDeathEnabled.checked=1;
		document.formDosCfg.pingSecEnabled.checked=1;
		document.formDosCfg.TraceRtEnabled.checked=1;
        //document.formDosCfg.DNSRelayEnabled.checked=1;
        //document.formDosCfg.NTPDefEnabled.checked=1;
	}
}

function ClearAll(){
	if(document.formDosCfg.dosEnabled.checked){
		document.formDosCfg.sysfloodSYN.checked=0;
		document.formDosCfg.TCPUDPPortScan.checked=0;
		document.formDosCfg.ICMPSmurfEnabled.checked=0;
		document.formDosCfg.IPSpoofEnabled.checked=0;
		document.formDosCfg.PingOfDeathEnabled.checked=0;
		document.formDosCfg.pingSecEnabled.checked=0;
		document.formDosCfg.TraceRtEnabled.checked=0;		
        //document.formDosCfg.DNSRelayEnabled.checked=0;
        //document.formDosCfg.NTPDefEnabled.checked=0;
	}                                                       
}

function applyClick(f)
{
	var macflood_ = $("#macflood").prop("checked") ? "1" : "0";
	var macflood_limit_ = $("#macflood_limit").val();
	if(document.formDosCfg.dosEnabled.checked){
		if ( document.formDosCfg.sysfloodSYN.checked == false &&
			 document.formDosCfg.TCPUDPPortScan.checked == false &&
			 document.formDosCfg.ICMPSmurfEnabled.checked == false &&
			 document.formDosCfg.IPSpoofEnabled.checked == false &&
			 document.formDosCfg.PingOfDeathEnabled.checked == false &&
			 document.formDosCfg.pingSecEnabled.checked == false &&
			 document.formDosCfg.TraceRtEnabled.checked == false ) 
             //document.formDosCfg.DNSRelayEnabled.checked == false &&
             //document.formDosCfg.NTPDefEnabled.checked == false )
        {
			 alert("Dos방어 기능 중 선택 된 항목이 없습니다.");
			 return false;
		}
	}	
	
//	if(document.formDosCfg.input_policy_accept.checked == true) {
//		document.formDosCfg.input_policy_accept.value = "1";
//	} else {
//		document.formDosCfg.input_policy_accept.value = "0";
//	}
    
    if(document.formDosCfg.ARPspoofEnabled.checked == true) {
		document.formDosCfg.ARPspoofEnabled.value = "1";
	} else {
		document.formDosCfg.ARPspoofEnabled.value = "0";
	}

/*
    if(document.formDosCfg.DNSRelayEnabled.checked == true) {
        document.formDosCfg.DNSRelayEnabled.value = "ON";
    } else {
        document.formDosCfg.DNSRelayEnabled.value = "OFF";
    }

    if(document.formDosCfg.NTPDefEnabled.checked == true) {
        document.formDosCfg.NTPDefEnabled.value = "ON";
    } else {
        document.formDosCfg.NTPDefEnabled.value = "OFF";
    }
*/
	if(macflood_ == "1"){
		if($("#macflood_limit").val() == ""){
			alert("CPU 인입 이상 트래픽 제어의 값이 입력되지 않았습니다.");
			return;
		}
		if(isNumVal($("#macflood_limit").val()) == false){
			alert("CPU 인입 이상 트래픽 제어의 값이 올바르지 않습니다.");
			return;
		}
		if(parseInt($("#macflood_limit").val(),10) < 0){
			alert("CPU 인입 이상 트래픽 제어의 값이 올바르지 않습니다.");
			return;
		}
	}
	var input_rate1 = trim(f.dns_input_rate.value);
	if (input_rate1 == "") {
		alert('DNS Relay 인입 허용 Rate의 값이 입력되지 않았습니다. 0 ~ 1000 사이의 숫자를 입력 해 주세요.');
		return false;
	}

	var rate1 = parseInt(input_rate1);
	if ( rate1 < 0 || rate1 > 1000 ) {
		alert('DNS Relay 인입 허용 Rate의 값이 올바르지 않습니다. 0 ~ 1000 사이의 숫자를 입력해야 합니다.');
		return false;
	}

	var input_rate2 = trim(f.ntp_input_rate.value);
	if (input_rate2 == "") {
		alert('NTP 인입 허용 Rate의 값이 입력되지 않았습니다. 0 ~ 1000 사이의 숫자를 입력 해 주세요.');
		return false;
	}

	rate2 = parseInt(input_rate2);
	if ( rate2 < 0 || rate2 > 1000 ) {
		alert('NTP 인입 허용 Rate의 값이 올바르지 않습니다. 0 ~ 1000 사이의 숫자를 입력해야 합니다.');
		return false;
	}

	var input_rate = trim(f.snmp_input_rate.value);
	if (input_rate == "") {
		alert('SNMP 인입 허용 Rate의 값이 입력되지 않았습니다. 0 ~ 1000 사이의 숫자를 입력 해 주세요.');
		return false;
	}

	var rate = parseInt(input_rate);
	if ( rate < 0 || rate > 1000 ) {
		alert('SNMP 인입 허용 Rate의 값이 올바르지 않습니다. 0 ~ 1000 사이의 숫자를 입력해야 합니다.');
		return false;
	}
	
//	var block_time = trim(f.IPblockTime.value);
//	if (block_time == "") {
//		alert('Source IP Blocking 값이 입력되지 않았습니다. 0 ~ 60000 사이의 숫자를 입력 해 주세요.');
//		return false;
//	}
//	b_time = parseInt(block_time);
//	if ( b_time < 0 || b_time > 60000 ) {
//		alert('Source IP Blocking 값이 올바르지 않습니다. 0 ~ 60000 사이의 숫자를 입력해야 합니다.');
//		return false;
//	}
	var dos_enable_ = $("#dosEnabled").prop("checked") ? "1" : "0";
	var tcpsynflood_ = $("#sysfloodSYN").prop("checked") ? "1" : "0";
	var tcpsynflood_pkt_ = $("#sysfloodSYNcount").val();
	var tcpportscan_ = $("#TCPUDPPortScan").prop("checked") ? "1": "0";
//	var tcpportscan_type_ = $("#portscanSensi").children(":selected").val();
	var icmpsmurf_ = $("#ICMPSmurfEnabled").prop("checked") ? "1" : "0";
	var ip_spoof_ = $("#IPSpoofEnabled").prop("checked") ? "1" : "0";
	var ping_of_death_ = $("#PingOfDeathEnabled").prop("checked") ? "1" : "0";
	var ping_of_sec_ = $("#pingSecEnabled").prop("checked") ? "1" : "0";
	var ping_of_sec_pkt_ = $("#pingSecCount").val();
	var traceroute_ = $("#TraceRtEnabled").prop("checked") ? "1" : "0";
	var arpspoof_ = $("#ARPspoofEnabled").prop("checked") ? "1" : "0";
	
	var dns_input_rate_ = $("#dns_input_rate").val();
	var ntp_input_rate_ = $("#ntp_input_rate").val();
	var snmp_input_rate_ = $("#snmp_input_rate").val();
//	var source_ip_block_ = $("#IPblockTime").val();
	f.enableDos.disabled="true";
//	f.submit();
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = "set_dos";
	sobj['dos_enable'] = dos_enable_;
	if(tcpsynflood_ == "1"){
		sobj['tcpsynflood'] = tcpsynflood_;
		sobj['tcpsynflood_pkt'] = tcpsynflood_pkt_;
	}
	if(tcpportscan_ == "1"){
		
		sobj['tcpportscan'] = tcpportscan_;
//		sobj['tcpportscan_type'] = tcpportscan_type_;
	}
	if(icmpsmurf_ == "1"){
		sobj['icmpsmurf'] = icmpsmurf_;
	}
	if(ip_spoof_ == "1"){
		sobj["ip_spoof"] = ip_spoof_;
	}
	if(ping_of_death_ == "1"){
		sobj['ping_of_death'] = ping_of_death_;
	}
	if(ping_of_sec_ == "1"){
		sobj['ping_of_sec'] = ping_of_sec_;
		sobj['ping_of_sec_pkt'] = ping_of_sec_pkt_;
	}
	if(traceroute_ == "1"){
		sobj['traceroute'] = traceroute_;
	}
	if(arpspoof_ == "1"){
		sobj["arpspoof"] = arpspoof_;
	}
	sobj['macflood'] = macflood_;
	if(macflood_ == "1"){
		sobj['macflood_limit'] = macflood_limit_;
	}
	sobj['ntp_input_rate'] = ntp_input_rate_;
	sobj['dns_input_rate'] = dns_input_rate_;
	sobj['snmp_input_rate'] = snmp_input_rate_;
//	sobj['source_ip_block'] = source_ip_block_;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				document.formDos.submit();
//				if(arpspoof_ != get_obj_val(dosinfo,"firewall.dos_config.arp_spoof")){
//					
//				}else{
//					alert("적용되었습니다.");
//					setTimeout(function(){
//						window.location.reload();
//					},500);
//				}
			}else{
				alert("적용되지 않았습니다.");
				return;
			}
		}
	});
}

function init()
{
	var dosEnabled="<?=$fw_enabled?>";
	var cf = document.formDosCfg;
	if(get_obj_val(dosinfo,"firewall.dos_config.enabled") == "1"){
		$("#dosEnabled").prop("checked",true);
	}else{
		$("#dosEnabled").prop("checked",false);
	}

	document.formDosCfg.dns_input_rate.value = get_obj_val(dosinfo,"firewall.dos_config.dns_relay_protect");
	document.formDosCfg.ntp_input_rate.value = get_obj_val(dosinfo,"firewall.dos_config.ntp_protect");
	document.formDosCfg.snmp_input_rate.value = get_obj_val(dosinfo,"firewall.dos_config.snmp_protect");
	if(get_obj_val(dosinfo,"firewall.dos_config.ping_limit")  == "0") {
		document.formDosCfg.pingSecEnabled.checked=0;
		disableTextField(document.formDosCfg.pingSecCount);
		document.formDosCfg.pingSecCount.value = get_obj_val(dosinfo,"firewall.dos_config.ping_rate");
	} else {
		document.formDosCfg.pingSecEnabled.checked=1;
		enableTextField(document.formDosCfg.pingSecCount);
		document.formDosCfg.pingSecCount.value = get_obj_val(dosinfo,"firewall.dos_config.ping_rate");;
	}

	if(get_obj_val(dosinfo,"firewall.dos_config.block_tracert") == "1"){
		document.formDosCfg.TraceRtEnabled.checked=1;
	} else {
		document.formDosCfg.TraceRtEnabled.checked=0;
	}
	if(get_obj_val(dosinfo,"firewall.dos_config.arp_spoof") == "1"){
		cf.ARPspoofEnabled.checked=1;
	}else{
		cf.ARPspoofEnabled.checked=0;
	}
	if(get_obj_val(dosinfo,"firewall.dos_config.macflood") == "1"){
		$("#macflood").prop("checked",true);
	}else{
		$("#macflood").prop("checked",false);
	}
	$("#macflood_limit").val(get_obj_val(dosinfo,"firewall.dos_config.macflood_limit"));

//	if(get_obj_val(dosinfo,"firewall.dos_config.block_tracert") == "1"){
//		document.formDosCfg.ARPspoofEnabled.checked=0;
//	} else {
//		document.formDosCfg.ARPspoofEnabled.checked=1;
//	}
//	if(0 == 0) {
//		cf.input_policy_accept.checked = 0;
//	} else {
//		cf.input_policy_accept.checked = 1;
//	}
   /*
      if(0 == 0) {
      document.formDosCfg.DNSRelayEnabled.checked=0;
      } else {
      document.formDosCfg.DNSRelayEnabled.checked=1;
      }

      if(0 == 0) {
      document.formDosCfg.NTPDefEnabled.checked=0;
      } else {
      document.formDosCfg.NTPDefEnabled.checked=1;
      }
   */

//	document.formDosCfg.IPblockTime.value = get_obj_val(dosinfo,"firewall.dos_config.block_time");

	if (cf.dosEnabled.checked) {
	  	if(get_obj_val(dosinfo,"firewall.dos_config.tcpsyn_flood") == "1"){
			cf.sysfloodSYN.checked = 1;
			$("#sysfloodSYNcount").val(get_obj_val(dosinfo,"firewall.dos_config.tcpsyn_flood_rate"));
		}else{
			cf.sysfloodSYN.checked = 0;
			$("#sysfloodSYNcount").val(get_obj_val(dosinfo,"firewall.dos_config.tcpsyn_flood_rate"));
		}
		if(get_obj_val(dosinfo,"firewall.dos_config.portscan") == "1"){
			cf.TCPUDPPortScan.checked = 1;
		}else{
			cf.TCPUDPPortScan.checked = 0;
		}
//		if(get_obj_val(dosinfo,"firewall.dos_config.portscan_sense") == "high"){
//			cf.portscanSensi.selectedIndex = 1;
//		}else{
//			cf.portscanSensi.selectedIndex = 0;
//		}
		if(get_obj_val(dosinfo,"firewall.dos_config.icmp_smurf") == "1"){
			cf.ICMPSmurfEnabled.checked = 1;
		}else{
			cf.ICMPSmurfEnabled.checked = 0;
		}
		if(get_obj_val(dosinfo,"firewall.dos_config.ip_spoof") == "1"){
			cf.IPSpoofEnabled.checked = 1;
		}else{
			cf.IPSpoofEnabled.checked = 0;
		}
		if(get_obj_val(dosinfo,"firewall.dos_config.ping_of_death") == "1"){
			cf.PingOfDeathEnabled.checked = 1;
		}else{
			cf.PingOfDeathEnabled.checked = 0;
		}
		
	}
	dosEnabledClick();
}
$(document).ready(function(){
	init();
});
</script>
</head>
<body>
<blockquote>
<h2>DoS 설정</h2>
<form action="proc/skb_dos_proc.php" method="POST" name="formDosCfg">
<table border="0" width="600" cellspacing="0" cellpadding="0">
<tr>
	<td><font size="2"><br>해커의 공격으로부터 정상적인 사용자의 서비스를 보호할 수 있도록 설정하는 페이지 입니다.</font></td>
</tr>
<tr>
	<td><hr size="1" noshade align="top"></td>
</tr>
</table>
<table border="0" width="600" cellspacing="0" cellpadding="0">
	<tr>
		<td><font size="2"><b><input type="checkbox" name="dosEnabled" id="dosEnabled" value="1" onclick="dosEnabledClick()">&nbsp;&nbsp;DoS 방어 사용</b></font></td>
	</tr>
</table>
<table border="0" width="600">
	<tr style="display:on">
  		<td width="40%">&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="sysfloodSYN" id="sysfloodSYN" value="1" > <font size="2"><b> TCP Syn Flood 방어 </b></font><br></td>
		<td width="40%"><input type="text" name="sysfloodSYNcount" id="sysfloodSYNcount" size="6" maxlength="4" value="0" > <font size="2"><b> Packets/Second</b></font><br></td>
	</tr>
	<tr>
  		<td colspan="2">&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="TCPUDPPortScan" id="TCPUDPPortScan" value="1" > <font size="2"><b> TCP PortScan 방어 </b></font></td>
<!-- 		<td width="40%"><select name="portscanSensi" id="portscanSensi"> -->
<!-- 			<option value="low" >Low </option> -->
<!-- 			<option value="high" >High </option> -->
<!-- 		</select><font size="2"><b> Sensitivity </b></font></td> -->
	</tr>
	<tr>
		<td colspan="2">&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="ICMPSmurfEnabled" id="ICMPSmurfEnabled" value="1" > <font size="2"><b> ICMP Smurf 공격 방어 </b></font></td>
	</tr>
	<tr style="display:on">
		<td colspan="2">&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="IPSpoofEnabled" id="IPSpoofEnabled" value="1" > <font size="2"><b> IP Spoof 방지 </b></font></td>
	</tr>
	<tr>
  		<td colspan="2">&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="PingOfDeathEnabled" id="PingOfDeathEnabled" value="1" > <font size="2"><b> Ping Of Death 방어 </b></font></td>
	</tr>

	<tr style="display:on">
		<td width="40%">&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="pingSecEnabled" id="pingSecEnabled" value="1" ><font size="2"><b> 초당 Ping 응답 수 </b></font></td>
		<td width="40%"><input type="text" name="pingSecCount" id="pingSecCount" size="6" maxlength="4" > <font size="2"><b> Packets/Second</b></font><br></td>
	</tr>
	<tr style="display:on">
		<td colspan="2">&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="TraceRtEnabled" id="TraceRtEnabled" value="1" > <font size="2"><b> Trace route 응답 여부 설정 </b></font></td>
	</tr>
</table>
<br>
<input type="button" value=" 전체 선택 " name="selectAll" onClick="SelectAll()">&nbsp;&nbsp;
<input type="button" value=" 전체 해제 " name="clearAll" onClick="ClearAll()">&nbsp;&nbsp;
<br>
<table border="0" width="600">
	<tr>
		<td colspan="2"><hr size="1" noshade align="top"></td>
	</tr>
	<tr>
		<td width="300"  colspan="2"><font size="2"><b>&nbsp;&nbsp;&nbsp;<input type="checkbox" name="ARPspoofEnabled" id="ARPspoofEnabled" value="1" >&nbsp;&nbsp;ARP Spoof 방지</b></font></td>
	</tr>
	<tr>
  		<td width="40%"><font size="2"><b>&nbsp;&nbsp;&nbsp;<input type="checkbox" name="macflood" id="macflood" value="1">&nbsp;&nbsp;CPU 인입 이상 트래픽 제어 사용</b></font></td>
		<td width="40%"><input type="text" name="macflood_limit" id="macflood_limit" size="4" maxlength="4"> <font size="2"><b> Packets/Second</b></font></td>
	</tr>
	<tr>
		<td width="40%">&nbsp;&nbsp;&nbsp;<font size="2"><b> DNS Relay 인입 허용 Rate </b></font></td>
		<td width="40%"><input type="text" name="dns_input_rate" id="dns_input_rate" size="4" maxlength="4"> <font size="2"><b> Packets/Second (0은 무제한)</b></font><br></td>
	</tr>
	<tr>
		<td width="40%">&nbsp;&nbsp;&nbsp;<font size="2"><b> NTP 인입 허용  Rate </b></font></td>
		<td width="40%"><input type="text" name="ntp_input_rate" id="ntp_input_rate" size="4" maxlength="4"> <font size="2"><b> Packets/Second (0은 무제한)</b></font><br></td>
	</tr>
	<tr>
		<td width="40%">&nbsp;&nbsp;&nbsp;<font size="2"><b> SNMP 인입 허용 Rate </b></font></td>
		<td width="40%"><input type="text" name="snmp_input_rate" id="snmp_input_rate" size="4" maxlength="4"> <font size="2"><b> Packets/Second (0은 무제한)</b></font><br></td>
	</tr>
	<tr>
		<td colspan="2"><hr size=1 noshade align="top"></td>
	</tr>
<!-- 	<tr style="display:on"> -->
<!-- 		<td width="40%"><font size="2"><b> Source IP Blocking </b></font></td> -->
<!-- 		<td width="40%"><input type="text" name="IPblockTime" id="IPblockTime" size="4" maxlength="5" value="" > <font size="2"><b> Block time (sec)</b></font><br></td> -->
<!-- 	</tr> -->
</table>
<br>
<input type="button" value="적용" name="enableDos" onclick="applyClick(this.form);" >&nbsp;&nbsp;
<input type="hidden" value="/skb_dos.php" name="submit-url">
</form>
<form name="formDos" id="formDos" action="proc/skb_restart.php" method="POST">
<input type="hidden" name="act" id="act" value="network_restart">
<input type="hidden" name="submit-url" id="submit-url" value="/skb_dos.php">
</form>
</body>
</html>
