<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$uci = new uci();
	$uci->mode("get");
	$uci->get("network.lan");
	$uci->get("dhcp.lan");
	$uci->get("dvui.network");
	$uci->get("dhcpr.ipv4");
	$uci->run();
	$get = json_decode($uci->result(),true);
	$opmode = 1; // 1 : NAT 0: BRIDGE
	if(get_array_val($get,"dvui.network.opmode") == "bridge"){
		$opmode = 0;
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
<title>LAN Interface Setup </title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
	var initialDhcp;
	var curLoginUser = 0;

	function checkMode()
	{
		var opmode=<?=$opmode?>;
		var initialDhcp = 2;
		var check_opt82 = document.getElementById("lan_opt82");
		if (opmode == 0){
			dhcpChange(0);
		}else{
			dhcpChange(1);
		}

		if (curLoginUser == 1) {
			disableTextField(document.tcpip.lan_mask);
			disableTextField(document.tcpip.dhcpRangeStart);
			disableTextField(document.tcpip.dhcpRangeEnd);
			check_opt82.style.display="none";
		}
		if(opmode == 1){
			check_opt82.style.display="none";
		}else if(opmode == 0){
			check_opt82.style.display="";
		}
	}

	function lan_ipaddr_change()
	{
		var lan_ipaddr, lan_netaddr, lan_netmask, dhcp_start, dhcp_end;

		if (checkIPMask(document.tcpip.lan_mask) == false)
			return;

		lan_ipaddr = inet_aton(document.tcpip.lan_ip.value);
		lan_netmask = inet_aton(document.tcpip.lan_mask.value);
		lan_netaddr = lan_ipaddr;
		lan_netaddr &= lan_netmask;
		dhcp_start = 0x1;
		dhcp_start |= lan_netaddr;
		dhcp_end = 0xfffffffe;
		dhcp_end &= ~lan_netmask;
		dhcp_end |= lan_netaddr;
		if (lan_ipaddr >= dhcp_start && lan_ipaddr <= dhcp_end) {
			if ((lan_ipaddr - dhcp_start) > (dhcp_start - lan_ipaddr)) {
				dhcp_end = lan_ipaddr - 0x1;
				dhcp_end &= ~lan_netmask;
				dhcp_end |= lan_netaddr;
			} else {
				dhcp_start = lan_ipaddr + 0x1;
				dhcp_start &= ~lan_netmask;
				dhcp_start |= lan_netaddr;
			}
		}
		document.tcpip.dhcpRangeStart.value = inet_ntoa(dhcp_start);
		document.tcpip.dhcpRangeEnd.value = inet_ntoa(dhcp_end);
	}

	function dhcpChange(index)
	{
		var dF = document.tcpip;
		if (index == 0) {
			disableTextField(document.tcpip.dhcpRangeStart);
			disableTextField(document.tcpip.dhcpRangeEnd);
			disableButton( document.tcpip.dhcpClientTbl );
			disableTextField(document.tcpip.dhcpLeaseTime);
			disableButton(dF.elements["staticdhcpTbl"]);
		}
		else {
			enableTextField(document.tcpip.dhcpRangeStart);
			enableTextField(document.tcpip.dhcpRangeEnd);
			enableButton( document.tcpip.dhcpClientTbl );
			enableTextField(document.tcpip.dhcpLeaseTime);
			enableButton(dF.elements["staticdhcpTbl"]);
		}
		enableTextField(document.tcpip.lan_ip);
	}

	function resetClick()
	{
		document.location.assign("skb_tcpiplan.php");
	}


	function checkClientRange(start,end)
	{
		start_d = getDigit(start,4);
		start_d += getDigit(start,3)*256;
		start_d += getDigit(start,2)*256;
		start_d += getDigit(start,1)*256;

		end_d = getDigit(end,4);
		end_d += getDigit(end,3)*256;
		end_d += getDigit(end,2)*256;
		end_d += getDigit(end,1)*256;

		if ( start_d < end_d )
			return true;

		return false;
	}

	function checkDhcpLeaseTime(time)
	{
		if (time >= 60 && time <= 604800)
			return true;
		else
			return false;
	}

	function saveChanges(f)
	{
		var lan_netaddr, lan_netmask, dhcp_start, dhcp_end, lan_ipaddr;

		if ( checkIpAddr(document.tcpip.lan_ip, 'IP 주소가 올바르지 않습니다! ') == false ){
			return false;
		}
		var tmp_lan = document.tcpip.lan_ip.value.split(".");
		if(tmp_lan[3] == "254"){
			alert("IP주소의 끝자리는 254를 입력할 수 없습니다.");
			return;
		}
		if (checkIPMask(document.tcpip.lan_mask) == false)
			return false ;

		if(checkHostIPValid(document.tcpip.lan_ip,document.tcpip.lan_mask,'IP 주소가 올바르지 않습니다!')== false)
			return false;

		if ( document.tcpip.dhcp.selectedIndex == 1) {
			if ( checkIpAddr(document.tcpip.dhcpRangeStart, 'DHCP 클라이언트 시작 주소가 올바르지 않습니다! ') == false )
					return false;

			if(checkHostIPValid(document.tcpip.dhcpRangeStart,document.tcpip.lan_mask,'DHCP 클라이언트 시작 주소가 올바르지 않습니다! ')== false)
				return false;

			if ( !checkSubnet(document.tcpip.lan_ip.value,document.tcpip.lan_mask.value,document.tcpip.dhcpRangeStart.value)) {
				alert('DHCP 클라이언트 시작 주소가 올바르지 않습니다!\n현재 IP 주소의 서브넷과 동일한 영역에 위치해야 합니다.');
				document.tcpip.dhcpRangeStart.value = document.tcpip.dhcpRangeStart.defaultValue;
				document.tcpip.dhcpRangeStart.focus();
				return false;
			}

			if ( checkIpAddr(document.tcpip.dhcpRangeEnd, 'DHCP 클라이언트 마지막 주소가 올바르지 않습니다! ') == false )
				return false;

			if(checkHostIPValid(document.tcpip.dhcpRangeEnd,document.tcpip.lan_mask,'DHCP 클라이언트 마지막 주소가 올바르지 않습니다! ')== false)
				return false;

			if ( !checkSubnet(document.tcpip.lan_ip.value,document.tcpip.lan_mask.value,document.tcpip.dhcpRangeEnd.value)) {
				alert('DHCP 클라이언트 마지막 주소가 올바르지 않습니다!\n현재 IP 주소의 서브넷과 동일한 영역에 위치해야 합니다.');
				document.tcpip.dhcpRangeEnd.value = document.tcpip.dhcpRangeEnd.defaultValue;
				document.tcpip.dhcpRangeEnd.focus();
				return false;
			}

				if ( !checkClientRange(document.tcpip.dhcpRangeStart.value,document.tcpip.dhcpRangeEnd.value) ) {
				alert('DHCP 클라이언트 주소 범위가 올바르지 않습니다!\n마지막 주소가 시작 주소보다 커야 합니다.');
				document.tcpip.dhcpRangeStart.focus();
				return false;
				}

			if (!checkDhcpLeaseTime(document.tcpip.dhcpLeaseTime.value)) {
				alert('DHCP 임대 시간이 올바르지 않습니다!\n60 ~ 604800 사이의 값을 입력해야 합니다.');
				document.tcpip.dhcpLeaseTime.focus();
				return false;
			}

			$("#dhcp_leasetime").val(document.tcpip.dhcpLeaseTime.value + "s");

			lan_ipaddr = inet_aton(document.tcpip.lan_ip.value);
			lan_netaddr = inet_aton(document.tcpip.lan_ip.value);
			lan_netmask = inet_aton(document.tcpip.lan_mask.value);
			lan_netaddr &= lan_netmask;
			dhcp_start = inet_aton(document.tcpip.dhcpRangeStart.value);
			dhcp_end = inet_aton(document.tcpip.dhcpRangeEnd.value);

			if ( dhcp_start == lan_ipaddr || dhcp_end == lan_ipaddr ) {
				alert('DHCP 클라이언트 주소 범위가 올바르지 않습니다!');
				return false;
			}
			if ((lan_ipaddr == lan_netaddr) || (lan_ipaddr == (lan_ipaddr | ~lan_netmask))) {
				alert("DHCP 클라이언트 주소 범위가 올바르지 않습니다!");
				return false;
			}
			if (((lan_ipaddr & ~lan_netmask) >= (dhcp_start & ~lan_netmask) && (lan_ipaddr & ~lan_netmask) <= (dhcp_end & ~lan_netmask))) {
				alert("DHCP 클라이언트 주소 범위가 올바르지 않습니다!");
				return false;
			}
			var tempIp = document.tcpip.dhcpRangeStart.value;
			var tempStr  = tempIp.split(".");
			tempStr = parseInt(tempStr[3]);
			$("#dhcp_start").val(tempStr);
			var dhcp_start_int = ip_to_int(document.tcpip.dhcpRangeStart.value);
			var dhcp_end_int = ip_to_int(document.tcpip.dhcpRangeEnd.value);
			var dhcp_limit = dhcp_end_int - dhcp_start_int + 1;
			$("#dhcp_limit").val(dhcp_limit);
		}

		if ( document.tcpip.dhcp.selectedIndex != 1) {

			var tempIp = document.tcpip.lan_ip.value;
			var tempStr  = tempIp.split(".");
			tempStr = parseInt(tempStr[3]);
			$("#dhcp_start").val(tempStr);

			tempIp = document.tcpip.dhcpRangeStart.value;
			var tempStr1 = tempIp.split(".");
			tempStr1 = parseInt(tempStr1[3]);

			tempIp = document.tcpip.dhcpRangeEnd.value;
			var tempStr2 = tempIp.split(".");
			tempStr2 = parseInt(tempStr2[3]);

			if( (tempStr >= tempStr1) && (tempStr <= tempStr2) ) {
				alert('DHCP 클라이언트 주소 범위가 올바르지 않습니다!');
				return false;
			}
		}
		f.reset.disabled= true;
		f.save.disabled = true;
		f.submit();
	}


	function dhcpTblClick(url) {
		if ( document.tcpip.dhcp.selectedIndex == 1) {
			openWindow(url, 'DHCPTbl',600, 400 );
		}
	}
	function staticdhcpTblClick(url) {
		if ( document.tcpip.dhcp.selectedIndex == 1) {
			//openWindow(url, 'StaticDHCPTbl',820, 500 );
			document.location.href = url;
		}
	}
	var proc = "proc/skb_tcpiplan_proc.php";
//	var myIP = new IPv4_Address( document.ip_subnet.in_ip_address.value, use_subnet_bits );
	var get_lan_info = function(){
		dummyVal = CreateDummy();
		var sobj = new Object();
		sobj['dummyVal'] = dummyVal;
		sobj['act'] = 'get_lan_info';
		$.ajax({
			"data":sobj,
			url:proc,
			"dataType":"json",
			"type":"POST",
			success:function(d){
				if(d != null){
					if(get_obj_val(d,"network.lan.ipaddr") == ""){
						$("#lan_ip").val(get_obj_val(d,"network.lan._orig_ipaddr"));
						$("#lan_mask").val(get_obj_val(d,"network.lan._orig_netmask"));
						var broadcast_ip = $("#lan_ip").val().ip_check(get_obj_val(d,"network.lan._orig_netmask"));
						if(get_obj_val(d,"dhcpr.ipv4.enabled") == "1"){
							$("#option82").prop("checked",true);
						}else{
							$("#option82").prop("checked",false);
						}
					}else{
						$("#lan_ip").val(get_obj_val(d,"network.lan.ipaddr"));
						$("#lan_mask").val(get_obj_val(d,"network.lan.netmask"));
						var broadcast_ip = $("#lan_ip").val().ip_check(get_obj_val(d,"network.lan.netmask"));
						$("#option82").prop("checked",false);
					}
					var start_ip = ip_to_int(broadcast_ip) + parseInt(get_obj_val(d,"dhcp.lan.start"),10);
					$("#dhcp_start").val(get_obj_val(d,"dhcp.lan.start"));
					$("#dhcp_limit").val(get_obj_val(d,"dhcp.lan.limit"));
					if(get_obj_val(d,"dhcp.lan.ignore") == ""){
						$("#dhcp").val(1);
						var dhcp_less = get_obj_val(d,"dhcp.lan.leasetime");
						var dhcplesstime = 0;
						if(dhcp_less.indexOf("h") > -1){
							//hour
							dhcplesstime = parseInt(dhcp_less.replace(/[^0-9]/g,''),10) * 60 * 60;
						}else if(dhcp_less.indexOf("m") > -1){
							//Minute
							dhcplesstime = parseInt(dhcp_less.replace(/[^0-9]/g,''),10) * 60;
						}else if(dhcp_less.indexOf("s") > -1){
							//Minute
							dhcplesstime = parseInt(dhcp_less.replace(/[^0-9]/g,''),10);
						}
						$("#dhcp_leasetime").val(dhcp_less);
						$("#dhcpLeaseTime").val(dhcplesstime);
						$("#dhcpRangeStart").val(int_to_ip(start_ip));
						$("#dhcpRangeEnd").val(int_to_ip(start_ip + parseInt(get_obj_val(d,"dhcp.lan.limit"),10)-1));
						
					}else{
						$("#dhcp").val(0);
					}
					$("#loop_check").val(get_obj_val(d,"loop_check.cfg.enabled"));
				}
			},complete:function(){
				checkMode();
			}
		});
	}
	var set_lan_info = function(){
		if(ipCheck($("#lan_ip").val()) == false){
			alert("IP 주소가 올바르지 않습니다!");
			$("#lan_ip").focus();
			return false;
		}
		if(maskCheck($("#lan_mask").val()) == false){
			alert("서브넷 마스크가 올바르지 않습니다!");
			$("#lan_mask").focus();
			return false;
		}
		if($("#dhcp").children(":selected").val() == "1"){
			if (!checkDhcpLeaseTime($("#dhcpLeaseTime").val())) {
				alert('DHCP 임대 시간이 올바르지 않습니다!\n60 ~ 604800 사이의 값을 입력해야 합니다.');
				$("#dhcpLeaseTime").focus();
				return false;
			}
		}
	}
	$(document).ready(function(){
		get_lan_info();
	});
</script>
</head>
<body>
<blockquote>
<h2>로컬 랜 설정</h2>
<form action="/proc/skb_tcpiplan_proc.php" method="POST" name="tcpip">
<input type="hidden" name="act" value="set_lan_info">
<input type="hidden" name="submit-url" value="/skb_tcpiplan.php">
<input type="hidden" name="dhcp_start" id="dhcp_start" value="">
<input type="hidden" name="dhcp_limit" id="dhcp_limit" value="">
<input type="hidden" name="dhcp_leasetime" id="dhcp_leasetime" value="">
<table border="0" width="540" cellspacing="4" cellpadding="0">
	<tr>
		<td colspan="2"><font size="2">
		로컬 호스트의 접속을 위한 설정 페이지입니다.<br>
		특정 호스트에 이미 정해진 IP를 할당해줄 수 있으며 DHCP를 이용하여 자동으로 IP를 할당해줄 수도 있습니다</font>
		</td>
	</tr>
	<tr>
		<td colspan="2"><hr size="1" noshade align="top"></td>
	</tr>
	<tr>
		<td width="30%"><font size="2"><b>IP 주소:</b></font></td>
		<td width="70%"><input type="text" name="lan_ip" id="lan_ip" size="15" maxlength="15" value="" onchange="lan_ipaddr_change();"></td>
	</tr>
	<tr>
		<td><font size="2"><b>서브넷 마스크:</b></font></td>
		<td><input type="text" name="lan_mask" id="lan_mask" size="15" maxlength="15" value="" onchange="lan_ipaddr_change();"></td>
	</tr>
	<tr>
		<td><font size="2"><b>DHCP 사용:</b></font></td>
		<td><select size="1" name="dhcp" id="dhcp" onchange="dhcpChange(document.tcpip.dhcp.selectedIndex);">
			<option value="0">사용안함</option>
			<option value="1">사용</option>
		</select></td>
	</tr>
	<tr>
		<td><font size="2"><b>IP 할당 범위:</b></font></td>
		<td><input type="text" name="dhcpRangeStart" id="dhcpRangeStart" size="15" maxlength="15" value="">
		<font face="Arial" size="5">-</font> <input type="text" name="dhcpRangeEnd" id="dhcpRangeEnd" size="15" maxlength="15" value="">&nbsp;
		<input type="button" value="접속 리스트" name="dhcpClientTbl" onClick="dhcpTblClick('/skb_dhcptbl.php#form')" ></td>
	</tr>
	<tr>
		<td><font size="2"><b>IP 대여시간:</b></font></td>
		<td><input type="text" name="dhcpLeaseTime" id="dhcpLeaseTime" style="text-align:center;" size="7" maxlength="6" value=""> <font size="2"> 초</font></td>
	</tr>
	<tr>
		<td><font size="2"><b>고정 IP할당:</b></font></td>
		<td><input type="button" value="설정" name="staticdhcpTbl" onClick="staticdhcpTblClick('/skb_tcpip_staticdhcp.php#form');" ></td>
	</tr>
	<tr>
		<td width="30%"><font size=2><b>자가 루프 진단:</b></td>
		<td width="70%"><select name="loop_check" id="loop_check">
			<option value="0">사용안함</option>
			<option value="1">사용</option>
		</select></td>
	</tr>
	<tr id="lan_opt82">
		<td colspan="2">
		<fieldset  style="border-right: #000000 1px solid; padding-right: 10px; border-top: #000000 1px solid; padding-left: 10px; padding-bottom: 5px; border-left: #000000 1px solid; width: 500px; padding-top: 0px; border-bottom: #000000 1px solid; "><legend><b>DHCP 옵션</b></legend>
		<table border="0" width="550" cellspacing="4" cellpadding="0">
			<tr>
				<td width="100%" colspan="2"><font size="2">
				<b><input type="checkbox" name="option82" id="option82" value="1">&nbsp;&nbsp;Option82 사용</b></font></td>
			</tr>
		</table>
		</FIELDSET>
		</td>
	</tr>
</table>
<br>
<input type="button" value="저장" name="save" onClick="return saveChanges(this.form);">&nbsp;&nbsp;
<input type="reset" value="취소" name="reset" onClick="resetClick();">

</form>
</blockquote>
</body>

</html>
