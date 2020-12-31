<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	check_admin($isAdmin );
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>자가 진단 기능</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/spin.min.js"></script>
<script type="text/javascript" src="inc/js/jquery.spin.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
function link_ping_page()
{
//	frames["ping_test_page"].location.href = "skb_diagnostic_ping.php#form";
}

function resetForm()
{
	document.location.assign("skb_diagnostic.php");
}

var proc = "proc/skb_diagnostic_proc.php";
var get_diagnostic = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_diagnostic';
//		alert(JSON.stringify(sobj));
	create_loading();
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
//			console.log(d);
			var wan_link = "";
			var lan_link = "";
			if(d["network_stat"].wan_link == "1"){
				wan_link = "<span style=\"color:green\">케이블 연결됨</span>";
			}else{
				wan_link = "<span style=\"color:red\">케이블 연결안됨</span>";
				$("#ping_gateway").append(wan_link);
				$("#ping_dns1").append(wan_link);
				$("#ping_dns2").append(wan_link);
			}
			if(d["network_stat"].wan_proto == "STATIC"){
				$("#wan_status").append(wan_link+" [ 고정 IP 연결됨 ]");
			}else{
				$("#wan_status").append(wan_link+"[ DHCP IP 획득 성공 ]");
			}
			if(d["network_stat"].lan_link == "1"){
				lan_link = "<span style=\"color:green\">케이블 연결됨</span>";
			}else{
				lan_link = "<span style=\"color:red\">케이블 연결안됨</span>";
			}
			if(d["network_stat"].lan_dhcp_mode == "1"){
				$("#lan_status").append(lan_link+" [ DHCP 서버 사용중 ]");
			}else{
				$("#lan_status").append(lan_link+" [ DHCP 서버 사용안함 ]");
			}
			if(d["network_stat"].lan_dhcp_remain == d["network_stat"].lan_dhcp_limit){
				$("#dhcp_limit").text("할당 내역 없음");
			}else{
				$("#dhcp_limit").text(d["network_stat"].lan_dhcp_remain);
			}
			if(d["network_stat"].wan_ip_conflict == "0"){
				$("#wan_ip_conflict").text("없음");
			}else{
				$("#wan_ip_conflict").text("WAN IP 충돌 상태");
			}
			if(d["network_stat"].wan_link == "1"){
				if(d["ping_stat"].gateway_result == "1"){
					$("#ping_gateway").append("<font size=2 color='green'>정상</font>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font size='2'>"+d["ping_stat"].gateway_ipaddr+"</font>");
				}else{
					$("#ping_gateway").append("<font size=2 color='red'>실패</font>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font size='2'>"+d["ping_stat"].gateway_ipaddr+"</font>");
				}
				if(d["ping_stat"].dns_1st_result == "1"){
					$("#ping_dns1").append("<font size=2 color='green'>정상</font>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font size='2'>"+d["ping_stat"].dns_1st_ipaddr+"</font>");
				}else{
					$("#ping_dns1").append("<font size=2 color='red'>실패</font>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font size='2'>"+d["ping_stat"].dns_1st_ipaddr+"</font>");
				}
				if(d["ping_stat"].dns_2nd_result == "1"){
					$("#ping_dns2").append("<font size=2 color='green'>정상</font>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font size='2'>"+d["ping_stat"].dns_2nd_ipaddr+"</font>");
				}else{
					$("#ping_dns2").append("<font size=2 color='red'>실패</font>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font size='2'>"+d["ping_stat"].dns_2nd_ipaddr+"</font>");
				}
			}
//			IPTV 셋탑박스 연결안됨
			if(d["iptv_stat"].connection_stat == "1"){
				$("#iptv_conn").append("<font size=\"2\" style=\"color:green;\">IPTV 셋탑박스 연결됨</font>");
				$("#iptv_ip").append("<font size=\"2\" style=\"color:green;\">"+d["iptv_stat"].ipaddr+"</font>");
				$("#iptv_port").append("<font size=\"2\" style=\"color:green;\">"+d["iptv_stat"].port+"</font>");
			}else{
				$("#iptv_conn").append("<font size=\"2\" style=\"color:red;\">IPTV 셋탑박스 연결안됨</font>");
				$("#iptv_ip").append("<font size=\"2\" style=\"color:red;\">없음</font>");
				$("#iptv_port").append("<font size=\"2\" style=\"color:red;\">연결안됨</font>");
			}
			var ch5 = "";
			var ch24 = "";
			if(d["wireless_5g_stat"].vap00_channel != -1){
				ch5 = "&nbsp;&nbsp;&nbsp;[ 채널 : "+d["wireless_5g_stat"].vap00_channel+" ]";
			}
			if(d["wireless_5g_stat"].vap10_channel != -1){
				ch24 = "&nbsp;&nbsp;&nbsp;[ 채널 : "+d["wireless_2g_stat"].vap10_channel+" ]";
			}
			$("#ssid_5g").append(d["wireless_5g_stat"].vap00_ssid + ch5);
			$("#ssid_24g").append(d["wireless_2g_stat"].vap10_ssid + ch24);
			$("#ssid_5g_auth").text(clean_auth_type(d["wireless_5g_stat"].vap00_encrypt));
			$("#ssid_24g_auth").text(clean_auth_type(d["wireless_2g_stat"].vap10_encrypt));
			if(d["dhcp_stat"].length > 0){
				for(i=0; i < d["dhcp_stat"].length; i++){
					if(d["dhcp_stat"][i].ping_result == "1"){
						$("#dhcp_list").append("<font size=2 color='green'>정상</font>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font size='2'>"+d["dhcp_stat"][i].ipaddr+"</font><br>");
					}else{
						$("#dhcp_list").append("<font size=2 color='red'>실패</font>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font size='2'>"+d["dhcp_stat"][i].ipaddr+"</font><br>");
					}
				}
			}else{
				$("#dhcp_list").append("<font size=2 color='#ff9900'>할당 내역 없음</font>");
			}
//				
		},complete:function(){
			remove_loading();
		}
	});
}
var run_ping_test = function(){
	var ip_ = $("#ping_ip").val();
	if(ip_ == ""){
		alert("IP를 입력해주세요.");
		return;
	}
	if(ipCheck(ip_) == false && isURL(ip_,"none") == false){
		alert("IP 주소가 올바르지 않습니다");
		return;
	}
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'ping_test';
	sobj['ip'] = ip_;
//		alert(JSON.stringify(sobj));
	create_loading();
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(d == "0"){
				$("#ping_result").append(ip_ + "&nbsp;&nbsp;&nbsp;&nbsp;" +"정상<br>");
			}else if(d == "1"){
				$("#ping_result").append(ip_ + "&nbsp;&nbsp;&nbsp;&nbsp;" +"응답없음<br>");
			}
		},complete:function(){
			$("#ping_ip").val("");
			remove_loading();
		}
	});
}
$(document).ready(function(){
	get_diagnostic();
});
</script>
</head>
<body>

<script type="text/javascript">
//	alert('자가 진단 작업을 수행중입니다. 잠시 기다려 주시기 바랍니다.');
</script>
<blockquote>
<h2>자가진단 기능</h2>
<table border="0" width="500" cellspacing="4" cellpadding="0">
	<tr>
		<td><font size="2">자가진단 기능 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>

<form name="diagnostic">
	<table border="0" width="500" cellspacing="4" cellpadding="0">
		<tr class="tbl_head">
			<td width="100%" colspan="2"><font size="2"><b>네트워크 상태</b></font></td>
		</tr>
		<tr bgcolor="#DDDDDD">
			<td width="30%"><font size="2"><b>WAN</b></td>
			<td width="70%"><font size="2"><span id="wan_status"></span></font></td>
		</tr>
		<tr bgcolor="#EEEEEE">
			<td width="30%"><font size="2"><b>LAN</b></td>
			<td width="70%"><font size="2"><span id="lan_status"></span></font></td>
		</tr>
		<tr bgcolor="#DDDDDD">
			<td width="30%"><font size="2"><b>DHCP 남은 IP 수</b></td>
			<td width="70%"><font size="2" color='#ff9900'><span id="dhcp_limit"></span></font></td>
		</tr>
		<tr bgcolor="#EEEEEE">
			<td width="30%"><font size="2"><b>WAN IP 충돌</b></td>
    		<td width="70%"><font size='2' color='green'><span id="wan_ip_conflict"></span></font></td>
		</tr>

		<tr class="tbl_head">
			<td width="100%" colspan="2"><font size="2"><b>인터넷 서비스 점검 (ping test)</b></font></td>
		</tr>
		<tr bgcolor="#DDDDDD">
			<td width="30%"><font size="2"><b>게이트웨이</b></td>
    		<td width="70%"><span id="ping_gateway"></span></td>
		</tr>
		<tr bgcolor="#EEEEEE">
    		<td width="30%"><font size="2"><b>기본 DNS</b></td>
    		<td width="70%"><span id="ping_dns1"></span></td>
		</tr>
		<tr bgcolor="#DDDDDD">
			<td width="30%"><font size="2"><b>보조 DNS</b></td>
    		<td width="70%"><span id="ping_dns2"></span></td>
		</tr>

		<tr class="tbl_head">
			<td width="100%" colspan="2"><font size="2"><b>접속 단말 점검 (ping test)</b></font></td>
		</tr>
		<tr bgcolor="#DDDDDD">
			<td width="30%">DHCP</td>
			<td width="70%"><span id="dhcp_list"></span></td>
		</tr>
		<tr class="tbl_head">
			<td width="100%" colspan="2"><font size="2"><b>IPTV 상태</b></font></td>
		</tr>
		<tr bgcolor="#EEEEEE">
			<td width="30%"><font size="2"><b>셋탑박스 연결</b></font></td>
    		<td width="70%"><span id="iptv_conn"></span></td>
		</tr>
		<tr bgcolor="#DDDDDD">
			<td width="30%"><font size="2"><b>셋탑박스 IP</b></font></td>
    		<td width="70%"><span id="iptv_ip"></span></td>
		</tr>
		<tr bgcolor="#EEEEEE">
			<td width="30%"><font size="2"><b>셋탑박스 LAN</b></font></td>
    		<td width="70%"><span id="iptv_port"></span></td>
		</tr>
		<tr class="tbl_head">
			<td width="100%" colspan="2"><font size="2"><b>무선 정보 WIFI-5G</b></font></td>
		</tr>
		<tr bgcolor="#DDDDDD">
			<td width="30%"><font size="2"><b>SSID</b></font></td>
    		<td width="70%"><span id="ssid_5g"></span></td>
		</tr>
		<tr bgcolor="#EEEEEE">
			<td width="30%"><font size="2"><b>무선 보안 설정</b></font></td>
    		<td width="70%"><span id="ssid_5g_auth"></span></td>
		</tr>
		<tr class="tbl_head">
			<td width="100%" colspan="2"><font size="2"><b>무선 정보 WIFI-2.4G</b></font></td>
		</tr>
		<tr bgcolor="#DDDDDD">
			<td width="30%"><font size="2"><b>SSID</b></font></td>
    		<td width="70%"><span id="ssid_24g"></span></td>
		</tr>
		<tr bgcolor="#EEEEEE">
			<td width="30%"><font size="2"><b>무선 보안 설정</b></font></td>
    		<td width="70%"><span id="ssid_24g_auth"></span></td>
		</tr>
	</table>

	<table border="0" width="500" cellspacing="0" cellpadding="0">
		<tr class="tbl_head">
			<td width="100%"><font size="2"><b>PING TEST</b></font></td>
		</tr>
		<tr>
			<td width="100%"><input type="text" name="ping_ip" id="ping_ip" value=""><input type="button" name="btn_ping" id="btn_ping" value="send ping" onclick="run_ping_test();"></td>
		</tr>
		<tr>
			<td height="30" style="padding-top:5px;padding-bottom:5px;"><div id="ping_result" style="width:100%;height:150px;background-color:#000;color:#fff;"></div></td>
		</tr>
		<tr>
			<td colspan="2"><input type='button' name='View' value='다시 보기' onclick="resetForm()"></td>
		</tr>
	</table>
	<br><br>
</form>
</blockquote>
</body>
</html>
