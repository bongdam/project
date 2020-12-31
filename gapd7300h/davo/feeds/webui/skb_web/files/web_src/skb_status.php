<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
//	$cmd = new dvcmd();
//	$cmd->add("cpuusage");
//	$cmd->run();
//	$cpu_info = rtrim($cmd->result()[0]);
//	if($cpu_info ==""){
	$cpu_info = 0;
	$wiface = "";
	if($fp = fopen("/tmp/state/wireless", 'r')){ 
		$wiface = fread($fp, filesize("/tmp/state/wireless"));
		fclose($fp); 
	}
	$show = new dvshow();
	$show->read($wiface);
	$wi = $show->result("object");
	$wlan00 = get_json_val($wi,"wireless.vap00.up");
	$wlan01 = get_json_val($wi,"wireless.vap01.up");
	$wlan01_bssid = "";
	if($wlan01 == "1"){
		if($fp = fopen("/sys/devices/virtual/net/ath01/address", 'r')){ 
			$wlan01_bssid = strtoupper(rtrim(fread($fp, filesize("/sys/devices/virtual/net/ath01/address"))));
			fclose($fp); 
		}
	}
	$wlan02 = get_json_val($wi,"wireless.vap02.up");
	$wlan02_bssid = "";
	if($wlan02 == "1"){
		if($fp = fopen("/sys/devices/virtual/net/ath02/address", 'r')){ 
			$wlan02_bssid = strtoupper(rtrim(fread($fp, filesize("/sys/devices/virtual/net/ath02/address"))));
			fclose($fp); 
		}
	}
	$wlan10 = get_json_val($wi,"wireless.vap10.up");
	$wlan11 = get_json_val($wi,"wireless.vap11.up");
	$wlan11_bssid = "";
	if($wlan11 == "1"){
		if($fp = fopen("/sys/devices/virtual/net/ath11/address", 'r')){ 
			$wlan11_bssid = strtoupper(rtrim(fread($fp, filesize("/sys/devices/virtual/net/ath11/address"))));
			fclose($fp); 
		}
	}
	$wlan12 = get_json_val($wi,"wireless.vap12.up");
	$wlan12_bssid = "";
	if($wlan12 == "1"){
		if($fp = fopen("/sys/devices/virtual/net/ath12/address", 'r')){ 
			$wlan12_bssid = strtoupper(rtrim(fread($fp, filesize("/sys/devices/virtual/net/ath12/address"))));
			fclose($fp); 
		}
	}

	$cfg = new dvcfg();
	$cfg->read("dvui");
	$cfg->read("wireless");
	$cfg->read("igmpproxy");
	$cfg->read("mcsd");
	$wcfg = $cfg->result("object");
	$winfo = $cfg->result("json_string");
//	}
//	$cmd->close();
//	$uci = new uci();
//	$uci->mode("get");
//	$uci->get("wireless.wifi0|wireless.vap00|wireless.wifi1|wireless.vap10|wireless.wifi2|wireless.vap20");
//	$uci->run();
//	$wifiinfo = json_encode(json_decode($uci->result(),true),JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK);
	
	if($wifi2_ch == ""){
		$wifi2_ch = "Progress";
	}
	if($wifi5_ch == ""){
		$wifi5_ch = "Progress";
	}
//	$uci->mode("get");
//	$uci->get("igmpproxy.igmpproxy");
//	$uci->get("mcsd.config");
//	$uci->run();
//	$igmp = json_decode($uci->result(),true);
	$igmp_enable = get_json_val($wcfg,"igmpproxy.igmpproxy.enabled");
	if($igmp_enable == "1"){
		$igmp_enable = "활성화";
	}else{
		$igmp_enable = "비활성화";
	}
	$igmp_quickleave = get_json_val($wcfg,"igmpproxy.igmpproxy.quickleave");
	if($igmp_quickleave == "1"){
		$igmp_quickleave = "활성화";
	}else{
		$igmp_quickleave = "비활성화";
	}
	$igmp_query_interval = get_json_val($wcfg,"mcsd.config.query_interval");
//	$uci->close();
	
	$repeater = get_json_val($wcfg,"dvui.network.repeater");
	$repeater_radio = get_json_val($wcfg,"dvui.network.repeater_radio");
	$rpvap = "";
	if($repeater_radio == "0"){
		//2.4G
		$rpvap = "vap14";
	}else{
		$rpvap = "vap05";
	}
	//wireless.vap14.encryption='none'
	$repeater_ssid = get_json_val($wcfg,"wireless.".$rpvap.".ssid");
	$repeater_enc = get_json_val($wcfg,"wireless.".$rpvap.".encryption");
	$cfg->close();
	$wds = "";
	if($fp = fopen("/tmp/repeater_state", 'r')){ 
		$wds = rtrim(fread($fp, filesize("/tmp/repeater_state")));
		fclose($fp); 
	}
	if($wds == "SUCCESS"){
		$repeater_state = "Connected";
	}else{
		$repeater_state = "Searching";
	}
	$repeater_bssid = "";
	if($fp = fopen("/tmp/repeater_bssid", 'r')){ 
		$repeater_bssid = rtrim(fread($fp, filesize("/tmp/repeater_bssid")));
		fclose($fp); 
	}

?><html>
<head>
<meta http-equiv='Pragma' content='no-cache'>
<meta http-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Expires" content="Mon, 01 Jan 1990 00:00:01 GMT">
<title>상태 정보</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<style type="text/css">
	.table550{
		width:550px;padding:0;border-spacing:2px 2px;border:0px; border-collapse:separate;
	}
	.table550 tr{
		height:16px;
	}
	.table550 tr:nth-child(even){
		background-color:#ddd;
	}
	.table550 tr:nth-child(odd){
		background-color:#eee;
	}
	.table550 .tl_td{
		width:30%;
		font-size:12px;font-weight:bold;
		height:22px;
	}
	.table550 .co_td{
		width:70%;
		font-size:12px;
		height:22px;
	}
</style>
<script type="text/javascript" charset="UTF-8">
var cpuuse = <?=$cpu_info?>;
//var memuse = ((mem_total - (mem_free + mem_buf + mem_cache)) / mem_total * 100).toFixed(2);
var wlanmode, wlanclientnum;
var isAP = 0;
var ipv6_mode = "0";
var speedW="&nbsp;";
var speedL1="&nbsp;";
var speedL2="&nbsp;";
var speedL3="&nbsp;";
var speedL4="&nbsp;";
var DuplexW= "";
var DuplexL1= "";
var DuplexL2= "";
var DuplexL3= "";
var DuplexL4= "";
var link_status;
var link_duplex;
var nowCount=0;
var winfo = <?=$winfo?>;
var repeater = "<?=$repeater?>";
var repeater_radio = "<?=$repeater_radio?>";
// S:Port Status

// E:Post Status 

/*var detect_offer_port = -1;*/

function check_ip_mode()
{
	var dhcpMode = '0';

	if(dhcpMode == "auto")
		return;

	document.formWanIpRenewal.apply.disabled = true;
}

function disableReflesh(f)
{
	f.apply.disabled=true;
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'ip_refresh';
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			f.apply.disabled=false;
			get_wan_info();
		}
	});
}

function portSpeed()
{
	link_status = 159;
	if ((link_status & 7) == 7)
		speedW = '1000M';
	else if ((link_status & 7) == 5)
		speedW = '500M';
	else if ((link_status & 7) == 3)
		speedW = '100M';
	else if ((link_status & 7) == 1)
		speedW = '10M';

	link_status = 144;
	if ((link_status & 7) == 7)
		speedL1 = '1000M';
	else if ((link_status & 7) == 5)
		speedL1 = '500M';
	else if ((link_status & 7) == 3)
		speedL1 = '100M';
	else if ((link_status & 7) == 1)
		speedL1 = '10M';

	link_status = 144;
	if ((link_status & 7) == 7)
		speedL2 = '1000M';
	else if ((link_status & 7) == 5)
		speedL2 = '500M';
	else if ((link_status & 7) == 3)
		speedL2 = '100M';
	else if ((link_status & 7) == 1)
		speedL2 = '10M';

	link_status = 144;
	if ((link_status & 7) == 7)
		speedL3 = '1000M';
	else if ((link_status & 7) == 5)
		speedL3 = '500M';
	else if ((link_status & 7) == 3)
		speedL3 = '100M';
	else if ((link_status & 7) == 1)
		speedL3 = '10M';

	link_status = 144;
	if ((link_status & 7) == 7)
		speedL4 = '1000M';
	else if ((link_status & 7) == 5)
		speedL4 = '500M';
	else if ((link_status & 7) == 3)
		speedL4 = '100M';
	else if ((link_status & 7) == 1)
		speedL4 = '10M';
}

function portNego()
{
	link_duplex = 2;
	if(link_duplex==2)
		DuplexW="/F";
	else if(link_duplex==1)
		DuplexW="/H";

	link_duplex = 0;
	if(link_duplex==2)
		DuplexL1="/F";
	else if(link_duplex==1)
		DuplexL1="/H";

	link_duplex = 0;
	if(link_duplex==2)
		DuplexL2="/F";
	else if(link_duplex==1)
		DuplexL2="/H";

	link_duplex = 0;
	if(link_duplex==2)
		DuplexL3="/F";
	else if(link_duplex==1)
		DuplexL3="/H";

	link_duplex = 0;
	if(link_duplex==2)
		DuplexL4="/F";
	else if(link_duplex==1)
		DuplexL4="/H";
}

function open_client_table(id)
{
	aclist_index = id;
	openWindow('/skb_wlstatbl.php?seq=4#form', 'showWirelessClient', 820, 500);
	return;
}

</script>
<script type="text/javascript">
	var ldap_enable = "0";
	var proc = "proc/skb_status_proc.php";
	var lan_port = "<?=dv_session("lan_port")?>";
	var wan_port = "<?=dv_session("wan_port")?>";
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
					$("#lan_ip").text(get_obj_val(d,"network.lan.ipaddr"));
					$("#lan_mask").text(get_obj_val(d,"network.lan.netmask"));
					var broadcast_ip = $("#lan_ip").val().ip_check(get_obj_val(d,"network.lan.netmask"));
					var start_ip = ip_to_int(broadcast_ip) + parseInt(get_obj_val(d,"dhcp.lan.start"),10);
					$("#dhcp_start").val(get_obj_val(d,"dhcp.lan.start"));
					$("#dhcp_limit").val(get_obj_val(d,"dhcp.lan.limit"));
					if(get_obj_val(d,"dhcp.lan.ignore") == ""){
						$("#lan_dhcpsvr").text("사용함");
					}else{
						$("#lan_dhcpsvr").text("사용안함");
					}
				}
			},complete:function(){
//				checkMode();
				get_wan_info();
			}
		});
	}
	var get_network_info = function(){
		dummyVal = CreateDummy();
		var sobj = new Object();
		sobj['dummyVal'] = dummyVal;
		sobj['act'] = 'get_network_info';
		$.ajax({
			"data":sobj,
			url:proc,
			"dataType":"json",
			"type":"POST",
			success:function(d){
//				console.log(d);
				if(d[1] != undefined){
					
					for (var i=0; i < d.length ; i++ )
					{
						if(d[i].ifname == wan_port){
//							console.log("wan");
//							$("#wan_gateway").text(d[i]);
							$("#wan_ipaddr").text(d[i].ipaddr);
							$("#wan_subnetmask").text(d[i].netmask);
							$("#wan_macaddr").text(d[i].mac);
						}else if(d[i].ifname == lan_port){
							$("#lan_macaddr").text(d[i].mac);
						}
					}
				}
			}
		});
	}
	var get_wan_info = function(){
		dummyVal = CreateDummy();
		var sobj = new Object();
		sobj['dummyVal'] = dummyVal;
		sobj['act'] = 'get_wan_info';
		$.ajax({
			"data":sobj,
			url:proc,
			"dataType":"json",
			"type":"POST",
			success:function(d){
				if(d != null){
					if(get_obj_val(d,"network.wan.proto") == "dhcp"){ 
						$("#wan_mode").text("DHCP IP 연결됨");
						get_wan_gateway();
					}else{
						$("#wan_mode").text("고정 IP 연결됨");
						get_wan_gateway();
						$("#wan_ipaddr").text(get_obj_val(d,"network.wan.ipaddr"));
						$("#wan_subnetmask").text(get_obj_val(d,"network.wan.netmask"));
						$("#wan_gateway").text(get_obj_val(d,"network.wan.gateway"));
					}
				}
			},
			complete:function(){
				get_network_info();
			}
		});
	}
	var get_wan_gateway = function(){
//		get_wan_gateway
		dummyVal = CreateDummy();
		var sobj = new Object();
		sobj['dummyVal'] = dummyVal;
		sobj['act'] = 'get_wan_gateway';
		$.ajax({
			"data":sobj,
			url:proc,
			"dataType":"json",
			"type":"POST",
			success:function(d){
				if(d != null){
//					console.log(d);
					$("#wan_gateway").text(d.gateway);
					if(d.dns1 != undefined && d.dns2 != undefined){
						$("#wan_dns_server").text(d.dns1 + " " + d.dns2);
					}else if(d.dns1 != undefined){
						$("#wan_dns_server").text(d.dns1);
					}
					
				}
			}
		});
	}
	var portstatus_change = function(status_){
		var status = status_ ? status_ : "0";
		if (status == "1")
		{
			return "#00ff00";
		}else{
			return "#8b0000";
		}
	}
	var portStatus = function()
	{
		dummyVal = CreateDummy();
		var sobj = new Object();
		sobj['dummyVal'] = dummyVal;
		sobj['act'] = 'get_network_port_status'
		$.ajax({
			"data":sobj,
			url:proc,
			"dataType":"json",
			"type":"POST",
			success:function(d){
				for (var i=0; i < d.length ; i++ )
				{
					var link = portstatus_change(d[i].link);
					var status = "";
					if(d[i].link == "1"){
						status += d[i].speed + "M";
						status += d[i].duplex == "1" ? "/F" : "/H";
					}
					$("#"+d[i].name+"Status").css("background-color",link);
					if(status != ""){
						$("#"+d[i].name+"_port_status").append(status);
					}else{
						$("#"+d[i].name+"_port_status").append("&nbsp;&nbsp;");
					}
					
				}
			}
		});
	}
	var winfo_display = function(){
		if( typeof(winfo) == "object"){
			$("#wifi5_mode").text(get_json_val(winfo,"wireless.wifi0.hwmode"));
			$("#wifi5_band").text(get_json_val(winfo,"wireless.wifi0.htmode"));
			$("#wifi5_ssid").text(get_json_val(winfo,"wireless.vap00.ssid"));
			$("#wifi5_enc").text(clean_auth_type(get_json_val(winfo,"wireless.vap00.encryption")));
			$("#wifi5_bssid").text(get_json_val(winfo,"wireless.wifi0.macaddr").toUpperCase());
			if(get_json_val(winfo,"wireless.vap20.ssid") == ""){
				$("#wifi2_mode").text(get_json_val(winfo,"wireless.wifi1.hwmode"));
				$("#wifi2_band").text(get_json_val(winfo,"wireless.wifi1.htmode"));
				$("#wifi2_ssid").text(get_json_val(winfo,"wireless.vap10.ssid"));
				$("#wifi2_enc").text(clean_auth_type(get_json_val(winfo,"wireless.vap10.encryption")));
				$("#wifi2_bssid").text(get_json_val(winfo,"wireless.wifi1.macaddr").toUpperCase());
			}else{
				$("#wifi2_mode").text(get_json_val(winfo,"wireless.wifi2.hwmode"));
				$("#wifi2_band").text(get_json_val(winfo,"wireless.wifi2.htmode"));
				$("#wifi2_ssid").text(get_json_val(winfo,"wireless.vap20.ssid"));
				$("#wifi2_enc").text(clean_auth_type(get_json_val(winfo,"wireless.vap20.encryption")));
				$("#wifi2_bssid").text(get_json_val(winfo,"wireless.wifi2.macaddr").toUpperCase());
			}
			if(get_json_val(winfo,"wireless.vap11.disabled") != "1"){
				$("#wifi21_mode").text(get_json_val(winfo,"wireless.wifi1.hwmode"));
				$("#wifi21_band").text(get_json_val(winfo,"wireless.wifi1.htmode"));
				$("#wifi21_ssid").text(get_json_val(winfo,"wireless.vap11.ssid"));
				$("#wifi21_enc").text(clean_auth_type(get_json_val(winfo,"wireless.vap11.encryption")));
				$("#wifi21_bssid").text("<?=$wlan11_bssid?>");
			}else{
				$(".wifi21").hide();
			}
			if(get_json_val(winfo,"wireless.vap12.disabled") != "1"){
				$("#wifi22_mode").text(get_json_val(winfo,"wireless.wifi1.hwmode"));
				$("#wifi22_band").text(get_json_val(winfo,"wireless.wifi1.htmode"));
				$("#wifi22_ssid").text(get_json_val(winfo,"wireless.vap12.ssid"));
				$("#wifi22_enc").text(clean_auth_type(get_json_val(winfo,"wireless.vap12.encryption")));
				$("#wifi22_bssid").text("<?=$wlan12_bssid?>");
			}else{
				$(".wifi22").hide();
			}
			if(get_json_val(winfo,"wireless.vap01.disabled") != "1"){
				$("#wifi51_mode").text(get_json_val(winfo,"wireless.wifi0.hwmode"));
				$("#wifi51_band").text(get_json_val(winfo,"wireless.wifi0.htmode"));
				$("#wifi51_ssid").text(get_json_val(winfo,"wireless.vap01.ssid"));
				$("#wifi51_enc").text(clean_auth_type(get_json_val(winfo,"wireless.vap01.encryption")));
				$("#wifi51_bssid").text("<?=$wlan01_bssid?>");
			}else{
				$(".wifi51").hide();
			}
			if(get_json_val(winfo,"wireless.vap02.disabled") != "1"){
				$("#wifi52_mode").text(get_json_val(winfo,"wireless.wifi0.hwmode"));
				$("#wifi52_band").text(get_json_val(winfo,"wireless.wifi0.htmode"));
				$("#wifi52_ssid").text(get_json_val(winfo,"wireless.vap02.ssid"));
				$("#wifi52_enc").text(clean_auth_type(get_json_val(winfo,"wireless.vap02.encryption")));
				$("#wifi52_bssid").text("<?=$wlan02_bssid?>");
			}else{
				$(".wifi52").hide();
			}
		}
	}
	var get_system_info = function(){
//		get_wan_gateway
		dummyVal = CreateDummy();
		var sobj = new Object();
		sobj['dummyVal'] = dummyVal;
		sobj['act'] = 'get_system_info';
		$.ajax({
			"data":sobj,
			url:proc,
			"dataType":"json",
			"type":"POST",
			success:function(d){
				if(d != null){
					var mem_total = get_json_val(d,"meminfo.total");
					var mem_free = get_json_val(d,"meminfo.free");
					var mem_buf = get_json_val(d,"meminfo.buffer");
					var mem_cache = get_json_val(d,"meminfo.cache");
					var memuse = ((mem_total - (mem_free + mem_buf + mem_cache)) / mem_total * 100).toFixed(2);
					$("#uptime").text(get_json_val(d,"uptime"));
					$("#usemem").text(memuse);
					$("#wifi5_client").text(get_json_val(d,"sta_cnt.cnt5"));
					$("#wifi51_client").text(get_json_val(d,"sta_cnt.cnt51"));
					$("#wifi52_client").text(get_json_val(d,"sta_cnt.cnt52"));
					$("#wifi2_client").text(get_json_val(d,"sta_cnt.cnt24"));
					$("#wifi21_client").text(get_json_val(d,"sta_cnt.cnt241"));
					$("#wifi22_client").text(get_json_val(d,"sta_cnt.cnt242"));
					$("#wifi5_ch").text(get_json_val(d,"channel.ch5"));
					$("#wifi2_ch").text(get_json_val(d,"channel.ch24"));
					
				}
			},complete:function(){
				setTimeout(get_cpu_info,1000);
			}
		});
	}
	var get_cpu_info = function(){
//		get_wan_gateway
		dummyVal = CreateDummy();
		var sobj = new Object();
		sobj['dummyVal'] = dummyVal;
		sobj['act'] = 'get_cpu_info';
		$.ajax({
			"data":sobj,
			url:proc,
			"dataType":"text",
			"type":"POST",
			success:function(d){
//				console.log(d);
				if(d != ""){
					$("#usecpu").text(parseFloat(d,10).toFixed(2));
				}
			}
		});
	}
	$(document).ready(function(){
		if ( ldap_enable == "0" ) {
			$(".ldap").hide();
		}
		get_system_info();
		get_lan_info();
		winfo_display();
		
		$(".repeater24").hide();
		$(".repeater5").hide();
		if(repeater == "1"){
			if(repeater_radio == "0"){
				$(".repeater24").show();
				$("#repeater_enc24").text(clean_auth_type($("#repeater_enc24").text()));
			}else{
				$(".repeater5").show();
				$("#repeater_enc5").text(clean_auth_type($("#repeater_enc5").text()));
			}
		}
		
	});
</script>
</head>
<body>
<blockquote>
<script type="text/javascript">
document.write("<h2>H824G 상태 정보</h2>");
</script>
<!-- <table border=0 width="550" cellspacing=0 cellpadding=0> -->
<form name="formWanIpRenewal">
<table style="border-collapse:collapse; border:0;">

<tr><td><font size="2">
 현재 장비 상태 정보를 보여주는 페이지입니다.
</font></td></tr>
<?php
	if(get_json_val($wcfg,"dvui.network.repeater") == "1"){
		$wds_status = "";
		if($wds == "SUCCESS"){
			$wds_status = "Repeater 연결 : 메인 AP와 Repeater Mode로 연결 되었습니다.";
		}elseif($wds == "WEP_AUTH_FAIL"){
			$wds_status = "Repeater 연결 실패 : 잘못된 Password(WEP Mode)로 메인 AP와 연결 할 수 없습니다.";
		}elseif($wds == "WPA_AUTH_FAIL"){
			$wds_status = "Repeater 연결 실패 : 잘못된 Password(WPA Mode)로 메인 AP와 연결 할 수 없습니다.";
		}elseif($wds == "DHCP_FAIL"){
			$wds_status = "Repeater 연결 실패 : 잘못된 Password(WEP Mode) 또는 메인 AP로부터 IP 할당을 받지 못하여 연결 할 수 없습니다.";
		}elseif($wds == "PRIVACY_NOT_MATCH"){
			$wds_status = "Repeater 연결 실패 : 선택한 인증 보안 방식이 메인 AP와 다릅니다.";
		}elseif($wds == "SSID_NOT_MATCH"){
			$wds_status = "Repeater 연결 실패 : 메인 AP로부터 IP 할당을 받지 못하여 연결 할 수 없습니다.";
		}else{
			$wds_status = "Repeater 연결 실패 : 운용 모드 설정 페이지의 Repeater 설정을 확인해 주세요.";
		}
		echo("<tr>");
		echo("<td><font color='red'>".$wds_status."</font></td>");
		echo("</tr>");
	}
?>
<tr><td><hr size=1 noshade align=top><br></td></tr>
</table>
<table class="table550" style="">
	<tbody>
		<tr>
			<td colspan="2" class="tbl_title">시스템</td>
		</tr>
		<tr>
			<td class="tl_td">가동시간</td>
			<td class="co_td"><span id="uptime"></span></td>
		</tr>
		<tr>
			<td class="tl_td">펌웨어 버전</td>
			<td class="co_td"><?=DEF_VERSION?></td>
		</tr>
		<tr>
			<td class="tl_td">성능 (사용량-%)</td>
			<td class="co_td">CPU: <span id="usecpu"><?=$cpu_info?></span>%, RAM: <span id="usemem"></span>%&nbsp;<input type="button" value="새로 고침" name="refresh" onClick="get_system_info()"></td>
		</tr>
		<tr class="ldap">
			<td colspan="2" class="tbl_title">LDAP CFG</td>
		</tr>
		<tr class="ldap">
			<td class="tl_td">CFG 버전</td>
			<td class="co_td"></td>
		</tr>
		<tr class="ldap">
			<td class="tl_td">CFG 파일명</td>
			<td class="co_td"></td>
		</tr>
		<tr class="wifi5">
			<td colspan="2" class="tbl_title">WiFi-5G 정보</td>
		</tr>
		<tr class="wifi5">
			<td class="tl_td">모드</td>
			<td class="co_td"><span id="wifi5_mode"></span></td>
		</tr>
		<tr class="wifi5">
			<td class="tl_td">Band</td>
			<td class="co_td"><span id="wifi5_band"></span></td>
		</tr>
		<tr class="wifi5">
			<td class="tl_td">SSID</td>
			<td class="co_td"><span id="wifi5_ssid"></span></td>
		</tr>
		<tr class="wifi5">
			<td class="tl_td">채널 번호</td>
			<td class="co_td"><span id="wifi5_ch"><?=$wifi5_ch?></span></td>
		</tr>
		<tr class="wifi5">
			<td class="tl_td">암 호 화</td>
			<td class="co_td"><span id="wifi5_enc"></span></td>
		</tr>
		<tr class="wifi5">
			<td class="tl_td">BSSID</td>
			<td class="co_td"><span id="wifi5_bssid"></span></td>
		</tr>
		<tr class="wifi5">
			<td class="tl_td">접속된 클라이언트 수</td>
			<td class="co_td"><span id="wifi5_client"><?=$wifi5_cnt?></span></td>
		</tr>
		<?php
		if($wlan01 == "1"){
		?>
		<tr class="wifi51">
			<td colspan="2" class="tbl_title">WiFi-5G 가상 무선 인터넷 1 정보</td>
		</tr>
		<tr class="wifi51">
			<td class="tl_td">모드</td>
			<td class="co_td"><span id="wifi51_mode"></span></td>
		</tr>
		<tr class="wifi51">
			<td class="tl_td">Band</td>
			<td class="co_td"><span id="wifi51_band"></span></td>
		</tr>
		<tr class="wifi51">
			<td class="tl_td">SSID</td>
			<td class="co_td"><span id="wifi51_ssid"></span></td>
		</tr>
		<tr class="wifi51">
			<td class="tl_td">암 호 화</td>
			<td class="co_td"><span id="wifi51_enc"></span></td>
		</tr>
		<tr class="wifi51">
			<td class="tl_td">BSSID</td>
			<td class="co_td"><span id="wifi51_bssid"></span></td>
		</tr>
		<tr class="wifi51">
			<td class="tl_td">접속된 클라이언트 수</td>
			<td class="co_td"><span id="wifi51_client"></span></td>
		</tr>
		<?php
		}
		?>
		<?php
		if($wlan01 == "1"){
		?>
		<tr class="wifi52">
			<td colspan="2" class="tbl_title">WiFi-5G 가상 무선 인터넷 2 정보</td>
		</tr>
		<tr class="wifi52">
			<td class="tl_td">모드</td>
			<td class="co_td"><span id="wifi52_mode"></span></td>
		</tr>
		<tr class="wifi52">
			<td class="tl_td">Band</td>
			<td class="co_td"><span id="wifi52_band"></span></td>
		</tr>
		<tr class="wifi52">
			<td class="tl_td">SSID</td>
			<td class="co_td"><span id="wifi52_ssid"></span></td>
		</tr>
		<tr class="wifi52">
			<td class="tl_td">암 호 화</td>
			<td class="co_td"><span id="wifi52_enc"></span></td>
		</tr>
		<tr class="wifi52">
			<td class="tl_td">BSSID</td>
			<td class="co_td"><span id="wifi52_bssid"></span></td>
		</tr>
		<tr class="wifi52">
			<td class="tl_td">접속된 클라이언트 수</td>
			<td class="co_td"><span id="wifi52_client"><?=$wifi52_cnt?></span></td>
		</tr>
		<?php
		}
		?>
		<tr class="repeater5">
			<td colspan="2" class="tbl_title">Wireless 5G Repeater Interface Configuration</td>
		</tr>
		<tr class="repeater5">
			<td class="tl_td">Mode</td>
			<td class="co_td">Infrastructure Client</td>
		</tr>
		<tr class="repeater5">
			<td class="tl_td">SSID</td>
			<td class="co_td"><?=$repeater_ssid?></td>
		</tr>
		<tr class="repeater5">
			<td class="tl_td">Encryption</td>
			<td class="co_td" id="repeater_enc5"><?=$repeater_enc?></td>
		</tr>
		<tr class="repeater5">
			<td class="tl_td">BSSID</td>
			<td class="co_td"><?=$repeater_bssid?></td>
		</tr>
		<tr class="repeater5">
			<td class="tl_td">State</td>
			<td class="co_td"><?=$repeater_state?></td>
		</tr>
		<tr class="wifi24">
			<td colspan="2" class="tbl_title">WiFi-2.4G 정보</td>
		</tr>
		<tr class="wifi24">
			<td class="tl_td">모드</td>
			<td class="co_td"><span id="wifi2_mode"></span></td>
		</tr>
		<tr class="wifi24">
			<td class="tl_td">Band</td>
			<td class="co_td"><span id="wifi2_band"></span></td>
		</tr>
		<tr class="wifi24">
			<td class="tl_td">SSID</td>
			<td class="co_td"><span id="wifi2_ssid"></span></td>
		</tr>
		<tr class="wifi24">
			<td class="tl_td">채널 번호</td>
			<td class="co_td"><span id="wifi2_ch"><?=$wifi2_ch?></span></td>
		</tr>
		<tr class="wifi24">
			<td class="tl_td">암 호 화</td>
			<td class="co_td"><span id="wifi2_enc"></span></td>
		</tr>
		<tr class="wifi24">
			<td class="tl_td">BSSID</td>
			<td class="co_td"><span id="wifi2_bssid"></span></td>
		</tr>
		<tr class="wifi24">
			<td class="tl_td">접속된 클라이언트 수</td>
			<td class="co_td"><span id="wifi2_client"><?=$wifi2_cnt?></span></td>
		</tr>
		<tr class="wifi24">
			<td class="tl_td">HandOver 클라이언트</td>
			<td class="co_td"><button onclick="open_client_table();">HandOver_단말</button></td>
		</tr>
		<?php
		if($wlan11 == "1"){
		?>
		<tr class="wifi21">
			<td colspan="2" class="tbl_title">WiFi-2.4G 가상 무선 인터넷 1 정보</td>
		</tr>
		<tr class="wifi21">
			<td class="tl_td">모드</td>
			<td class="co_td"><span id="wifi21_mode"></span></td>
		</tr>
		<tr class="wifi21">
			<td class="tl_td">Band</td>
			<td class="co_td"><span id="wifi21_band"></span></td>
		</tr>
		<tr class="wifi21">
			<td class="tl_td">SSID</td>
			<td class="co_td"><span id="wifi21_ssid"></span></td>
		</tr>
		<tr class="wifi21">
			<td class="tl_td">암 호 화</td>
			<td class="co_td"><span id="wifi21_enc"></span></td>
		</tr>
		<tr class="wifi21">
			<td class="tl_td">BSSID</td>
			<td class="co_td"><span id="wifi21_bssid"></span></td>
		</tr>
		<tr class="wifi21">
			<td class="tl_td">접속된 클라이언트 수</td>
			<td class="co_td"><span id="wifi21_client"></span></td>
		</tr>
		<?php
		}
		?>
		<?php
		if($wlan12 == "1"){
		?>
		<tr class="wifi22">
			<td colspan="2" class="tbl_title">WiFi-2.4G 가상 무선 인터넷 2 정보</td>
		</tr>
		<tr class="wifi22">
			<td class="tl_td">모드</td>
			<td class="co_td"><span id="wifi22_mode"></span></td>
		</tr>
		<tr class="wifi22">
			<td class="tl_td">Band</td>
			<td class="co_td"><span id="wifi22_band"></span></td>
		</tr>
		<tr class="wifi22">
			<td class="tl_td">SSID</td>
			<td class="co_td"><span id="wifi22_ssid"></span></td>
		</tr>
		<tr class="wifi22">
			<td class="tl_td">암 호 화</td>
			<td class="co_td"><span id="wifi22_enc"></span></td>
		</tr>
		<tr class="wifi22">
			<td class="tl_td">BSSID</td>
			<td class="co_td"><span id="wifi22_bssid"></span></td>
		</tr>
		<tr class="wifi22">
			<td class="tl_td">접속된 클라이언트 수</td>
			<td class="co_td"><span id="wifi22_client"></span></td>
		</tr>
		<?php
		}
		?>
		<tr class="repeater24">
			<td colspan="2" class="tbl_title">Wireless 2.4G Repeater Interface Configuration</td>
		</tr>
		<tr class="repeater24">
			<td class="tl_td">Mode</td>
			<td class="co_td">Infrastructure Client</td>
		</tr>
		<tr class="repeater24">
			<td class="tl_td">SSID</td>
			<td class="co_td"><?=$repeater_ssid?></td>
		</tr>
		<tr class="repeater24">
			<td class="tl_td">Encryption</td>
			<td class="co_td" id="repeater_enc24"><?=$repeater_enc?></td>
		</tr>
		<tr class="repeater24">
			<td class="tl_td">BSSID</td>
			<td class="co_td"><?=$repeater_bssid?></td>
		</tr>
		<tr class="repeater24">
			<td class="tl_td">State</td>
			<td class="co_td"><?=$repeater_state?></td>
		</tr>
		<tr class="lan">
			<td colspan="2" class="tbl_title">랜 정보</td>
		</tr>
		<tr class="lan">
			<td class="tl_td">IP 주소</td>
			<td class="co_td"><span id="lan_ip"></span></td>
		</tr>
		<tr class="lan">
			<td class="tl_td">서브넷 마스크</td>
			<td class="co_td"><span id="lan_mask"></span></td>
		</tr>
		<tr class="lan">
			<td class="tl_td">DHCP 서버</td>
			<td class="co_td"><span id="lan_dhcpsvr"></span></td>
		</tr>
		<tr class="lan">
			<td class="tl_td">MAC 주소</td>
			<td class="co_td"><span id="lan_macaddr"></span></td>
		</tr>
		<tr class="wan">
			<td colspan="2" class="tbl_title">인터넷 정보</td>
		</tr>
		<tr class="wan">
			<td class="tl_td">IP 모드</td>
			<td class="co_td"><span id="wan_mode"></span><input type="button" name="apply" value="IP갱신" style="width:50px; height:20px; font-size:12px; vertical-align:middle; text-align:center; position:relative;" onclick="disableReflesh(this.form);"></td>
		</tr>
		<tr class="wan">
			<td class="tl_td">IP 주소</td>
			<td class="co_td"><span id="wan_ipaddr"></span></td>
		</tr>
		<tr class="wan">
			<td class="tl_td">서브넷 마스크</td>
			<td class="co_td"><span id="wan_subnetmask"></span></td>
		</tr>
		<tr class="wan">
			<td class="tl_td">게이트웨이</td>
			<td class="co_td"><span id="wan_gateway"></span></td>
		</tr>
		<tr class="wan">
			<td class="tl_td">DNS 서버</td>
			<td class="co_td"><span id="wan_dns_server"></span></td>
		</tr>
		<tr class="wan">
			<td class="tl_td">MAC 주소</td>
			<td class="co_td"><span id="wan_macaddr"></span></td>
		</tr>
		<tr class="igmp">
			<td colspan="2" class="tbl_title">IGMP 정보</td>
		</tr>
		<tr class="wan">
			<td class="tl_td">IGMP</td>
			<td class="co_td"><span id="igmp_status"><?=$igmp_enable?></span></td>
		</tr>
		<tr class="wan">
			<td class="tl_td">Fast Leave</td>
			<td class="co_td"><span id="igmp_fastleave"><?=$igmp_quickleave?></span></td>
		</tr>
		<tr class="wan">
			<td class="tl_td">Query Interval</td>
			<td class="co_td"><span id="igmp_queryintv"><?=$igmp_query_interval?>초</span></td>
		</tr>
	</tbody>
</table>


	

<style type="text/css">
div {
		width:15px; height:15px; overflow:hidden; background:#8b0000;
}
</style>



<script type="text/javascript">//portSpeed(); portNego();</script>
<table width=550 border="0">
	<tr>
		<td width="100%" colspan="5" class="tbl_title">포트 상태&nbsp;
		<span id='connection_error' style='color:yellow; display:none; font-size:13px;'>인터넷선 연결이 올바르지 않습니다!</span>
		</td>
	</tr>
	<tr bgcolor="#DDDDDD" style="height:50px;">
	<td align="center"><font size="2"><b>WAN</b><div id="wanStatus"></div>
		<span id="wan_port_status"></span></td>
		<td align="center"><font size="2"><b>LAN1</b><div id="lan1Status"></div>
		<span id="lan1_port_status"></span></td>
		<td align="center"><font size="2"><b>LAN2</b><div id="lan2Status"></div>
		<span id="lan2_port_status"></span></td>
		<td align="center"><font size="2"><b>LAN3</b><div id="lan3Status"></div><span id="lan3_port_status"></span></td>
		<td align="center"><font size="2"><b>LAN4</b><div id="lan4Status"></div>
		<span id="lan4_port_status"></span></td>
	</tr>
	<tr><td>
	<br>
	</td></tr>
</table>
<script >portStatus();
//	if(detect_offer_port >= 1 && detect_offer_port <= 4)
//	show_connection_error();
</script>
</table>

<br>
</form>
</blockquote>
</body>
</html>
