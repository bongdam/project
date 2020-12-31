<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$uci = new uci();
	$uci->mode("get");
	$uci->get("network.lan");
	$uci->get("dvui.network");
	$uci->run();
	$lan = $uci->result();
	if($lan == ""){
		$lan = "null";
	}
	$cfg = new dvcfg();
	$cfg->read("dvui","network");
	$cfg->read("wireless","wifi0");
	$cfg->read("wireless","wifi1");
	$cfg->read("wireless","vap07");
	$cfg->read("wireless","vap17");
	$wep_key0 = $cfg->search("wireless.vap07.key1");
	$wep_key1 = $cfg->search("wireless.vap17.key1");
	$cfg->result_remove("wireless.vap07.key");
	$cfg->result_remove("wireless.vap17.key");
	$cfg->result_remove("wireless.vap07.key1");
	$cfg->result_remove("wireless.vap17.key1");
	$cfg->result_remove("wireless.vap07.key2");
	$cfg->result_remove("wireless.vap17.key2");
	$cfg->result_remove("wireless.vap07.key3");
	$cfg->result_remove("wireless.vap17.key3");
	$cfg->result_remove("wireless.vap07.key4");
	$cfg->result_remove("wireless.vap17.key4");
	$wifi = $cfg->result("json_string");
	$wifiobj = $cfg->result("object");
	$wep_key24 = "";
	$wep_key5 = "";
	if($wep_key0 != ""){
		$wep_key5 = "1";
	}
	if($wep_key1 != ""){
		$wep_key24 = "1";
	}
	$wds = "";
	if($fp = fopen("/tmp/repeater_state", 'r')){ 
		// 바이너리로 읽기 
		// 파일 포인터로 지정된 파일에서 최대 길이 1024*100 만큼 브라우저로 출력합니다. 
		$wds = rtrim(fread($fp, filesize("/tmp/repeater_state")));
		fclose($fp); 
	}
?>
<!DOCTYPE html>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<title>운용 모드 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var lan = <?=$lan?>;
var wifi = <?=$wifi?>;
var repeater_radio = "";
var vap = "";
var wep_key24 = "<?=$wep_key24?>";
var wep_key5 = "<?=$wep_key5?>";
var wds = "<?=$wds?>";
function click_apply()
{
	var regPwd = /^.*(?=.*\d)(?=.*[a-zA-Z])(?=.*[^a-zA-Z0-9]).*$/;
	var reg = /[^0-9a-fA-F]{1,}/;
	var ssid = document.formSetOperation.repeater_ssid;
	var repeater_intf = document.formSetOperation.repeater_intf;
	var operation_mode = document.formSetOperation.operation_mode;
	var method_index = document.formSetOperation.method.selectedIndex;
	var repeater_radio;
	var ret="";
	var auth;

//	if (operation_mode[0].checked == false && operation_mode[1].checked == false && operation_mode[2].checked == false) {
	if (operation_mode[0].checked == false && operation_mode[1].checked == false && operation_mode[2].checked == false) {
		alert("운용 모드가 선택되지 않았습니다.");
		return false;
	}
	if($("#prev_op_mode").val() == $("[name=operation_mode]:checked").val()){
		if($("#prev_op_mode").val() == "0" || $("#prev_op_mode").val() == "1"){
			alert("변경 사항이 존재하지 않습니다.");
			return false;
		}
	}
	if($("[name=operation_mode]:checked").val() == "2"){
		if($("#method").children(":selected").val() == "wpa" || $("#method").children(":selected").val() == "wpa2" || $("#method").children(":selected").val() == "wpa-mixed"){
			var enc = $("#method").children(":selected").val().replace("wpa","psk");
			var cipher = "";
			if($("#cipher0").prop("checked") == true && $("#cipher1").prop("checked") == true){
				cipher = "tkip+aes";
			}else if($("#cipher0").prop("checked") == true){
				cipher = "tkip";
			}else if($("#cipher1").prop("checked") == true){
				cipher = "aes";
			}else{
				alert("WPA Cipher Suite를 선택해주세요.");
				return;
			}
			enc = enc + "+" + cipher;
			$("#enc").val(enc);
			$("#wifi_mode").val("psk");
			if($("#psk_key").val() == ""){
				alert("Pre-Shared Key를 입력해주세요.");
				$("#psk_key").focus();
				return;
			}
			if($("#psk_type").children(":selected").val() == "ascii"){
				if($("#psk_key").val().length < 8 || $("#psk_key").val().length > 63){
					alert("Pre-Shared Key가 8자 미만이거나 63자를 초과했습니다.");
					$("#psk_key").focus();
					return;
				}
				
//				if(!regPwd.test($("#psk_key").val())) {
//					alert('Pre-Shared Key는 영문, 숫자, 특수문자가 조합 되어야 합니다.\n특수문자는 `,~,!,@,#,$,%,^,&,*,(,),-,_,+,=,공백만 사용 가능합니다.');
//					$("#psk_key").focus();
//					return false;
//				}
			}else{
				if($("#psk_key").val().replace(reg,'').length < $("#psk_key").val().length){
					alert("0~9 또는 a~f를 입력해 주시기바랍니다.");
					$("#psk_key").focus();
					return;
				}
				if($("#psk_key").val().length != 64){
					alert("Pre-Shared Key를 64자 입력해주세요.");
					$("#psk_key").focus();
					return;
				}
			}
			if($("#psk_key_con").val() == ""){
				alert("Pre-Shared Key 재입력을 입력해주세요.");
				$("#psk_key_con").focus();
				return;
			}
			
			if($("#psk_key").val() != $("#psk_key_con").val()){
				alert("Pre-Shared Key가 일치하지 않습니다.");
				$("#psk_key").focus();
				return;
			}
		}else if($("#method").children(":selected").val() == "wep"){
			var enc = $("#method").children(":selected").val().replace("wpa","psk");
			var cipher = $("[name='auth_type']:checked").val();
			enc = enc + "+" + cipher;
			$("#enc").val(enc);
			$("#wifi_mode").val("wep");
			var wep_len = $("#wep_key_len").children(":selected").val();
			var ck_len = 5;
			var wep_type = $("#wep_key_type").children(":selected").val();
			if(wep_type == "ascii" && wep_len == "64"){
				ck_len = 5;
			}else if(wep_type == "hex" && wep_len == "64"){
				ck_len = 10;
			}else if(wep_type == "ascii" && wep_len == "128"){
				ck_len = 13;
			}else if(wep_type == "hex" && wep_len == "128"){
				ck_len = 26;
			}
			var mask_val = "";
			for (var i=0; i < ck_len ; i++ )
			{
				mask_val += "*";
			}
			//select_key wep_key wep_key_con
			var wep_key_index = $("#select_key").children(":selected").val();
			var wep_key_val = $("#wep_key").val();
			if(wep_key_val.replace(mask_val,"") == ""){
				alert("암호화 Key가 비어있습니다.");
				$("#wep_key").focus();
				return;
			}
			
			if(wep_key_val.length != ck_len){
				alert("암호화 Key의 값이 " + ck_len + "자를 입력해주세요.");
				$("#wep_key").focus();
				return;
			}
			if(wep_type == "ascii"){
				if(check_to_passwd(wep_key_val) == 0){
					alert('암호화 KEY는 영문, 숫자, 특수문자가 조합 되어야 합니다.\n특수문자는 `,~,!,@,#,$,%,^,&,*,(,),-,_,+,=,공백만 사용 가능합니다.');
					$("#wep_key").focus();
					return;
				}
			}else{
				if(wep_key_val.replace(reg,'').length < wep_key_val.length && mask_val != wep_key_val){
					alert('암호화 KEY는 0~9 또는 a~f를 입력해 주시기바랍니다.');
					$("#wep_key").focus();
					return;
				}
			}
			if($("#wep_key_con").val() == ""){
				alert("암호화 Key 재입력을 입력해주세요.");
				$("#wep_key_con").focus();
				return;
			}
			if($("#wep_key_con").val() != wep_key_val){
				alert("암호화 Key 일치하지 않습니다.");
				$("#wep_key_con").focus();
				return;
			}
		}else if($("#method").children(":selected").val() == "none"){
			$("#wifi_mode").val("none");
		}
	}
	document.formSetOperation.submit();
	return true;
}


function resetForm()
{
	document.location.assign("skb_operate_mode.php");
}

function show_search_ap()
{
	var wlan_idx;
	if (document.formSetOperation.radio[0].checked==true) {
		wlan_idx=0;
	} else if (document.formSetOperation.radio[1].checked==true) {
		wlan_idx=1;
	} else {
		alert("선택된 무선이 없습니다.");
		return;
	}
	//ap검색 창 open(radio 버튼 추가)
	openWindow('wlan_redriect.php?redirect-url=skb_repeater_search_ap.php&wlan_id='+wlan_idx+"#form", 'skb_repeater_search_ap', 920, 700 );

}



function change_authentication()
{
	var method = "";
	var method_index = document.formSetOperation.method.selectedIndex;
	$("#repeater_div").show();
	$("#psk_div").hide();
	$("#wep_div").hide();
	if (method_index == 4) { //none
		method = "none";
	} else if (method_index == 3) {	//wep
		method = "wep";
		$("#wep_div").show();
	} else { //wpa
		method = "wpa";
		$("#psk_div").show();
	}
	if($("#radio1").prop("checked") == true){
		vap = "vap07";
	}else{
		vap = "vap17";
	}
	if(method != "wep" && method != "none"){
		var cipher = clean_cipher(get_json_val(wifi,"wireless."+vap+".encryption"));
		if(cipher == "tkip+aes"){
			$("#cipher0").prop("checked",true);
			$("#cipher1").prop("checked",true);
		}else if(cipher == "tkip"){
			$("#cipher0").prop("checked",true);
		}else{
			$("#cipher1").prop("checked",true);
		}
		set_default_key("psk");
	}else if(method == "wep"){
		var cipher = clean_cipher(get_json_val(wifi,"wireless."+vap+".encryption"));
		if(cipher == "open"){
			$("[name='auth_type']").eq(0).prop("checked",true);
		}else if(cipher == "shared"){
			$("[name='auth_type']").eq(1).prop("checked",true);
		}else{
			$("[name='auth_type']").eq(2).prop("checked",true);
		}
		var wep_key_len = get_json_val(wifi,"wireless."+vap+".wep_key_len",64);
		var wep_index = get_json_val(wifi,"wireless."+vap+".wep_key",1);
		var wep_key_type = get_json_val(wifi,"wireless."+vap+".wep_key_type","ascii");
		$("#wep_key_len").val(wep_key_len);
		$("#select_key").val(wep_index);
		$("#wep_key").val("");
		$("#wep_key_type").val(wep_key_type);
		change_wep_key_len();
		set_default_key("wep");
	}
}

function clean_method(val_)
{
	var auth = "";
	if(val_.indexOf("psk-mixed") > -1){
		auth = "wpa-mixed";
	}else if(val_.indexOf("wpa-mixed") > -1){
		auth = "wpa-mixed";
	}else if(val_.indexOf("psk2") > -1){
		auth = "wpa2";
	}else if(val_.indexOf("wpa2") > -1){
		auth = "wpa2";
	}else if(val_.indexOf("psk") > -1){
		auth = "wpa";
	}else if(val_.indexOf("wpa") > -1){
		auth = "wpa";
	}else if(val_.indexOf("wep") > -1){
		auth = "wep";
	}else{
		auth = "none";
	}
	return auth;
}
var clean_cipher = function(val_){
	var auth = "";
	if(val_.indexOf("tkip+aes") > -1){
		auth = "tkip+aes";
	}else if(val_.indexOf("aes") > -1){
		auth = "aes";
	}else if(val_.indexOf("tkip") > -1){
		auth = "tkip";
	}else if(val_.indexOf("mixed") > -1 && val_.indexOf("wep") > -1){
		auth = "mixed";
	}else if(val_.indexOf("open") > -1 && val_.indexOf("wep") > -1){
		auth = "open";
	}else if(val_.indexOf("shared") > -1 && val_.indexOf("wep") > -1){
		auth = "shared";
	}
	return auth;
}
var change_wep_key_len = function(){
	var wep_len = $("#wep_key_len").children(":selected").val();
	if(wep_len == "64"){
		$("#wep_key_type").children().eq(0).text("ASCII (5 characters)");
		$("#wep_key_type").children().eq(1).text("HEX (10 characters)");
	}else{
		$("#wep_key_type").children().eq(0).text("ASCII (13 characters)");
		$("#wep_key_type").children().eq(1).text("HEX (26 characters)");
	}
}
var check_wifi_mode = function(val_){
//	wireless.vap00.encryption
}
var set_default_key = function(mode_){
	var result = "";
	if(mode_ == "psk"){
		result = "********";
		$("#psk_key").val("");
		$("#psk_key_con").val("");
	}else if(mode_ == "wep"){
		
	}
}
function change_op_mode()
{
	if (document.formSetOperation.operation_mode[2].checked == true) {
		//05/14
		document.getElementById("repeater_div").style.display="";
		if(get_json_val(wifi,"dvui.network.repeater_radio") == "1"){
			$("#radio1").prop("checked",true);
			//5Ghz
			repeater_radio = "1";
			vap = "vap07";
		}else{
			$("#radio0").prop("checked",true);
			//2Ghz
			repeater_radio = "0";
			vap = "vap17";
		}
		$("#ssid").val(get_json_val(wifi,"wireless."+vap+".ssid"));
		var method = clean_method(get_json_val(wifi,"wireless."+vap+".encryption"));
		$("#method").val(method);
		change_authentication();
	}else{
		$("#repeater_div").hide();
		$("#psk_div").hide();
		$("#wep_div").hide();
	}
}
$(document).ready(function(){
	var dv_opmode = get_json_val(wifi,"dvui.network.opmode");
	var dv_repeater = get_json_val(wifi,"dvui.network.repeater");
	if(dv_opmode == "bridge" && dv_repeater == "0"){
		var op_mode = 0;
		$("#lan_ifname").val(lan["network.lan._orig_ifname"]);
		$("#lan_ipaddr").val(lan["network.lan._orig_ipaddr"]);
		$("#lan_netmask").val(lan["network.lan._orig_netmask"]);
	}else if(dv_opmode == "nat" && dv_repeater == "0"){
		var op_mode = 1;
		$("#lan_ifname").val(lan["network.lan.ifname"]);
		$("#lan_ipaddr").val(lan["network.lan.ipaddr"]);
		$("#lan_netmask").val(lan["network.lan.netmask"]);
	}else{
		var op_mode = 2;
		$("#radio"+get_json_val(wifi,"dvui.network.repeater_radio",0)).prop("checked",true);
	}
	$("#operation_mode"+op_mode).prop("checked",true);
	$("#prev_op_mode").val(op_mode);
	change_op_mode();
//	var repeater_enable_1 = 0;
//	var repeater_enable_2 = 0;
	
//	if(op_mode==0 && repeater_enable_1==0 && repeater_enable_2==0) {	//NAT
//		document.formSetOperation.operation_mode[1].checked = true;
//	} else if(op_mode==1 && repeater_enable_1==0 && repeater_enable_2==0) {	//Bridge
//		document.formSetOperation.operation_mode[0].checked = true;
//	} else {	//Repeater
////		document.formSetOperation.operation_mode[2].checked = true;
//	}
//	change_op_mode();
});

</script>
<blockquote>
<body>
<b><font size="3" face="arial" color="#3c7A95">운용 모드 설정</font></b>
<!--  네트워크 모드(Bridge, Gateway, Repeater)를 변경할 수 있는 페이지입니다. -->
<table border="0" width="650" cellspacing="4" cellpadding="0">
	<tr>
		<td><font size="2"><br>네트워크 모드(Bridge, Gateway, Repeater)를 변경할 수 있는 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><font color="red">Repeater 모드 설정 시 인터넷(WAN)선을 제거해주시기 바랍니다.<br></font></td>
	</tr>
<script type="text/javascript">
	/* 0:repeater enabled     */
	/* 1:not found ssid       */
	/* 2:failed encrypt format */
	/* 4:failed wpa password */
	/* 8:wep mode - failed password or dhcp not bound */
	/* 16:not wan bound (wpa, disabled mode) */
//	var repeater_fail = parseInt(2, 10);
//	var fail_str;
//	var repeater_enable_1 = 0;
//	var repeater_enable_2 = 0;
//	if (repeater_enable_1 == 1 || repeater_enable_2 == 1) {
//		if (repeater_fail == 0) {
//			fail_str="Repeater 연결 : 메인 AP와 Repeater Mode로 연결 되었습니다.";
//		} else if (repeater_fail==1) {
//			fail_str="Repeater 연결 실패 : 입력한 SSID를 찾을 수 없습니다.";
//		} else if (repeater_fail==2) {
//			fail_str="Repeater 연결 실패 : 선택한 인증보안방식이 메인 AP와 다릅니다.";
//		} else if (repeater_fail==4) {
//			fail_str="Repeater 연결 실패 : 잘못된 Password(WPA Mode)로 메인 AP와 연결 할 수 없습니다.";
//		} else if (repeater_fail==8) {
//			fail_str="Repeater 연결 실패 : 잘못된 Password(WEP Mode) 또는 메인 AP로부터 IP 할당을 받지 못하여 연결 할 수 없습니다.";
//		} else if (repeater_fail==16) {
//			fail_str="Repeater 연결 실패 : 메인 AP로부터 IP 할당을 받지 못하여 연결 할 수 없습니다.";
//		} else {
//			fail_str="Repeater 연결 실패 : 운용 모드 설정 페이지의 Repeater 설정을 확인해 주세요.";
//		}
//
//		document.write("<tr>");
//		document.write("	<td ><font color='red'>"+fail_str+"<br></font></td>");
//		document.write("</tr>");
//	}
</script>
<?php
	if(get_json_val($wifiobj,"dvui.network.repeater") == "1"){
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
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>

<form name="formSetOperation" action="/proc/skb_operate_mode_proc.php" method="POST" onSubmit="return false;">
<input type="hidden" name="lan_ifname" id="lan_ifname" value="">
<input type="hidden" name="lan_ipaddr" id="lan_ipaddr" value="">
<input type="hidden" name="lan_netmask" id="lan_netmask" value="">
<input type="hidden" name="prev_op_mode" id="prev_op_mode" value="">
<input type="hidden" name="dv_opmode" id="dv_opmode" value="">
<input type="hidden" name="dv_repeater" id="dv_repeater" value="">
<input type="hidden" name="enc" id="enc" value="">
<input type="hidden" name="wifi_mode" id="wifi_mode" value="">

	<input type="hidden" name="page" value="/skb_operate_mode.php">
	<table border="0" width="650" cellspacing="4" cellpadding="0">
		<tr>
			<td width="25%">
				<input type="radio" name="operation_mode" id="operation_mode0" value="0" onclick="change_op_mode()">Bridge Mode :
			</td>
			<td width="75%">
				단순히 포트간 통신만을 지원하는 모드 입니다.(공유기 모드가 사라집니다)
			</td>
		</tr>
		<tr>
			<td width="25%">
				<input type="radio" name="operation_mode" id="operation_mode1" value="1" onclick="change_op_mode()">Gateway Mode :
			</td>
			<td width="75%">
				사설 IP를 이용하여 네트워크 주소를 나누어 사용할 수 있는 모드입니다.
			</td>
		</tr>
		<tr>
			<td width="25%">
				<input type="radio" name="operation_mode" id="operation_mode2" value="2" onclick="change_op_mode()">Repeater Mode :
			</td>
			<td width="75%">
				AP 신호를 증폭하여 원활한 WiFi 서비스가 이루어 지도록 하는 모드입니다.
			</td>
		</tr>
	</table><br>
	<div id="repeater_div" style="width:500px;display:none;">
		<table id="repeater_mode" name="repeater_mode" border="0" width="500" cellspacing="4" cellpadding="0" >
			<tr>
				<td width="35%">&nbsp;무선 :</td>
				<td width="65%">
					<input type="radio" name="radio" id="radio0" value="0">2.4GHz&nbsp;&nbsp;
					<input type="radio" name="radio" id="radio1" value="1">5GHz
				</td>
			</tr>
			<tr>
				<td width="35%">&nbsp;Repeater SSID :</td>
				<td width="65%">
					<input type="text" name="ssid" id="ssid" size="33" maxlength="32" value="">&nbsp;&nbsp;
					<input type="button" name="search_ssid" value="AP 검색" onclick="show_search_ap();">
				</td>
			</tr>
			<tr>
				<td width="35%">&nbsp;인증 보안 방식 :</td>
				<td width="65%">
					<select size="1" id="method" name="method" onchange="change_authentication()">
						<option value="wpa-mixed"> WPA-Mixed </option>
						<option value="wpa2"> WPA2 </option>
						<option value="wpa"> WPA </option>
						<option value="wep"> WEP </option>
						<option value="none"> disable </option>
					</select>
				</td>
			</tr>
		</table>
	</div>
	<div id="psk_div" style="display:none;">
		<table border="0" width="500" cellspacing="4" cellpadding="0" >
			<tr>
				<td width="35%" class="bgblue"><font size="2"><b>WPA Cipher Suite:</b></font></td>
				<td width="65%" class="bggrey"><font size="2">
					<input type="checkbox" name="cipher" id="cipher0" value="tkip" >TKIP&nbsp;
					<input type="checkbox" name="cipher" id="cipher1" value="aes">AES
				</font></td>
			</tr>
			<tr>
				<td width="35%" class="bgblue"><font size="2"><b>Key 형식:</b></font></td>
				<td width="65%" class="bggrey"><font size="2">
					<select id="psk_type" name="psk_type" onchange="change_psk_mode();">
						<option value="ascii">ASCII (8~63 characters)</option>
						<option value="hex">Hex (64 characters)</option>
					</select>
				</td>
			</tr>
			<tr>
				<td width="35%" class="bgblue"><font size="2"><b>Pre-Shared&nbsp;Key:</b></font></td>
				<td width="65%" class="bggrey" id="psk_key_area">
					<input type="password" name="psk_key" id="psk_key" size="32" maxlength="64" value="">
<!-- 					 &nbsp;<input type="checkbox" name="chk_psk_view" id="chk_psk_view" value="1">보이기 -->
				</td>
			</tr>
			<tr>
				<td width="35%" class="bgblue"><font size="2"><b>Pre-Shared&nbsp;Key 재입력:</b></font></td>
				<td width="65%" class="bggrey" id="psk_key_area_con">
					<input type="password" name="psk_key_con" id="psk_key_con" size="32" maxlength="64" value="" >
				</td>
			</tr>
		</table>
	</div>
	<div id="wep_div" style="display:none;">
		<table border="0" width="500" cellspacing="4" cellpadding="0" >
			<tr>
				<td width="35%" class="bgblue"><font size="2"><b>인증:</b></font></td>
				<td width="65%" class="bggrey"><font size="2">
				<input name="auth_type" type="radio" value="open">Open System
				<input name="auth_type" type="radio" value="shared">Shared Key
				<input name="auth_type" type="radio" value="mixed" checked>Auto
				</font></td>
			</tr>
			<tr>
				<td width="35%" class="bgblue"><font size="2"><b>Key 길이:</b></font></td>
				<td width="65%" class="bggrey"><font size="2">
				<select size="1" name="wep_key_len" id="wep_key_len" onchange="change_wep_key_len();">
					 <option value="64"> 64-bit</option>
					 <option value="128">128-bit</option>
				</select>
				</font></td>
			</tr>
			<tr>
				<td width="35%" class="bgblue"><font size="2"><b>Key 형식:</b></font></td>
				<td width="65%" class="bggrey"><font size="2">
				<select size="1" name="wep_key_type" id="wep_key_type" onchange="">
					 <option value="ascii">Ascii</option>
					 <option value="hex">hex</option>
				</select>
				</font></td>
			</tr>
			<tr>
				<td width="35%" class="bgblue"><font size="2"><b>암호화 Key :</b></font></td>
				<td width="65%" class="bggrey" id="wep_key_parent">
					<select name="select_key" id="select_key">
						 <option value="1"> 1</option>
						 <option value="2"> 2</option>
						 <option value="3"> 3</option>
						 <option value="4"> 4</option>
					</select>
					<input type="password" id="wep_key" name="wep_key" maxlength="26" size="26" value="">
				</td>
			</tr>
			<tr>
				<td width="35%" class="bgblue"><font size="2"><b>암호화 Key 재입력:</b></font></td>
				<td id="check_wep_key_parent">
					&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
					<input type="password" id="wep_key_con" name="wep_key_con" maxlength="26" size="26" value="" >
				</td>
			</tr>
		</table>
	</div>

	<br>
	<input type="button" value="적용" name="save" onclick="click_apply();">
	<input type="hidden" value="/skb_operate_mode.php" name="submit-url" >
	<input type="reset" value="취소" name="reset" onclick="resetForm();">



</form>
</blockquote>

</body>
</html>
