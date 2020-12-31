<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");

	/*
		Static list
		network.portautonegenable_1~5
		network.portautoadv_1~5
		network.portspeed_1~5
		network.portduplex_1~5
		network.portflowctrl_1~5
		network.portflowctrlforcemode_1~5
		network.portpoweron_1~5
		network.portpoweroff_1~5
	*/
	$uci = new uci();
	$uci->mode("get");

	for($i=1; $i <= DEF_MAX_PORT; $i++){
		$uci->get("network.portautonegenable_".$i);
		$uci->get("network.portautoadv_".$i);
		$uci->get("network.portspeed_".$i);
		$uci->get("network.portduplex_".$i);
		$uci->get("network.portflowctrl_".$i);
		$uci->get("network.portflowctrlforcemode_".$i);
		$uci->get("network.portpoweron_".$i);
		$uci->get("network.portpoweroff_".$i);
	}
	$uci->run();
	$portinfo = $uci->result();
	if($portinfo == ""){
		$portinfo = "null";
	}
//	print_r($portinfo);
	$uci->close();
	$wan_no = dv_session("wan_no");
	$lan1_no = dv_session("lan_no");
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>포트 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var wan_no = <?=$wan_no?>;
var lan_no = <?=$lan1_no?>;
var portinfo = <?=$portinfo?>;
var cfg_finder = function(cfg_, val_, key_){
	var keylist = Object.keys(val_);
	for(var i=0; i < Object.keys(val_).length; i++){
//		var keylist = Object.keys(val_);
		if(val_[keylist[i]].indexOf(key_) != -1){
			var tmpkey = keylist[i].split(".");
			return tmpkey[0]+"."+tmpkey[1];
			
		}
	}
	return "";
}
/* QCA-50 */
var autoadv_chk = function(p_) {
	var port_no;
	if (p_ == 0) {
		port_no = 2; // LAN1
	} else if (p_ == 1) {
		port_no = 3; // LAN2
	} else if (p_ == 2) {
		port_no = 4; // LAN3
	} else if (p_ == 3) {
		port_no = 5; // LAN4
	} else {
		port_no = 1; // WAN
	}
	var adv = get_obj_val(portinfo,"network.portautoadv_"+port_no+".name");
	if(adv != ""){
		var tmp = "000000000000"+parseInt(get_obj_val(portinfo,"network.portautoadv_"+port_no+".auto_adv"),16).toString(2);
		var advflag = tmp.substring(tmp.length-10,tmp.length);
		$("#p"+p_+"10h").prop("checked",advflag.charAt(9) == "1" ? true : false);
		$("#p"+p_+"10f").prop("checked",advflag.charAt(8) == "1" ? true : false);
		$("#p"+p_+"100h").prop("checked",advflag.charAt(7) == "1" ? true : false);
		$("#p"+p_+"100f").prop("checked",advflag.charAt(6) == "1" ? true : false);
		$("#p"+p_+"pause").prop("checked",advflag.charAt(5) == "1" ? true : false);
		$("#p"+p_+"apause").prop("checked",advflag.charAt(4) == "1" ? true : false);
		$("#p"+p_+"1000f").prop("checked",advflag.charAt(0) == "1" ? true : false);
	}else{
		$("#p"+p_+"10h").prop("checked",true);
		$("#p"+p_+"10f").prop("checked",true);
		$("#p"+p_+"100h").prop("checked",true);
		$("#p"+p_+"100f").prop("checked",true);
		$("#p"+p_+"pause").prop("checked",false);
		$("#p"+p_+"apause").prop("checked",false);
		$("#p"+p_+"1000f").prop("checked",true);
	}
}
function selectSwitch(flag_)
{
	var flag = flag_ ? flag_ : "";
	if (document.port_setup.nego0.selectedIndex == 1) {
		document.port_setup.speed0.disabled = true;
		document.port_setup.duplex0.disabled = true;
		$("#p010h").prop("disabled",false);
		$("#p010f").prop("disabled",false);
		$("#p0100h").prop("disabled",false);
		$("#p0100f").prop("disabled",false);
		$("#p0pause").prop("disabled",false);
		$("#p0apause").prop("disabled",false);
		$("#p01000f").prop("disabled",false);

		/* QCA-50 */
		autoadv_chk(0);
//		if(flag == ""){
//			$("#p010h").prop("checked",true);
//			$("#p010f").prop("checked",true);
//			$("#p0100h").prop("checked",true);
//			$("#p0100f").prop("checked",true);
//			$("#p0pause").prop("checked",false);
//			$("#p0apause").prop("checked",false);
//			$("#p01000f").prop("checked",true);
//		}
	} else {
		document.port_setup.speed0.disabled = false;
		document.port_setup.duplex0.disabled = false;
		$("#p010h").prop("checked",false).prop("disabled",true);
		$("#p010f").prop("checked",false).prop("disabled",true);
		$("#p0100h").prop("checked",false).prop("disabled",true);
		$("#p0100f").prop("checked",false).prop("disabled",true);
		$("#p0pause").prop("checked",false).prop("disabled",true);
		$("#p0apause").prop("checked",false).prop("disabled",true);
		$("#p01000f").prop("checked",false).prop("disabled",true);
	}
	if (document.port_setup.nego1.selectedIndex == 1) {
		document.port_setup.speed1.disabled = true;
		document.port_setup.duplex1.disabled = true;
		$("#p110h").prop("disabled",false);
		$("#p110f").prop("disabled",false);
		$("#p1100h").prop("disabled",false);
		$("#p1100f").prop("disabled",false);
		$("#p1pause").prop("disabled",false);
		$("#p1apause").prop("disabled",false);
		$("#p11000f").prop("disabled",false);

		/* QCA-50 */
		autoadv_chk(1);
//		if(flag == ""){
//			$("#p110h").prop("checked",true);
//			$("#p110f").prop("checked",true);
//			$("#p1100h").prop("checked",true);
//			$("#p1100f").prop("checked",true);
//			$("#p1pause").prop("checked",false);
//			$("#p1apause").prop("checked",false);
//			$("#p11000f").prop("checked",true);
//		}
	} else {
		document.port_setup.speed1.disabled = false;
		document.port_setup.duplex1.disabled = false;
		$("#p110h").prop("checked",false).prop("disabled",true);
		$("#p110f").prop("checked",false).prop("disabled",true);
		$("#p1100h").prop("checked",false).prop("disabled",true);
		$("#p1100f").prop("checked",false).prop("disabled",true);
		$("#p1pause").prop("checked",false).prop("disabled",true);
		$("#p1apause").prop("checked",false).prop("disabled",true);
		$("#p11000f").prop("checked",false).prop("disabled",true);
	}
	if (document.port_setup.nego2.selectedIndex == 1) {
		document.port_setup.speed2.disabled = true;
		document.port_setup.duplex2.disabled = true;
		$("#p210h").prop("disabled",false);
		$("#p210f").prop("disabled",false);
		$("#p2100h").prop("disabled",false);
		$("#p2100f").prop("disabled",false);
		$("#p2pause").prop("disabled",false);
		$("#p2apause").prop("disabled",false);
		$("#p21000f").prop("disabled",false);

		/* QCA-50 */
		autoadv_chk(2);
//		if(flag == ""){
//			$("#p210h").prop("checked",true);
//			$("#p210f").prop("checked",true);
//			$("#p2100h").prop("checked",true);
//			$("#p2100f").prop("checked",true);
//			$("#p2pause").prop("checked",false);
//			$("#p2apause").prop("checked",false);
//			$("#p21000f").prop("checked",true);
//		}
	} else {
		document.port_setup.speed2.disabled = false;
		document.port_setup.duplex2.disabled = false;
		$("#p210h").prop("checked",false).prop("disabled",true);
		$("#p210f").prop("checked",false).prop("disabled",true);
		$("#p2100h").prop("checked",false).prop("disabled",true);
		$("#p2100f").prop("checked",false).prop("disabled",true);
		$("#p2pause").prop("checked",false).prop("disabled",true);
		$("#p2apause").prop("checked",false).prop("disabled",true);
		$("#p21000f").prop("checked",false).prop("disabled",true);
	}
	if (document.port_setup.nego3.selectedIndex == 1) {
		document.port_setup.speed3.disabled = true;
		document.port_setup.duplex3.disabled = true;
		$("#p310h").prop("disabled",false);
		$("#p310f").prop("disabled",false);
		$("#p3100h").prop("disabled",false);
		$("#p3100f").prop("disabled",false);
		$("#p3pause").prop("disabled",false);
		$("#p3apause").prop("disabled",false);
		$("#p31000f").prop("disabled",false);

		/* QCA-50 */
		autoadv_chk(3);
//		if(flag == ""){
//			$("#p310h").prop("checked",true);
//			$("#p310f").prop("checked",true);
//			$("#p3100h").prop("checked",true);
//			$("#p3100f").prop("checked",true);
//			$("#p3pause").prop("checked",false);
//			$("#p3apause").prop("checked",false);
//			$("#p31000f").prop("checked",true);
//		}
	} else {
		document.port_setup.speed3.disabled = false;
		document.port_setup.duplex3.disabled = false;
		$("#p310h").prop("checked",false).prop("disabled",true);
		$("#p310f").prop("checked",false).prop("disabled",true);
		$("#p3100h").prop("checked",false).prop("disabled",true);
		$("#p3100f").prop("checked",false).prop("disabled",true);
		$("#p3pause").prop("checked",false).prop("disabled",true);
		$("#p3apause").prop("checked",false).prop("disabled",true);
		$("#p31000f").prop("checked",false).prop("disabled",true);
	}
	if (document.port_setup.nego4.selectedIndex == 1) {
		document.port_setup.speed4.disabled = true;
		document.port_setup.duplex4.disabled = true;

		$("#p410h").prop("disabled",false);
		$("#p410f").prop("disabled",false);
		$("#p4100h").prop("disabled",false);
		$("#p4100f").prop("disabled",false);
		$("#p4pause").prop("disabled",false);
		$("#p4apause").prop("disabled",false);
		$("#p41000f").prop("disabled",false);
		/* QCA-50 */
		autoadv_chk(4);
//		if(flag == ""){
//			$("#p410h").prop("checked",true);
//			$("#p410f").prop("checked",true);
//			$("#p4100h").prop("checked",true);
//			$("#p4100f").prop("checked",true);
//			$("#p4pause").prop("checked",false);
//			$("#p4apause").prop("checked",false);
//			$("#p41000f").prop("checked",true);
//		}
	} else {
		document.port_setup.speed4.disabled = false;
		document.port_setup.duplex4.disabled = false;
		$("#p410h").prop("checked",false).prop("disabled",true);
		$("#p410f").prop("checked",false).prop("disabled",true);
		$("#p4100h").prop("checked",false).prop("disabled",true);
		$("#p4100f").prop("checked",false).prop("disabled",true);
		$("#p4pause").prop("checked",false).prop("disabled",true);
		$("#p4apause").prop("checked",false).prop("disabled",true);
		$("#p41000f").prop("checked",false).prop("disabled",true);
	}
}

function resetClick()
{
  	document.location.assign("skb_tcpipport.php");
}

function formLoad()
{
	if(portinfo.length == 0){
		$("#nego0").children().eq(1).prop("selected",true);
		$("#nego1").children().eq(1).prop("selected",true);
		$("#nego2").children().eq(1).prop("selected",true);
		$("#nego3").children().eq(1).prop("selected",true);
		$("#nego4").children().eq(1).prop("selected",true);
		$("#duplex0").children().eq(1).prop("selected",true);
		$("#duplex1").children().eq(1).prop("selected",true);
		$("#duplex2").children().eq(1).prop("selected",true);
		$("#duplex3").children().eq(1).prop("selected",true);
		$("#duplex4").children().eq(1).prop("selected",true);
		$("#speed0").children().eq(2).prop("selected",true);
		$("#speed1").children().eq(2).prop("selected",true);
		$("#speed2").children().eq(2).prop("selected",true);
		$("#speed3").children().eq(2).prop("selected",true);
		$("#speed4").children().eq(2).prop("selected",true);
	}else{
		for(var i=0; i < <?=DEF_MAX_PORT?>; i++){
			if(i == 4){
				var port_no = wan_no;
			}else{
				var port_no = lan_no + i;
			}
			if(get_obj_val(portinfo,"network.portautonegenable_"+port_no+".name") == ""){
				//static
				$("#nego"+i).children().eq(0).prop("selected",true);
				var speed = get_obj_val(portinfo,"network.portspeed_"+port_no+".speed");
				if(speed== "1000"){
					$("#speed"+i).children().eq(2).prop("selected",true);
				}else if(speed == "100"){
					$("#speed"+i).children().eq(1).prop("selected",true);
				}else{
					$("#speed"+i).children().eq(0).prop("selected",true);
				}
				var duplex = get_obj_val(portinfo,"network.portduplex_"+port_no+".duplex");
				if(duplex == "full"){
					$("#duplex"+i).children().eq(1).prop("selected",true);
				}else{
					$("#duplex"+i).children().eq(0).prop("selected",true);
				}
			}else{
				//auto nego
				$("#nego"+i).children().eq(1).prop("selected",true);
				$("#duplex"+i).children().eq(1).prop("selected",true);
				$("#speed"+i).children().eq(2).prop("selected",true);
			}
			//PortPoweron or PortPoweroff
			var power = get_obj_val(portinfo,"network.portpoweroff_"+port_no+".name");
			if(power != ""){
				$("#power"+i).children().eq(1).prop("selected",true);
			}else{
				$("#power"+i).children().eq(0).prop("selected",true);
			}
			var Flow = get_obj_val(portinfo,"network.portflowctrl_"+port_no+".name");
			if(Flow != ""){
				if(get_obj_val(portinfo,"network.portflowctrl_"+port_no+".flow_control_status") == "enable"){
					$("#rx"+i+"_pause").children().eq(1).prop("selected",true);
				}else{
					$("#rx"+i+"_pause").children().eq(0).prop("selected",true);
				}
			}else{
				$("#rx"+i+"_pause").children().eq(0).prop("selected",true);
			}
			var fFlow = get_obj_val(portinfo,"network.portflowctrlforcemode_"+port_no+".name");
			if(fFlow != ""){
				if(get_obj_val(portinfo,"network.portflowctrlforcemode_"+port_no+".flow_control_force_mode_status") == "enable"){
					$("#rx"+i+"_fpause").children().eq(1).prop("selected",true);
				}else{
					$("#rx"+i+"_fpause").children().eq(0).prop("selected",true);
				}
			}else{
				$("#rx"+i+"_fpause").children().eq(0).prop("selected",true);
			}
			var adv = get_obj_val(portinfo,"network.portautoadv_"+port_no+".name");
			if(adv != ""){
				var tmp = "000000000000"+parseInt(get_obj_val(portinfo,"network.portautoadv_"+port_no+".auto_adv"),16).toString(2);
				var advflag = tmp.substring(tmp.length-10,tmp.length);
				$("#p"+i+"10h").prop("checked",advflag.charAt(9) == "1" ? true : false);
				$("#p"+i+"10f").prop("checked",advflag.charAt(8) == "1" ? true : false);
				$("#p"+i+"100h").prop("checked",advflag.charAt(7) == "1" ? true : false);
				$("#p"+i+"100f").prop("checked",advflag.charAt(6) == "1" ? true : false);
				$("#p"+i+"pause").prop("checked",advflag.charAt(5) == "1" ? true : false);
				$("#p"+i+"apause").prop("checked",advflag.charAt(4) == "1" ? true : false);
				$("#p"+i+"1000f").prop("checked",advflag.charAt(0) == "1" ? true : false);
			}else{
				$("#p"+i+"10h").prop("checked",false);
				$("#p"+i+"10f").prop("checked",false);
				$("#p"+i+"100h").prop("checked",false);
				$("#p"+i+"100f").prop("checked",false);
				$("#p"+i+"pause").prop("checked",false);
				$("#p"+i+"apause").prop("checked",false);
				$("#p"+i+"1000f").prop("checked",false);
			}
		}
	}
	selectSwitch();
}
var change_pause  = function(num_){
	if($("#rx"+num_+"_pause").children(":selected").val() == "1"){
		$("#p"+num_+"pause").prop("checked",true);
		$("#p"+num_+"apause").prop("checked",true);
	}else{
		$("#p"+num_+"pause").prop("checked",false);
		$("#p"+num_+"apause").prop("checked",false);
	}
}
function apply_button(f)
{
	f.submitBtn.disabled=true;
	f.reset.disabled=true;
	f.port_reset_0.disabled=true;
	f.port_reset_1.disabled=true;
	f.port_reset_2.disabled=true;
	f.port_reset_3.disabled=true;
	f.port_reset_4.disabled=true;
	f.submit();
}

var proc = "proc/skb_tcpipport_proc.php";
var apply_reset = function(c_port, f){
	f._port_reset_0.disabled=true;
	f._port_reset_1.disabled=true;
	f._port_reset_2.disabled=true;
	f._port_reset_3.disabled=true;
	f._port_reset_4.disabled=true;
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'port_reset';
	sobj["port_no"] = c_port;
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
//			console.log(d);
			f._port_reset_0.disabled=false;
			f._port_reset_1.disabled=false;
			f._port_reset_2.disabled=false;
			f._port_reset_3.disabled=false;
			f._port_reset_4.disabled=false;
		}
	});
}
</script>
</head>

<body onload="formLoad();">
<blockquote>
<form action="/proc/skb_tcpipport_proc.php" method="POST" name="port_setup">
<input type="hidden" name="act" id="act" value="form_save">
<input type="hidden" name="wan_no" id="wan_no" value="<?=$wan_no?>">
<input type="hidden" name="lan_no" id="lan_no" value="<?=$lan1_no?>">
<input type="hidden" value="/skb_tcpipport.php" name="submit-url">
<h2>포트 설정</h2>
<table border="0" width="600" cellspacing=4 cellpadding=0>
	<tr>
		<td><font size="2">
		각 포트의 속도, 미디어 속성, 네트워크 모드 및 활성화/비활성화 설정을 할 수 있는 페이지입니다.
		</font></td>
	</tr>
	<tr>
		<td><hr size="1" align="top" noshade="noshade"></td>
	</tr>
</table>
<br>
<table border="0" cellpadding="2" cellspacing="1">
<tr><td colspan="9">&nbsp;</td></tr>
<tr class="tbl_head">
	<td align="center"><b>포트</b></td>
	<td align="center"><b>협상</b></td>
	<td align="center"><b>속도</b></td>
	<td align="center"><b>전송방식</b></td>
	
	<td align="center"><b>흐름제어</b></td>
	<td align="center"><b>흐름제어(강제)</b></td>
	<td align="center"><b>PortAuto(Adv)</b></td>
	<td align="center"><b>전원</b></td>
	
	<td align="center"><b>리셋</b></td>
</tr>

<tr>
	<td align="center" height="25">WAN</td>
	<td align="center" height="25">
	<input type="hidden" name="mode0" value="1">
	  <select name="nego4" id="nego4"  onchange="selectSwitch();">
		<option value=0 >force
		<option value=1>auto</select></td>
	<td align="center" height="25">
	  <select name="speed4" id="speed4" disabled onchange="selectSwitch();">
		<option value="10">10
		<option value="100">100
		<option value="1000">1000</select></td>
	<td align="center" height="25">
	  <select name="duplex4" id="duplex4" disabled onchange="selectSwitch();">
		<option value="0">half
		<option value="1">full</select></td>
	<td align="center" height="25">
		<select name="rx4_pause" id="rx4_pause" onchange="change_pause('4');" style="text-align:center;">
			<option value="0">사용안함</option>
			<option value="1">사용</option>
		</select>
	</td>
	<td align="center" height="25">
		<select name="rx4_fpause" id="rx4_fpause" style="text-align:center;">
			<option value="0">사용안함</option>
			<option value="1">사용</option>
		</select>
	</td>
	<td>
		<input type="checkbox" name="p410h" id="p410h" value="1">10M/H
		<input type="checkbox" name="p410f" id="p410f" value="1">10M/F
		<input type="checkbox" name="p4100h" id="p4100h" value="1">100M/H
		<input type="checkbox" name="p4100f" id="p4100f" value="1">100M/F
		<input type="checkbox" name="p41000f" id="p41000f" value="1">1000M/F
		<input type="checkbox" name="p4pause" id="p4pause" value="1">Pause
		<input type="checkbox" name="p4apause" id="p4apause" value="1">Async Pause
	</td>
	<td align="center" height="25">
	<select name="power4" id="power4">
		<option value="0">ON</option>
		<option value="1">OFF</option>
	</select></td>
	
	<td><input type="button" value="리셋" name="_port_reset_4" onclick="apply_reset(<?=$wan_no?>, this.form);"></td>
</tr>
<?php
	for($i=0; $i < 4; $i++){
?>
<tr>
	<td align="center" height="25">LAN<?=($i+1)?></td>
	<td align="center" height="25">
	  <select name="nego<?=$i?>" id="nego<?=$i?>"  onchange="selectSwitch();">
		<option value="0">force
		<option value="1">auto</select></td>
	<td align="center" height="25">
	  <select name="speed<?=$i?>" id="speed<?=$i?>" onchange="selectSwitch();">
		<option value="10">10
		<option value="100">100
		<option value="1000">1000</select></td>
	<td align="center" height="25">
		<select name="duplex<?=$i?>" id="duplex<?=$i?>" onchange="selectSwitch();">
		<option value="0">half
		<option value="1">full</select></td>
	<td align="center" height="25">
		<select name="rx<?=$i?>_pause" id="rx<?=$i?>_pause"  onchange="change_pause('<?=($i+1)?>');" style="text-align:center;">
			<option value="0">사용안함</option>
			<option value="1">사용</option>
		</select>
	</td>
	<td align="center" height="25">
		<select name="rx<?=$i?>_fpause" id="rx<?=$i?>_fpause" style="text-align:center;">
			<option value="0">사용안함</option>
			<option value="1">사용</option>
		</select>
	</td>
	<td>
		<input type="checkbox" name="p<?=$i?>10h" id="p<?=$i?>10h" value="1">10M/H
		<input type="checkbox" name="p<?=$i?>10f" id="p<?=$i?>10f" value="1">10M/F
		<input type="checkbox" name="p<?=$i?>100h" id="p<?=$i?>100h" value="1">100M/H
		<input type="checkbox" name="p<?=$i?>100f" id="p<?=$i?>100f" value="1">100M/F
		<input type="checkbox" name="p<?=$i?>1000f" id="p<?=$i?>1000f" value="1">1000M/F
		<input type="checkbox" name="p<?=$i?>pause" id="p<?=$i?>pause" value="1">Pause
		<input type="checkbox" name="p<?=$i?>apause" id="p<?=$i?>apause" value="1">Async Pause
	</td>
	<td align="center" height="25">
		<select name="power<?=$i?>" id="power<?=$i?>">
			<option value="0">ON</option>
			<option value="1">OFF</option>
		</select></td>
	<td><input type="button" value="리셋" name="_port_reset_<?=$i?>" id="_port_reset_<?=$i?>" onclick="apply_reset(<?=$lan1_no + $i?>, this.form);"></td>
</tr>
<?}?>

<tr><td colspan=9>&nbsp;</td></tr>
<tr>
	<td colspan="9">
		<input type="button" value="적용" name="submitBtn" onclick="apply_button(this.form);">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
		<input type="button" value="취소" name="reset" onclick="resetClick();">
		<input type="hidden" value="리셋" name="port_reset_0">
		<input type="hidden" value="리셋" name="port_reset_1">
		<input type="hidden" value="리셋" name="port_reset_2">
		<input type="hidden" value="리셋" name="port_reset_3">
		<input type="hidden" value="리셋" name="port_reset_4">
	</td>
</tr>
</table>
</form>
<br>
<br>
<br>
</blockquote>
</body>
</html>
