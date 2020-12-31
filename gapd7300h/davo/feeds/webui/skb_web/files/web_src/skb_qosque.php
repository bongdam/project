<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$uci = new uci();
	$uci->mode("get");
	for($i=1; $i < 6; $i++){
		$uci->get("network.qosptschmode_".$i);
	}
	$uci->run();
	$port = json_encode(json_decode($uci->result(),true));
	$uci->close();
	$wan_no = dv_session("wan_no");
	$lan1_no = dv_session("lan_no");
	$uci = new uci();
	for($i=1; $i < 6; $i++){
		$uci->get("network.rateportpolicer_".$i);
		$uci->get("network.rateportshaper_".$i);
	}
	$uci->run();
	$rate = json_encode(json_decode($uci->result(),true));
	$uci->close();
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>QUEUE 출력 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<script type="text/javascript" src="js/skb_util_qos.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var qos_info = <?=$port?>;
var qos_rate = <?=$rate?>;
var wan_no = <?=dv_session("wan_no")?>;
var qos_mode = {
	"sp":["SPQ","SPQ","SPQ","SPQ"],
	"mix":["WRR","WRR","WRR","SPQ"],
	"mixplus":["WRR","WRR","SPQ","SPQ"],
	"wrr":["WRR","WRR","WRR","WRR"]
}

var result_no = new Array(5);
var result_mode = new Array(5);
var result = new Array(5);
var result_we = new Array(5);
var result_rate = new Array(5);
var result_inrate = new Array(5);
var result_outrate = new Array(5);

function qosEnChanged(v)
{
	var en;

	if (v == true)
		en = false;
	else
		en = true;

//	document.qos.qtype3.disabled=en;
	document.qos.qweight3.disabled=en;

//	document.qos.qtype2.disabled=en;
	document.qos.qweight2.disabled=en;

//	document.qos.qtype1.disabled=en;
	document.qos.qweight1.disabled=en;

//	document.qos.qtype0.disabled=en;
	document.qos.qweight0.disabled=en;
}

function rateEnChanged(v)
{
	if ( v == true) {
		document.qos.in_rate.disabled = false;
		document.qos.out_rate.disabled = false;
	} else {
		document.qos.in_rate.disabled = true;
		document.qos.out_rate.disabled = true;
	}
}
var prev_port = "";
var port_change = function(){
	var port_no = $("#port_num").children(":selected").val();
	result_no[prev_port] = prev_port;
	result_mode[prev_port] = $("#que_enable").prop("checked") ? "1" : "0";
	result[prev_port] =  $("#port_mode").val();
	if(prev_port == "5"){
		result_we[prev_port] = $("#qweight0").val() + "," + $("#qweight0").val() + "," + $("#qweight1").val() + "," + $("#qweight1").val() + "," + $("#qweight2").val() + ","+$("#qweight3").val();
	}else{
		result_we[prev_port] = $("#qweight0").val() + "," + $("#qweight1").val() + "," + $("#qweight2").val() + "," + $("#qweight3").val()+",0,0";
	}
	result_rate[prev_port] = $("#rate_enable").prop("checked") ? "1" : "0";
	result_inrate[prev_port] = $("#in_rate").val();
	result_outrate[prev_port] = $("#out_rate").val();
	if(result_mode[port_no] == undefined){
		$("#que_enable").prop("checked",false);
	}else{
		if(result_mode[port_no] == "1"){
			$("#que_enable").prop("checked",true);
		}else{
			$("#que_enable").prop("checked",false);
		}
	}
	if(result[port_no] == undefined){
		$("#port_mode").val("mixplus");
	}else{
		$("#port_mode").val(result[port_no]);
	}
	if(result_we[port_no] == undefined){
		$("#qweight3").val("1");
		$("#qweight2").val("1");
		$("#qweight1").val("7");
		$("#qweight0").val("3");
		result_we[port_no] = "3,7,1,1,0,0";
		qosEnChanged(false);
	}else{
		var temp_we = result_we[port_no].split(",");
		if(port_no == "5"){
			console.log(temp_we);
			$("#qweight3").val(temp_we[5]);
			$("#qweight2").val(temp_we[4]);
			$("#qweight1").val(temp_we[2]);
			$("#qweight0").val(temp_we[0]);
		}else{
			$("#qweight3").val(temp_we[3]);
			$("#qweight2").val(temp_we[2]);
			$("#qweight1").val(temp_we[1]);
			$("#qweight0").val(temp_we[0]);
		}
//		var result_rate = new Array(5);
//		var result_inrate = new Array(5);
//		var result_outrate = new Array(5);
		if(result_rate[port_no] == "1"){
			$("#rate_enable").prop("checked",true);
		}else{
			$("#rate_enable").prop("checked",false);
		}
		$("#in_rate").val(result_inrate[port_no]);
		$("#out_rate").val(result_outrate[port_no]);
		qosEnChanged(true);
	}
	change_qos_mode();
	prev_port = port_no;
}
var change_qos_mode = function(){
	var port_no = $("#port_num").children(":selected").val();
	var port_mode = $("#port_mode").children(":selected").val();
	for (var i=3 ; i >= 0 ; i--)
	{
		$("#qtype"+i).val(qos_mode[port_mode][i]);
	};
	result[port_no] = port_mode;
	if(port_no == "5"){
		result_we[port_no] = $("#qweight0").val() + "," + $("#qweight0").val() + "," + $("#qweight1").val() + "," + $("#qweight1").val() + "," + $("#qweight2").val() + ","+$("#qweight3").val();
	}else{
		result_we[port_no] = $("#qweight0").val() + "," + $("#qweight1").val() + "," + $("#qweight2").val() + "," + $("#qweight3").val() + ",0,0";
	}
}
var save_data = function(f){
	var port_no = $("#port_num").children(":selected").val();
	result_mode[port_no] = $("#que_enable").prop("checked") ? "1" : "0";
	result[port_no] =  $("#port_mode").val();
	result_we[port_no] = $("#qweight0").val() + "," + $("#qweight1").val() + "," + $("#qweight2").val() + "," + $("#qweight3").val() + ",0,0";
	result_rate[port_no] = $("#rate_enable").prop("checked") ? "1" : "0";
	result_inrate[port_no] = $("#in_rate").val();
	result_outrate[port_no] = $("#out_rate").val();
	for(var i=1; i < result.length; i++){
//		console.log(i,result[i]);
		$("#qos_port_no"+i).val(result_no[i]);
		$("#qos_enable"+i).val(result_mode[i]);
		$("#qos_mode"+i).val(result[i]);
		$("#qos_weight"+i).val(result_we[i]);
		$("#qos_rate"+i).val(result_rate[i]);
		$("#qos_in_rate"+i).val(result_inrate[i]);
		$("#qos_out_rate"+i).val(result_outrate[i]);
	}
	f.submit();
//	return false;
	
}
function do_init()
{
	prev_port = $("#port_num").children(":selected").val();
	if(qos_info.length == 0){
		$("#port_mode").val("sp");
		$("#qweight3").val("0");
		$("#qweight2").val("0");
		$("#qweight1").val("7");
		$("#qweight0").val("3");
		$("#que_enable").prop("checked",true);
		for (var i=1;i <= 5 ; i++ ){
			result_no[i] = i;
			result_mode[i] = "1";
			result[i] = "sp";
			if(i == 5){
				result_we[i] = "3,3,7,7,0,0";
			}else{
				result_we[i] = "3,7,0,0,0,0";
			}
		}
		$("#qweight3").val("0");
		$("#qweight2").val("0");
		$("#qweight1").val("7");
		$("#qweight0").val("3");
	}else{
		$("#port_mode").val(qos_info["network.qosptschmode_"+wan_no+".mode"]);
		var wan_weight = qos_info["network.qosptschmode_"+wan_no+".weight"].split(",");
		if(wan_no == 5){
			$("#qweight0").val(wan_weight[0]);
			$("#qweight1").val(wan_weight[2]);
			$("#qweight2").val(wan_weight[4]);
			$("#qweight3").val(wan_weight[5]);
		}else{
			$("#qweight0").val(wan_weight[0]);
			$("#qweight1").val(wan_weight[1]);
			$("#qweight2").val(wan_weight[2]);
			$("#qweight3").val(wan_weight[3]);
		}
		$("#que_enable").prop("checked",true);
		for (var i=1;i <= 5 ; i++ ){
			result_no[i] = qos_info["network.qosptschmode_"+i+".port_id"];
			result_mode[i] = "1";
			result[i] = qos_info["network.qosptschmode_"+i+".mode"];
			result_we[i] = qos_info["network.qosptschmode_"+i+".weight"];
		}
	}
	change_qos_mode();
	if(qos_rate.length == 0){
		$("#in_rate,#out_rate").val("0");
		for (var i=1;i <= 5 ; i++ ){
			result_rate[i] = "0";
			result_inrate[i] = 0;
			result_outrate[i] = 0;
		}
		$("#rate_enable").prop("checked",false);
		$("#in_rate").val("0");
		$("#out_rate").val("0");
	}else{
		if(qos_rate["network.rateportpolicer_"+wan_no+".cir"] == "0"){
			$("#rate_enable").prop("checked",false);
		}else{
			$("#rate_enable").prop("checked",true);
		}
		$("#in_rate").val(qos_rate["network.rateportpolicer_"+wan_no+".cir"]);
		$("#out_rate").val(qos_rate["network.rateportshaper_"+wan_no+".cir"]);
		for (var i=1;i <= 5 ; i++ ){
			if(qos_rate["network.rateportpolicer_"+i+".cir"] == "0"){
				result_rate[i] = "0";
			}else{
				result_rate[i] = "1";
			}
			result_inrate[i] = qos_rate["network.rateportpolicer_"+i+".cir"];
			result_outrate[i] = qos_rate["network.rateportshaper_"+i+".cir"];
			
		}
	}
	qosEnChanged(true);
}
$(document).ready(function(){
	do_init();
});
</script>
</head>
<body>
<blockquote>
<h2>QUEUE 출력 설정</h2>
<table border=0 width="550" cellspacing=4 cellpadding=0>
<tr><td><font size=2>
 QUEUE 출력 제어를 위한 페이지입니다.
</font></td></tr>
<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<form action="/proc/skb_qosque_proc.php" method="POST" name="qos">
<input type="hidden" name="wan_no" id="wan_no" value="<?=$wan_no?>">
<input type="hidden" name="lan_no" id="lan_no" value="<?=$lan1_no?>">
<?php
	for($i=1; $i <= 5; $i++){
?>
<input type="hidden" name="qos_port_no<?=$i?>" id="qos_port_no<?=$i?>" value="">
<input type="hidden" name="qos_enable<?=$i?>" id="qos_enable<?=$i?>" value="">
<input type="hidden" name="qos_mode<?=$i?>" id="qos_mode<?=$i?>" value="">
<input type="hidden" name="qos_weight<?=$i?>" id="qos_weight<?=$i?>" value="">
<input type="hidden" name="qos_rate<?=$i?>" id="qos_rate<?=$i?>" value="">
<input type="hidden" name="qos_in_rate<?=$i?>" id="qos_in_rate<?=$i?>" value="">
<input type="hidden" name="qos_out_rate<?=$i?>" id="qos_out_rate<?=$i?>" value="">
<?
	}
?>
<table border="0" cellspacing=1 cellpadding="2">
	<tr>
  	<td width="100" colspan="4">포트 &nbsp;&nbsp;
		<select name="port_num" id="port_num" onchange="port_change();">
			<option value="<?=$wan_no?>">WAN</option>
			<option value="<?=$lan1_no?>">LAN1</option>
			<option value="<?=($lan1_no+1)?>">LAN2</option>
			<option value="<?=($lan1_no+2)?>">LAN3</option>
			<option value="<?=($lan1_no+3)?>">LAN4</option>
		</select>
		<select name="port_mode" id="port_mode" onchange="change_qos_mode();">
			<option value="sp">SP</option>
			<option value="mix">MIX</option>
			<option value="mixplus">MIX PLUS</option>
			<option value="wrr">WRR</option>
		</select>
		</td>
	</tr>
	<tr>
		<td colspan="4"> 사용 &nbsp;&nbsp;<input type="checkbox" name="que_enable" id="que_enable" onclick="qosEnChanged(document.qos.que_enable.checked);"></td>
	</tr>
	<tr class='tbl_head' align='center'>
    	<td width="100"><b>Queue </b></td>
    	<td width="100"><b>Int. Priority</b></td>
		<td width="100"><b>Queue 종류</b></td>
		<td width="100"><b>Weight<br>(0 ~ 31)</b></td>
  	</tr>

  	<tr bgcolor="#DDDDDD" align='center'>
		<td align='center'>Q3</td>
		<td align='center'>7 / 6</td>
		<td><select name="qtype3" id="qtype3" disabled>
			<option value="SPQ">SPQ</option>
			<option value="WRR">WRR</option>
		</select></td>
		<td><input type="text" name="qweight3" id="qweight3" size="4" maxlength="2"></td>
  	</tr>
  	<tr bgcolor="#DDDDDD" align='center'>
		<td align='center'>Q2</td>
		<td align='center'>5 / 4</td>
		<td><select name="qtype2" id="qtype2" disabled>
			<option value="SPQ">SPQ</option>
			<option value="WRR">WRR</option>
		</select></td>
		<td><input type="text" name="qweight2" id="qweight2" size="4" maxlength="2"></td>
  	</tr>

  	<tr bgcolor="#DDDDDD" align='center'>
		<td align='center'>Q1</td>
		<td align='center'>2 / 3</td>
		<td><select name="qtype1" id="qtype1" disabled>
			<option value="SPQ">SPQ</option>
			<option value="WRR">WRR</option>
		</select></td>
		<td><input type="text" name="qweight1" id="qweight1" size="4" maxlength="2"></td>
  	</tr>

  	<tr bgcolor="#DDDDDD" align='center'>
		<td align='center'>Q0</td>
		<td align='center'>1 / 0</td>
		<td><select name="qtype0" id="qtype0" disabled>
			<option value="SPQ">SPQ</option>
			<option value="WRR">WRR</option>
		</select></td>
		<td><input type="text" name="qweight0" id="qweight0" size="4" maxlength="2"></td>
  	</tr>
	<tr height="10"><td colspan="4"></td></tr>
  	<tr>
		<td colspan="1"><input type="checkbox" name="rate_enable" id="rate_enable" onclick="rateEnChanged(document.qos.rate_enable.checked);">&nbsp;&nbsp; 전체 속도 제어</td>
		<td colspan="3">
	  		&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;수신 &nbsp;&nbsp;&nbsp;<input type="text" name="in_rate" id="in_rate" size='10' maxlength='7'>&nbsp;Kbps<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(0 입력시, 수신 속도 제어 사용 안함)<br>
	  		&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;송신 &nbsp;&nbsp;&nbsp;<input type="text" name="out_rate" id="out_rate" size='10' maxlength='7'>&nbsp;Kbps<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(0 입력시, 송신 속도 제어 사용 안함)
		</td>
  	</tr>
  </table>

  <br>
<input type="submit" value="저장" name="save" onclick="return save_data(this.form)">&nbsp;&nbsp;
<input type="button" value="취소" name="reset" onclick="do_init()">
<input type="hidden" value="/skb_qosque.php" name="submit-url">
</form>



</blockquote>
</body>
</html>

