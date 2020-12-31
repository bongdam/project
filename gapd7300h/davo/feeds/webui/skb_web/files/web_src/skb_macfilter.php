<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$lan_no = dv_session("lan_no");
//	print_r($get);
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>MAC 필터링</title>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<script type="text/javascript">
var proc = "proc/skb_macfilter_proc.php";
var lan_no = <?=$lan_no?>;

function macTblClick(url)
{
	openWindow(url, 'macTbl', 700, 400);
}
var lan1 = new Array();
var lan2 = new Array();
var lan3 = new Array();
var lan4 = new Array();
function addClick()
{
	if (document.formFilterAdd.mac.value=="" && document.formFilterAdd.comment.value=="" ){
		alert("입력된 정보가 없습니다.");
		return false;
	}
	if(!validation_mac($("#mac").val())){
		alert("MAC 주소가 올바르지 않습니다. 16진수를 입력해야 합니다. (0-9 또는 a-f 또는 :)");
		return;
	}
	if($("#commnet").val().trim() == ""){
		alert("설명을 입력해주세요.");
		$("#comment").focus();
		return;
	}
	if(!check_xss($("#commnet").val())){
		alert(xss_err_msg);
		$("#comment").focus();
		return;
	}
	var mac = $("#mac").val();
	var port = $("#port").children(":selected").val();
	var comment = $("#commnet").val();
	var status = $("#opmode"+port).children(":selected").val()
	var tmp = new Object();
	tmp["mac"] = mac;
	tmp["comment"] = comment;
	tmp["port"] = port;
	tmp['status'] = status;
	$("#opmode"+port).prop("disabled",false);
	var position = port - lan_no;
	switch(position){
		case 0:
			if(lan1.length > 3){
				alert("포트별 최대 4개까지 등록가능합니다.");
				return;
			}
			lan1.push(tmp);
			break;
		case 1:
			if(lan2.length > 3){
				alert("포트별 최대 4개까지 등록가능합니다.");
				return;
			}
			lan2.push(tmp);
			break;
		case 2:
			if(lan3.length > 3){
				alert("포트별 최대 4개까지 등록가능합니다.");
				return;
			}
			lan3.push(tmp);
			break;
		case 3:
			if(lan4.length > 3){
				alert("포트별 최대 4개까지 등록가능합니다.");
				return;
			}
			lan4.push(tmp);
			break;
		default:
			console.log('insert error',position);
			break;
	}
	
	create_table();
//	console.log($("#lan"+port+"_mac").find("input[name='list"+port+"_mac']").length);
}
var create_table = function(){
	for (var i=0; i < 4 ; i++ )
	{
		var port = lan_no +i;
		$("#lan"+port+"_mac").children().remove();
		$("#lan"+port+"_desc").children().remove();
		$("#lan"+port+"_del").children().remove();
	}
	for(var j=0 ; j < 4; j++){
		switch(j){
			case 0:
				var obj = lan1;
				break;
			case 1:
				var obj = lan2;
				break;
			case 2:
				var obj = lan3;
				break;
			case 3:
				var obj = lan4;
				break;
		}
		
		for (var i=0; i< obj.length ; i++ )
		{
			var port = obj[i].port;
			var mac = obj[i].mac;
			var comment = obj[i].comment;
			var cnt = $("[name='list"+port+"_del']").length;
			$("#lan"+port+"_mac").append('<input type="text" name="list'+port+'_mac" id="" value="'+mac+'" style="width:95%;" readonly><br>');
			$("#lan"+port+"_desc").append('<input type="text" name="list'+port+'_desc" id="" value="'+comment+'" style="width:95%;" readonly><br>');
			$("#lan"+port+"_del").append('<input type="button" name="list'+port+'_del" id="list'+port+'_del'+cnt+'" value="삭제" onclick="del_macfilter('+port+','+cnt+');" ><br>');
		}
	}
	
}

function modeChange(port_no_)
{
	var status = $("#opmode"+port_no_).children(":selected").val();
	var position = port_no_ - lan_no;
	switch(position){
		case 0:
			for(var i=0; i < lan1.length; i++){
				lan1[i].status = status;
			}
			break;
		case 1:
			for(var i=0; i < lan2.length; i++){
				lan2[i].status = status;
			}
			break;
		case 2:
			for(var i=0; i < lan3.length; i++){
				lan3[i].status = status;
			}
			break;
		case 3:
			for(var i=0; i < lan4.length; i++){
				lan4[i].status = status;
			}
			break;
	}
}

function do_init()
{
	var active_port = 0;

	document.formFilterAdd.opmode1.disabled = ( active_port & 1 )? false: true;
	document.formFilterAdd.opmode2.disabled = ( active_port & 2 )? false: true;
	document.formFilterAdd.opmode3.disabled = ( active_port & 4 )? false: true;
	document.formFilterAdd.opmode4.disabled = ( active_port & 8 )? false: true;
}
var set_array_count = function(){
	if(lan1.length != 0){
		var lan1_cnt = lan1.length;
		for(var i=0; i < lan1.length; i++){
			lan1[i].count = lan1_cnt;
		}
	}
	if(lan2.length != 0){
		var lan2_cnt = lan2.length;
		for(var i=0; i < lan2.length; i++){
			lan2[i].count = lan2_cnt;
		}
	}
	if(lan3.length != 0){
		var lan3_cnt = lan3.length;
		for(var i=0; i < lan3.length; i++){
			lan3[i].count = lan3_cnt;
		}
	}
	if(lan4.length != 0){
		var lan4_cnt = lan4.length;
		for(var i=0; i < lan4.length; i++){
			lan4[i].count = lan4_cnt;
		}
	}
}
var macfilter_apply = function(){
	dummyVal = CreateDummy();
	var fw_list = new Array();
	var forward_rst = new Array();
	set_array_count();
//	var lan = lan1.concat(lan2).concat(lan3).concat(lan4);
//	for (var i=0; i < forward_ori.length ; i++ )
//	{
//		fw_list.push(forward_ori[i]);
//	}
//	console.log(lan);
//	if(lan1.length > 0 ){
//	console.log(lan1);
//	}
//	if(lan2.length > 0 ){
//	console.log(lan2);
//	}
//	if(lan3.length > 0 ){
//	console.log(lan3);
//	}
//	if(lan4.length > 0 ){
//	console.log(lan4);
//	}
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'set_macfilter';
//	sobj['lan'] = lan;
	if(lan1.length > 0 ){
		sobj["lan1"] = lan1;
	}
	if(lan2.length > 0 ){
		sobj["lan2"] = lan2;
	}
	if(lan3.length > 0 ){
		sobj["lan3"] = lan3;
	}
	if(lan4.length > 0 ){
		sobj["lan4"] = lan4;
	}
//	if(fw_list.length > 0){
//		sobj["fw_list"] = fw_list;
//	}
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
//			alert("적용되었습니다.");
//			window.location.reload();
			document.formFilterAdd.submit();
		}
	});
}
var del_macfilter = function(port_no_, no_){
	
	if (!confirm('선택한 목록을 삭제하시겠습니까?')){
		return true;
	}
	var position = port_no_ - lan_no;
	switch(position){
		case 0:
			lan1.splice(no_,1);
			if(lan1.length == 0){
				$("#opmode"+(lan_no+position)).prop("disabled",true).val("drop");
			}
			break;
		case 1:
			lan2.splice(no_,1);
			if(lan2.length == 0){
				$("#opmode"+(lan_no+position)).prop("disabled",true).val("drop");
			}
			break;
		case 2:
			lan3.splice(no_,1);
			if(lan3.length == 0){
				$("#opmode"+(lan_no+position)).prop("disabled",true).val("drop");
			}
			break;
		case 3:
			lan4.splice(no_,1);
			if(lan4.length == 0){
				$("#opmode"+(lan_no+position)).prop("disabled",true).val("drop");
			}
			console.log(lan4);
			break;
	}
	create_table();
}
var result_key = new Array();
var get_macfilter = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_macfilter';
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			$(".opmode").prop("disabled",true);
			if(d.length != 0){
				for(var i=0; i < 4; i++){
					var vp = d["mf_lan_"+i]["port"] + lan_no;
					var status = ""
					if(d["mf_lan_"+i]["mode"] == "1"){
						$("#opmode"+ vp).val("forward");
						status = "forward";
					}else if(d["mf_lan_"+i]["mode"] == "2"){
						$("#opmode"+ vp).val("drop");
						status = "drop";
					}else{
						status = "drop";
					}
//					$("#opmode"+ vp).prop("disabled",false);
					if(d["mf_lan_"+i]["mac"] != undefined){
						$("#opmode"+ vp).prop("disabled",false);
//						console.log(status);
						for(var j=0; j < d["mf_lan_"+i]["mac"].length; j++){
							var tmpObj = new Object();
							tmpObj["mac"] = d["mf_lan_"+i]["mac"][j];
							tmpObj["comment"] = d["mf_lan_"+i]["comment"][j];
							tmpObj["port"] = vp;
							tmpObj["status"] = status;
							switch(i){
								case 0:
									lan1.push(tmpObj);
									break;
								case 1:
									lan2.push(tmpObj);
									break;
								case 2:
									lan3.push(tmpObj);
									break;
								case 3:
									lan4.push(tmpObj);
									break;
							}
						}
					}
				}
				create_table();
			}
		}
	});
}
$(document).ready(function(){
//	do_init();
	get_macfilter();
});
</script>
</head>

<body>
<blockquote>
<form action="proc/skb_macfilter_proc.php" method="POST" name="formFilterAdd">
<input type="hidden" name="act" id="act" value="macfilter_apply">
<h2>MAC 필터링</h2>

<table border="0" width="500" cellspacing="4" cellpadding="0">
	<tr>
		<td><font size="2">해당 MAC 주소를 사용하는 호스트에 대해 접속을 차단하는 설정 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>

<input type="hidden" name="pageName" value="MACF">
<br>
<table border="0" width="500" cellpadding="5">
	<tr>
		<td colspan="4"><font size="2"><b>MAC 필터링 리스트:</b></font></td>
	</tr>
	<tr class='tbl_head'>
		<td align="center" width="20%" ><font size="2"><b>포트</b></font></td>
		<td align="center" width="30%" ><font size="2"><b>MAC 주소</b></font></td>
		<td align="center" width="30%" ><font size="2"><b>설명</b></font></td>
		<td align="center" width="20%" ><font size="2"><b>삭제</b></font></td>
	</tr>
<?php
	$port_no = $lan_no;
	for($i=1; $i <= DEF_MAX_LAN; $i++){
		$port_no = $lan_no + ($i-1);
		$bgcolor = "#f0f0f0";
		if($i % 2 == 0){
			$bgcolor="#d5d5d5";
		}
		
?>
	<tr>
		<td align="center" width="20%" bgcolor="<?=$bgcolor?>"><font size="2">LAN<?=$i?><br><select name="opmode<?=$port_no?>" id="opmode<?=$port_no?>" class="opmode" onchange="modeChange(<?=$port_no?>);">
			<option value="drop" selected>차단</option>
<!-- 			<option value="forward" >허용</option> -->
		</select></font></td>
		<td bgcolor="<?=$bgcolor?>"><span id="lan<?=$port_no?>_mac"></span></td>
		<td bgcolor="<?=$bgcolor?>"><span id="lan<?=$port_no?>_desc"></span></td>
		<td bgcolor="<?=$bgcolor?>" align="center"><span id="lan<?=$port_no?>_del"></span></td>
	</tr>
<?php
	}
?>
	<tr align="center">
		<td><select name="port" id="port">
			<option value="<?=$lan_no?>">LAN1</option>
			<option value="<?=($lan_no+1)?>">LAN2</option>
			<option value="<?=($lan_no+2)?>">LAN3</option>
			<option value="<?=($lan_no+3)?>">LAN4</option>
		</select></td>
		<td><input type="text" name="mac" id="mac" value="" size="20" maxlength="17"></td>
		<td><input type="text" name="comment" id="commnet" value="" size="16" maxlength="20"></td>
		<td><input type="button" value=" 추가 " name="addFilterMac" onclick="addClick();"></td>
	</tr>
	<tr>
		<td>&nbsp;</td>
		<td align="center"><input type="button" id="macSearch" name="macSearch" value="MAC search" onClick="macTblClick('/skb_mactbl.php#form')"></td>
		<td colspan="2">&nbsp;</td>
	</tr>
</table>
<input type="button" id="btn_apply" name="btn_apply" value="적용" onClick="macfilter_apply();">
<input type="hidden" value="ON" name="select">
<input type="hidden" value="ON" name="changeModeFilterMac">
<input type="hidden" name="page" value="skb_macfilter.php">
<input type="hidden" value="/skb_macfilter.php" name="submit-url">
</form>

</blockquote>
</body>
</html>
