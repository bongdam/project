<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Expires" content="-1">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>Static Mapping</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var proc = "proc/skb_static_mapping_proc.php";
var listcnt = 0;
var result_key = new Array();
var result_proto = new Array();
var result_s_ip = new Array();
var result_s_port = new Array();
var result_d_ip = new Array();
var result_d_port = new Array();
function addClick()
{
 	if (document.formStMappingAdd.s_ip.value=="") {
		alert("출발지 주소를 입력해주세요!");
		return false;
	}

	if(document.formStMappingAdd.fromSport.value=="") {
		alert("출발지 포트를 입력해주세요!");
		return false;
	}

  	if ( checkIpAddr(document.formStMappingAdd.s_ip, 'IP 주소가 올바르지 않습니다') == false )
	    return false;

  	if (document.formStMappingAdd.fromSport.value=="") {
		alert("포트 범위가 비어있습니다! 1에서 65535 사이의 숫자를 입력해야 합니다.");
		document.formStMappingAdd.fromSport.focus();
		return false;
  	}

  	if ( validateKey( document.formStMappingAdd.fromSport.value ) == 0 ) {
		alert("포트 번호가 올바르지 않습니다! 숫자를 입력해야 합니다");
		document.formStMappingAdd.fromSport.focus();
		return false;
  	}

  	d1 = getDigit(document.formStMappingAdd.fromSport.value, 1);

  	if (d1 > 65535 || d1 < 1) {
		alert("포트 번호가 올바르지 않습니다! 1에서 65535 사이의 숫자를 입력해야 합니다.");
		document.formStMappingAdd.fromSport.focus();
		return false;
  	}
	if (document.formStMappingAdd.d_ip.value=="") {
		alert("목적지 주소를 입력해주세요!");
		return false;
	}

	if(document.formStMappingAdd.fromDport.value=="") {
		alert("목적지 포트를 입력해주세요!");
		return false;
	}

  	if ( checkIpAddr(document.formStMappingAdd.d_ip, 'IP 주소가 올바르지 않습니다') == false )
	    return false;

  	if (document.formStMappingAdd.fromDport.value=="") {
		alert("포트 범위가 비어있습니다! 1에서 65535 사이의 숫자를 입력해야 합니다.");
		document.formStMappingAdd.fromDport.focus();
		return false;
  	}

  	if ( validateKey( document.formStMappingAdd.fromDport.value ) == 0 ) {
		alert("포트 번호가 올바르지 않습니다! 숫자를 입력해야 합니다");
		document.formStMappingAdd.fromDport.focus();
		return false;
  	}

  	d1 = getDigit(document.formStMappingAdd.fromDport.value, 1);

  	if (d1 > 65535 || d1 < 1) {
		alert("포트 번호가 올바르지 않습니다! 1에서 65535 사이의 숫자를 입력해야 합니다.");
		document.formStMappingAdd.fromDport.focus();
		return false;
  	}
	
	var s_ip_ = $("#s_ip").val();
	var fromSport_ = $("#fromSport").val();
	var protocol_ = $("#protocol").children(":selected").val();
	var d_ip_ = $("#d_ip").val();
	var fromDport_ = $("#fromDport").val();

	if(listcnt >= 32){
		alert("최대 32개까지 등록 가능합니다.");
		return;
	}

	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = "add_static_mapping";
	sobj['s_ip'] = s_ip_;
	sobj['s_port'] = fromSport_;
	sobj['protocol'] = protocol_;
	sobj['d_ip'] = d_ip_;
	sobj['d_port'] = fromDport_;
	sobj['seq'] = listcnt + 1;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				alert("적용되었습니다.");
				window.location.reload();
			}else{
				alert("적용되지 않았습니다.");
				return;
			}
		}
	});
}


function deleteClick()
{
  	if ( !confirm('선택한 목록을 삭제하시겠습니까?') ) {
		return false;
  	}
  	else
		return true;
}

function deleteAllClick()
{
   	if ( !confirm('모든 목록을 삭제하시겠습니까?') ) {
		return false;
  	}
  	else
		return true;
}
function disableDelButton()
{
//	disableButton(document.formStMappingDel.deleteMappingElement);
	disableButton(document.formStMappingDel.deleteAllMapping);
}

function resetForm()
{
	document.location.assign("skb_static_mapping.php");
}

var get_static_mapping = function(){
	var check_button = false;
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = "get_static_mapping";
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(d.length != 0){
				check_button = true;
				
				result_key = new Array();
				result_proto = new Array();
				result_s_ip = new Array();
				result_s_port = new Array();
				result_d_ip = new Array();
				result_d_port = new Array();
				var keys = new Array();
				if (typeof(d) == "object")
				{
					keys = Object.keys(d);
				}else{
					listcnt = 0;
					return;
				}
				var reg_proto = /^(firewall\.staticmapping\_\d+\.proto)/;
				var reg_s_ip = /^(firewall\.staticmapping\_\d+\.src_ip)/;
				var reg_s_port = /^(firewall\.staticmapping\_\d+\.src_dport)/;
				var reg_d_ip = /^(firewall\.staticmapping\_\d+\.dest_ip)/;
				var reg_d_port = /^(firewall\.staticmapping\_\d+\.dest_port)/;

				for(var i=0 ; i < keys.length; i++){
					if(reg_proto.test(keys[i])){
						result_key.push(keys[i].replace(".proto",""));
						result_proto.push(d[keys[i]]);
					};
					if(reg_s_ip.test(keys[i])){
						result_s_ip.push(d[keys[i]]);
					};
					if(reg_s_port.test(keys[i])){
						result_s_port.push(d[keys[i]]);
					};
					if(reg_d_ip.test(keys[i])){
						result_d_ip.push(d[keys[i]]);
					};
					if(reg_d_port.test(keys[i])){
						result_d_port.push(d[keys[i]]);
					};
				}
				listcnt = result_proto.length;
				create_table();
			}else{
				listcnt = 0;
				$("#tbdy").children().remove();
//				console.log("not data.");
				check_button = false;
				if(!check_button)
					disableDelButton();
			}
		}
	});
}
var create_table = function(){
	$("#tbdy").children().remove();
	var tempVal = "";
	for(var i=0; i < result_s_ip.length; i++){
		tempVal += "<tr>";
		tempVal += "	<td>"+result_s_ip[i]+"<input type=\"hidden\" name=\"save_s_ip\" id=\"save_s_ip"+i+"\" value=\""+result_s_ip[i]+"\"> </td>";
		tempVal += "	<td>"+result_s_port[i]+"<input type=\"hidden\" name=\"save_s_port\" id=\"save_s_port"+i+"\" value=\""+result_s_port[i]+"\"></td>";
		tempVal += "	<td>"+result_proto[i]+"<input type=\"hidden\" name=\"save_proto\" id=\"save_proto"+i+"\" value=\""+result_proto[i]+"\"></td>";
		tempVal += "	<td>"+result_d_ip[i]+"<input type=\"hidden\" name=\"save_d_ip\" id=\"save_d_ip"+i+"\" value=\""+result_d_ip[i]+"\"></td>";
		tempVal += "	<td>"+result_d_port[i]+"<input type=\"hidden\" name=\"save_d_port\" id=\"save_d_port"+i+"\" value=\""+result_d_port[i]+"\"></td>";
		tempVal += "	<td><input type=\"button\" name=\"del_check\" id=\"del_check\" value=\"삭제\" onclick=\"del_list("+i+",'"+result_key[i]+"')\"></td>";
		tempVal += "</tr>>";
	}
	$("#tbdy").append(tempVal);
	$("#tbdy").children("tr:odd").css("background-color","#e1e1e1");
}
var del_list = function(i_){
//		console.log(i_,key_);
//		console.log($("#tbdy").children("tr").eq(i_));
	$("#tbdy").children("tr").eq(i_).remove();
	var tr = $("#tbdy").children("tr");
	var result = new Array();
	for(i=0; i < tr.length; i++){
//			console.log(tr.eq(i).find("input[name^='save_ip']").eq(0).val());
		var tmp = new Object();
		tmp["s_ip"] = tr.eq(i).find("input[name^='save_s_ip']").eq(0).val();
		tmp["s_port"] = tr.eq(i).find("input[name^='save_s_port']").eq(0).val();
		tmp["proto"] = tr.eq(i).find("input[name^='save_proto']").eq(0).val();
		tmp["d_ip"] = tr.eq(i).find("input[name^='save_d_ip']").eq(0).val();
		tmp["d_port"] = tr.eq(i).find("input[name^='save_d_port']").eq(0).val();
		result.push(tmp);
	}
//	console.log(result);
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'del_static_mapping';
	sobj["del_list"] = result;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			alert("삭제되었습니다.");
			get_static_mapping();
		}
	});
}
var deleteAllClick = function(){
	$("#deleteAllMapping").prop("disabled",true);
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'del_all_static_mapping';
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			alert("삭제되었습니다.");
			$("#deleteAllMapping").prop("disabled",false);
			get_static_mapping();
		}
	});
}
$(document).ready(function(){
	get_static_mapping();
});

</script>
</head>

<body>
<blockquote>
<h2>Static Mapping</h2>

<table border="0" width="500" cellspacing="4" cellpadding="0">
	<tr>
		<td><font size="2">출발지 IP, Port를 보고 목적지 IP, Port로 연결시켜주는 설정을 할 수 있는 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>
<form action="proc/skb_static_mapping_proc.php" method="POST" name="formStMappingAdd">
<font size="2"><b>&nbsp;&nbsp;Static Mapping 설정</b></font>
<table border="0" width="550">
	<tr class="tbl_head">
		<td align="center" width="25%"><p><font size="2"><b>출발지 주소</b></font></p></td>
		<td align="center" width="15%"><p><font size="2"><b>출발지 포트</b></font></p></td>
		<td align="center"><p><font size="2"><b>&nbsp;프로토콜&nbsp;</b></font></p></td>
		<td align="center" width="25%"><p><font size="2"><b>목적지 주소</b></font></p></td>
		<td align="center" width="15%"><p><font size="2"><b>목적지 포트</b></font></p></td>
	</tr>
	<tr>
		<td><input type="text" name="s_ip" id="s_ip" size="10" style="width:100%;"></td>
	    <td><input type="text" name="fromSport" id="fromSport" value="" size="3" style="width:100%;"></td>
		<td align="center"><select style="width:100%;" name="protocol" id="protocol">
			<option value="tcp udp">TCP+UDP</option>
			<option value="tcp">TCP</option>
			<option value="udp">UDP</option>
		</select></td>
		<td><input type="text" name="d_ip" id="d_ip" value="" size="10" style="width:100%;"></td>
		<td><input type="text" name="fromDport" id="fromDport" value="" style="width:100%;"></td>
	</tr>
	<tr>
		<td colspan="5"><p><input type="button" value="적용" name="addStMapping" onclick="addClick()">&nbsp;&nbsp;
		<input type="button" value="취소" name="reset" onclick="resetForm();"></p>
		<input type="hidden" value="/skb_static_mapping.php" name="submit-url"></td>
	</tr>
</table>
</form>

<br>
<form action="proc/skb_static_mapping_proc.php" method="POST" name="formStMappingDel">
<table border="0" width="550">
	<tr>
		<td><font size="2"><b>Static Mapping Table</b></font></td>
	</tr>
</table>
<table border="0" width="550">
<thead>
	<tr class="tbl_head">
		<td align="center"><p><font size="2"><b>출발지 주소</b></font></p></td>
		<td align="center"><p><font size="2"><b>출발지 포트</b></font></p></td>
		<td align="center"><p><font size="2"><b>&nbsp;프로토콜&nbsp;</b></font></p></td>
		<td align="center"><p><font size="2"><b>목적지 주소</b></font></p></td>
		<td align="center"><p><font size="2"><b>목적지 포트</b></font></p></td>
		<td align="center" width="8%"><p><font size="2"><b>선택</b></font></p></td>
	</tr>
</thead>
<tbody id="tbdy">
</tbody>
</table>
<br>
<input type="button" value="전체 삭제" name="deleteAllMapping" id="deleteAllMapping" onclick="deleteAllClick()">&nbsp;&nbsp;&nbsp;
<input type="reset" value="취소" name="reset">
<input type="hidden" value="/skb_static_mapping.php" name="submit-url">
</form>
</blockquote>
</body>
</html>

