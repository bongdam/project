<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$uci = new uci();
	$uci->mode("get");
	$uci->get("network.lan");
	$uci->run();
	$laninfo = json_decode($uci->result());
	$uci->close();
	$lan_ipaddr = std_get_val($laninfo,"network.lan.ipaddr");
	$lan_netmask = std_get_val($laninfo,"network.lan.netmask");
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>Port Forwarding</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var proc = "proc/skb_portfw_proc.php";
var listcnt = 0;
var result_key = new Array();
var result_proto = new Array();
var result_s_port = new Array();
var result_d_ip = new Array();
var result_d_port = new Array();
var result_comment = new Array();
function addClick()
{
	var sys_gateway = "<?=$lan_ipaddr?>";
	var sys_netmask = "<?=$lan_netmask?>";
	var bcast = 255 - getDigit(sys_netmask, 4);

  	if (document.formPortFwAdd.ip.value=="" && document.formPortFwAdd.fromPort.value=="" &&
		document.formPortFwAdd.toPort.value=="" && document.formPortFwAdd.comment.value=="" &&
		document.formPortFwAdd.t_fromPort.value=="" ){
		alert('입력된 정보가 없습니다.');
		return false;
  	}

  	if ( checkIpAddr(document.formPortFwAdd.ip, 'IP 주소가 올바르지 않습니다') == false )
		return false;

	if (  bcast == getDigit(document.formPortFwAdd.ip.value, 4) ) {
		alert('DHCP IP 할당 내역에 맞게 설정 해 주세요.');
		return false;
	}

	if ( sys_gateway == document.formPortFwAdd.ip.value) {
		alert('AP의 게이트웨이 주소는 설정할 수 없습니다.');
		return false;
	}

  	if (document.formPortFwAdd.fromPort.value=="") {
		alert("포트 범위가 비어있습니다! 1에서 65535 사이의 숫자를 입력해야 합니다.");
		document.formPortFwAdd.fromPort.focus();
		return false;
  	}

  	if ( validateKey( document.formPortFwAdd.fromPort.value ) == 0 ) {
		alert("포트 번호가 올바르지 않습니다! 숫자를 입력해야 합니다. (0-9)");
		document.formPortFwAdd.fromPort.focus();
		return false;
  	}

  	d1 = getDigit(document.formPortFwAdd.fromPort.value, 1);

  	if (d1 > 65535 || d1 < 1) {
		alert("포트 번호가 올바르지 않습니다! 1에서 65535 사이의 숫자를 입력해야 합니다.");
		document.formPortFwAdd.fromPort.focus();
		return false;
  	}

    if (d1 == 80 || d1 == 6000 || d1 == 67 || d1 == 68 || d1 == 53 || d1 == 12380 || d1 == 123 || d1 == 161) {
        alert("AP Router에서 사용 중인 서비스 포트는 입력할 수 없습니다.");
        document.formPortFwAdd.fromPort.focus();
        return false;
    }

  	if (document.formPortFwAdd.toPort.value!="") {
  		if ( validateKey( document.formPortFwAdd.toPort.value ) == 0 ) {
			alert("포트 번호가 올바르지 않습니다! 숫자를 입력해야 합니다. (0-9)");
			document.formPortFwAdd.toPort.focus();
			return false;
  		}

		d2 = getDigit(document.formPortFwAdd.toPort.value, 1);

 		if (d2 > 65535 || d2 < 1) {
			alert("포트 번호가 올바르지 않습니다! 1에서 65535 사이의 숫자를 입력해야 합니다.");
			document.formPortFwAdd.toPort.focus();
			return false;
  		}

		if (d1 > d2 ) {
			alert("포트 범위가 올바르지 않습니다! 첫번째 포트 값이 두번째 포트 값보다 작아야 합니다.");
			document.formPortFwAdd.fromPort.focus();
			return false;
		}

		if (d2 == 80 || d2 == 6000 || d2 == 67 || d2 == 68 || d2 == 53 || d2 == 12380 || d2 == 123 || d2 == 161) {
        	alert("AP Router에서 사용 중인 서비스 포트는 입력할 수 없습니다.");
        	document.formPortFwAdd.toPort.focus();
        	return false;
    	}

    	if ( (d1 < 80 && d2 > 80) || (d1 < 6000 && d2 > 6000) || (d1 < 67 && d2 > 68) || (d1 < 53 && d2 > 53) ||
    	(d1 < 12380 && d2 > 12380) || (d1 < 123 && d2 > 123) || (d1 < 161 && d2 > 161) ) {
        	alert("AP Router에서 사용 중인 서비스 포트는 입력할 수 없습니다.");
        	document.formPortFwAdd.fromPort.focus();
        	return false;
    	}
   	}

	if ( validateKey( document.formPortFwAdd.t_fromPort.value ) == 0 ) {
		alert("포트 번호가 올바르지 않습니다! 숫자를 입력해야 합니다. (0-9)");
		document.formPortFwAdd.t_fromPort.focus();
		return false;
  	}

	d3 = getDigit(document.formPortFwAdd.t_fromPort.value, 1);

 	if (d3 > 65535 || d3 < 1) {
		alert("포트 번호가 올바르지 않습니다! 1에서 65535 사이의 숫자를 입력해야 합니다.");
		document.formPortFwAdd.t_fromPort.focus();
		return false;
  	}

	if (d3 == 80 || d3 == 6000 || d3 == 67 || d3 == 68 || d3 == 53 || d3 == 12380 || d3 == 123 || d3 == 161 || d3 == 8080) {
        alert("AP Router에서 사용 중인 서비스 포트는 입력할 수 없습니다.");
        document.formPortFwAdd.t_fromPort.focus();
        return false;
    }

	var fromSport_ = $("#fromPort").val();
	var fromDport_ = $("#toPort").val();
	var s_port_ = "";
	var protocol_ = $("#protocol").children(":selected").val();
	var d_ip_ = $("#ip").val();
	
	var d_port_ = $("#t_fromPort").val();
	var description = $("#comment").val();
	if(description == ""){
		alert("설명을 입력해주세요.");
		$("#comment").focus();
		return;
	}
	if(!check_xss(description)){
		alert(xss_err_msg);
		$("#comment").focus();
		return;
	}
	if(fromSport_ != ""){
		s_port_ = fromSport_;
	}
	if(fromDport_ != ""){
		s_port_ = fromSport_ + "-" + fromDport_;
	}
	if(listcnt >= 30){
		alert("최대 30개까지 등록 가능합니다.");
		return;
	}

	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = "add_port_forward";
	sobj['s_port'] = s_port_;
	sobj['protocol'] = protocol_;
	sobj['d_ip'] = d_ip_;
	sobj['d_port'] = d_port_;
	sobj['comment'] = description;
	sobj['seq'] = listcnt + 1;
//	console.log(sobj);
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


function deleteClick(i)
{
  document.formPortFwDel.elements["select"].name = "select"+i;
  if ( !confirm('선택된 목록을 정말로 삭제하시겠습니까?') ) {
	return false;
  }
  else
	return true;
}


function disableDelButton()
{
//	disableButton(document.formPortFwDel.deleteSelPortFw);
//	disableButton(document.formPortFwDel.deleteAllPortFw);
}

function updateState()
{

	var is_disable = false;

  	document.formPortFwAdd.ip.disabled = is_disable;
  	document.formPortFwAdd.protocol.disabled = is_disable;
  	document.formPortFwAdd.fromPort.disabled = is_disable;
  	document.formPortFwAdd.toPort.disabled = is_disable;
  	document.formPortFwAdd.t_fromPort.disabled = is_disable;
  	document.formPortFwAdd.comment.disabled = is_disable;
  	document.formPortFwAdd.addPortFw.disabled = is_disable;

  	var portFw_num = 0 ;
  	for(i=1 ; i <= portFw_num; i++){
		get_by_id("deleteSelPortFw"+i).disabled = is_disable;
  	}
}
var get_port_forward = function(){
	var check_button = false;
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = "get_port_forward";
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
				result_s_port = new Array();
				result_d_ip = new Array();
				result_d_port = new Array();
				result_comment = new Array();
				var keys = new Array();
				if (typeof(d) == "object")
				{
					keys = Object.keys(d);
				}else{
					listcnt = 0;
					return;
				}
				var reg_proto = /^(firewall\.portfw\_\d+\.proto)/;
				var reg_s_port = /^(firewall\.portfw\_\d+\.src_dport)/;
				var reg_d_ip = /^(firewall\.portfw\_\d+\.dest_ip)/;
				var reg_d_port = /^(firewall\.portfw\_\d+\.dest_port)/;
				var reg_comment = /^(firewall\.portfw\_\d+\.name)/;

				for(var i=0 ; i < keys.length; i++){
					if(reg_proto.test(keys[i])){
						result_key.push(keys[i].replace(".proto",""));
						result_proto.push(d[keys[i]]);
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
					if(reg_comment.test(keys[i])){
						result_comment.push(d[keys[i]]);
					};
				}
				listcnt = result_proto.length;
				create_table();
				$("#deleteAllPortFw").prop("disabled",false);
//				console.log(result_key,result_proto,result_s_port,result_d_ip,result_d_port,result_comment);
			}else{
//				console.log("not data.");
				check_button = false;
				$("#tbdy").children().remove();
				$("#deleteAllPortFw").prop("disabled",true);
				
			}
		}
	});
}
var create_table = function(){
	$("#tbdy").children().remove();
	var tempVal = "";
	if(result_s_port.length > 0){
		for(var i=0; i < result_s_port.length; i++){
			tempVal += "<tr>";
			tempVal += "	<td>"+result_s_port[i]+"<input type=\"hidden\" name=\"save_s_port\" id=\"save_s_port"+i+"\" value=\""+result_s_port[i]+"\"></td>";
			tempVal += "	<td>"+result_proto[i]+"<input type=\"hidden\" name=\"save_proto\" id=\"save_proto"+i+"\" value=\""+result_proto[i]+"\"></td>";
			tempVal += "	<td>"+result_d_ip[i]+"<input type=\"hidden\" name=\"save_d_ip\" id=\"save_d_ip"+i+"\" value=\""+result_d_ip[i]+"\"></td>";
			tempVal += "	<td>"+result_d_port[i]+"<input type=\"hidden\" name=\"save_d_port\" id=\"save_d_port"+i+"\" value=\""+result_d_port[i]+"\"></td>";
			tempVal += "	<td>"+result_comment[i]+"<input type=\"hidden\" name=\"save_comment\" id=\"save_comment"+i+"\" value=\""+result_comment[i]+"\"> </td>";
			tempVal += "	<td><input type=\"button\" name=\"del_check\" id=\"del_check\" value=\"삭제\" onclick=\"del_list("+i+",'"+result_key[i]+"')\"></td>";
			tempVal += "</tr>";
		}
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
		tmp["s_port"] = tr.eq(i).find("input[name^='save_s_port']").eq(0).val();
		tmp["proto"] = tr.eq(i).find("input[name^='save_proto']").eq(0).val();
		tmp["d_ip"] = tr.eq(i).find("input[name^='save_d_ip']").eq(0).val();
		tmp["d_port"] = tr.eq(i).find("input[name^='save_d_port']").eq(0).val();
		tmp["comment"] = tr.eq(i).find("input[name^='save_comment']").eq(0).val();
		result.push(tmp);
	}
//	console.log(result);
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'del_port_forward';
	sobj["del_list"] = result;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			alert("삭제되었습니다.");
			get_port_forward();
		}
	});
}
var deleteAllClick = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'del_all_port_forward';
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			alert("삭제되었습니다.");
			get_port_forward();
		}
	});
}
$(document).ready(function(){
	updateState();
	get_port_forward();
});
</script>
</head>

<body>
<blockquote>
<h2>포트 포워딩</h2>

<table border="0" width="500" cellspacing="4" cellpadding="0">
<tr>
	<td><font size="2">특정 포트로 들어오는 네트워크 데이터를 해당 IP 주소로 연결시켜주는 설정을 할 수 있는 페이지입니다.</font></td>
</tr>
<tr>
	<td><hr size=1 noshade align="top"></td>
</tr>
</table>
<form method="POST" name="formPortFwAdd">
<table border="0" width="500" cellspacing="4" cellpadding="0">

<tr>
    <td width="140"><p><font size="2"><b>서비스 포트</b></font></p></td>
    <td><p><font size="2"><b>프로토콜</b></font></p></td>
    <td><p><font size="2"><b>내부 IP 주소</b></font></p></td>
    <td><p><font size="2"><b>포트</b></font></p></td>
    <td><p><font size="2"><b>설명</b></font></p></td>
</tr>
<tr>
    <td><input type="text" name="fromPort" id="fromPort" value="" size="4" maxlength="5"><b>
        -</b><input type="text" name="toPort" id="toPort" value="" size="4" maxlength="5"></td>
    <td>
        <select name="protocol" id="protocol">
            <option value="tcp udp">TCP+UDP</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
    </td>
    <td> <input type="text" name="ip" id="ip" value="" size="10" maxlength="15"> </td>
    <td><input type="text" name="t_fromPort" id="t_fromPort" value="" size="4" maxlength="5"></td>
    <td> <input type="text" name="comment" id="comment" value="" size="6" maxlength="14"> </td>
</tr>
<tr>
	<td colspan='5'>
  		<p><input type="button" value="적용" name="addPortFw" onclick="addClick()">&nbsp;&nbsp;
     	<input type="reset" value="취소" name="reset"></p>
  		<input type="hidden" value="/skb_portfw.php" name="submit-url">
	</td>
</tr>
<!--<tr><td><font size="2"><b>
	<input type="checkbox" name="enabled" value="ON" onclick=updateState()>&nbsp;&nbsp;Enable Port Forwarding</b><br>
    </td>
</tr>

<tr><td>
  <p><font size="2"><b>IP Address:</b> <input type="text" name="ip" size="10" maxlength="15">&nbsp;
  <b>Protocol:</b> <select name="protocol">
    <option select value="0">Both</option>
    <option value="1">TCP</option>
    <option value="2">UDP</option>
  </select>&nbsp;<b>Port Range:</b> <input type="text" name="fromPort" size="3"><b>-</b>
      <input type="text" name="toPort" size="3">
    <b>Comment:</b> <input type="text" name="comment" size="6" maxlength="20"></font>

  <p><input type="submit" value="Apply Changes" name="addPortFw" onclick="return addClick()">&nbsp;&nbsp;
     <input type="reset" value="Reset" name="reset"></p>
  <input type="hidden" value="/skb_portfw.php" name="submit-url">
</td></tr>
  <script> updateState(); </script>-->
</form>
</table>
<br>
<form method="POST" name="formPortFwDel">
<table border="0" width="500">
  <tr><font size="2"><b>포트 포워딩 리스트:</b></font></tr>
</table>
<table border="0" width="500">
	<thead>
		<tr class="tbl_head">
			<td align="center" width="20%" ><font size="2"><b>서비스포트</b></font></td>
			<td align="center" width="20%" ><font size="2"><b>프로토콜</b></font></td>
			<td align="center" width="20%" ><font size="2"><b>내부IP주소</b></font></td>
			<td align="center" width="15%" ><font size="2"><b>포트</b></font></td>
			<td align="center" width="15%" ><font size="2"><b>설명</b></font></td>
			<td align="center" width="10%" ><font size="2"><b>삭제</b></font></td>
		</tr>
	</thead>
	<tbody id="tbdy">
	
	</tbody>
</table>
<input type="button" value="전체 삭제" name="deleteAllPortFw" id="deleteAllPortFw" onclick="return deleteAllClick();">
<!-- <br><input type="submit" value="Delete Selected" name="deleteSelPortFw" onclick="return deleteClick()">&nbsp;&nbsp;
     <input type="submit" value="Delete All" name="deleteAllPortFw" onclick="return deleteAllClick()">&nbsp;&nbsp;&nbsp;
     <input type="reset" value="Reset" name="reset">
 <script>
	if ( 0 == 0 )
		disableDelButton();
 </script>-->
  	 <input type="hidden" value="ON" name="select">
     <input type="hidden" value="/skb_portfw.php" name="submit-url">
</form>
</blockquote>
</body>
</html>

