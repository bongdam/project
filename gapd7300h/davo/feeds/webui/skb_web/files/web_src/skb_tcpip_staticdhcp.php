<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$param = null;
	$sock = new rcqm();
	$sock->connect();
	if($sock->con()){
	}else{
		return "0";
	}
	$sock->write("dhcp_list",$param);
	$dhcpinfo = $sock->read();
	$dhcpinfo = json_decode($dhcpinfo,true)["data"];
	$dhcpinfo = explode("\n",rtrim($dhcpinfo));
	$devicelist = Array();
	for($i=0; $i < count($dhcpinfo);$i++){
		if(preg_match("/^(\d+)\s+(\w+:\w+:\w+:\w+:\w+:\w+)\s+(\d+.\d+.\d+.\d+)\s+([\w+\-\*]{1,})\s+([\w:\*]{1,})\s+(\w+)/",$dhcpinfo[$i],$d) == true) {
			$tmp = Array(
				"time"=> $d[1],
				"mac"=> $d[2],
				"ip"=>$d[3],
				"device_name"=>$d[4],
				"contype"=>$d[6]
			);
			$devicelist[] = $tmp;
		}
	}
	$nowtime = ceil(getTimestamp()/1000);
	$uci = new uci();
	$uci->mode("get");
	$uci->get("network.lan");
	$uci->run();
	$laninfo = json_decode($uci->result());
	$uci->close();
	$lan_ipaddr = std_get_val($laninfo,"network.lan.ipaddr");
	$lan_netmask = std_get_val($laninfo,"network.lan.netmask");
?>
<!DOCTYPE html>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>Static DHCP Setup</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<script type="text/javascript" src="js/skb_util_qos.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<style type="text/css">
	table{
		font-size:12px;
	}
</style>
<script type="text/javascript">
var proc = "proc/skb_tcpip_staticdhcp_proc.php";
var result_key = new Array();
	
var result_ip = new Array();
var result_mac = new Array();
var result_host = new Array();

function addClick()
{
	var sys_gateway = "<?=$lan_ipaddr?>";
	var sys_netmask = "<?=$lan_netmask?>";
	var bcast = 255 - getDigit(sys_netmask, 4);
	var obj_val_ip = "",obj_val_mac = "";
	var obj_tag_ip = $("#static_ip").get(0).tagName;
	var obj_tag_mac = $("#static_mac").get(0).tagName;
	
	if(obj_tag_ip == "SELECT"){
		obj_val_ip = $("#static_ip").children(":selected").val();
	}else{
		obj_val_ip = $("#static_ip").val();
	}
	if(obj_tag_mac == "SELECT"){
		obj_val_mac = $("#static_mac").children(":selected").val();
	}else{
		obj_val_mac = $("#static_mac").val();
	}
	if(obj_val_ip == "" || obj_val_mac == "") {
		alert("IP 주소와 MAC 주소 모두 설정되어 있어야 합니다.");
		return false;
	}
	if(!ipCheck(obj_val_ip)){
		alert('IP 주소가 올바르지 않습니다! ');
		return false;
	}
	if(!check_ip_du_band(obj_val_ip,sys_netmask,sys_gateway,sys_netmask)){
		alert('DHCP IP 할당 내역에 맞게 설정 해 주세요.');
		return false;
	}
	if(obj_val_ip == sys_gateway){
		alert('AP의 게이트웨이 주소는 설정할 수 없습니다.');
		return false;
	}
	if(!validation_mac(obj_val_mac)){
		alert("MAC 주소가 올바르지 않습니다. 16진수 콜론(:)을 포함한 17자리를 입력하여 주십시오.");
		return false;
	}
	if($("#static_name").val().trim() == ""){
		alert("호스트 이름을 설정해 주세요.");
		return false;
	}
	if(result_ip.length > 0){
		if(result_ip.indexOf(obj_val_ip) > -1){
			alert("이미 등록된 IP주소입니다.");
			return false;
		}
	}
	if(result_mac.length > 0){
		if(result_mac.indexOf(obj_val_mac) > -1){
			alert("이미 등록된 MAC 주소입니다.");
			return false;
		}
	}
	if(parseInt($("#no").val(),10) > 30){
		alert("최대 30개까지 등록가능합니다.");
		return;
	}
	if($("#static_name").val().replace(/\s/gi,"").length != $("#static_name").val().length){
		alert('설명에 공백 없이 입력해주세요.');
		return;
	}
	if(!check_xss($("#static_name").val())){
		alert(xss_err_msg);
		$("#static_name").focus();
		return;
	}
	//LIST 체크 누락
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'add_ipaddr';
	sobj['no'] = $("#no").val();
	sobj["static_ip"] = obj_val_ip;
	sobj["static_mac"] = obj_val_mac;
	sobj["static_name"] = $("#static_name").val();
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
//			get_static_list();
			alert("등록되었습니다.");
			setTimeout(function(){
				window.location.reload();
			},500);
		}
	});
//	document.formStaticDHCP.submit();
//	return true;
}

function deleteClick(i)
{
	document.formStaticDHCP.elements["select"].name = "select"+i;

	if ( !confirm('선택한 목록을 삭제하시겠습니까?') ) {
	return false;
	}
	else
	return true;
}


	var change_select = function(obj_){
		var objname = obj_.name;
		var objid = obj_.id;
		var obj = $(obj_);
		if(obj.children(":selected").val() == ""){
			var tempVal = "<input type=\"text\" name=\""+objname+"\" id=\""+objid+"\" value=\""+obj.attr("preval")+"\" style=\"width:95%\">";
			$(tempVal).replaceAll(obj);
		}else{
			obj.attr("preval",obj.children(":selected").val());
		}
	}
	

	var get_static_list = function(){
		dummyVal = CreateDummy();
		var sobj = new Object();
		sobj['dummyVal'] = dummyVal;
		sobj['act'] = 'get_static_list';
	//		alert(JSON.stringify(sobj));
		$.ajax({
			"data":sobj,
			url:proc,
			"dataType":"json",
			"type":"POST",
			success:function(d){
				result_key = new Array();
		
				result_ip = new Array();
				result_mac = new Array();
				result_host = new Array();
				if(d != null){
					var keys = new Array();
					if (typeof(d) == "object")
					{
						keys = Object.keys(d);
					}
					var reg_ip = /^(dhcp\.host\_\d+\.ip)/;
					var reg_mac = /^(dhcp\.host\_\d+\.mac)/;
					var reg_host = /^(dhcp\.host\_\d+\.name)/;

					for(var i=0 ; i < keys.length; i++){
						if(reg_ip.test(keys[i])){
							result_key.push(keys[i].replace(".ip",""));
							result_ip.push(d[keys[i]]);
						};
						if(reg_mac.test(keys[i])){
							result_mac.push(d[keys[i]]);
						};
						if(reg_host.test(keys[i])){
							result_host.push(d[keys[i]]);
						}
					}
				}
			},complete:function(){
				$("#no").val(result_ip.length+1);
				create_table();
			}
		});
	}
	var create_table = function(){
		$("#tbdy").children().remove();
		if(result_ip.length > 0 ){
			var tempVal = "";
			for(i=0; i < result_ip.length; i++){
				tempVal += "<tr>";
				tempVal += "	<td>"+result_ip[i]+"<input type=\"hidden\" name=\"save_ip\" id=\"save_ip"+i+"\" value=\""+result_ip[i]+"\" ></td>";
				tempVal += "	<td>"+result_mac[i]+"<input type=\"hidden\" name=\"save_mac\" id=\"save_mac"+i+"\" value=\""+result_mac[i]+"\" ></td>";
				tempVal += "	<td>"+result_host[i]+"<input type=\"hidden\" name=\"save_host\" id=\"save_host"+i+"\" value=\""+result_host[i]+"\" ></td>";
				tempVal += "	<td><input type=\"button\" name=\"btn_del"+i+"\" id=\"btn_del"+i+"\" value=\"DEL\" onclick=\"del_host("+i+",'"+result_key[i]+"')\"></td>";
				tempVal += "</tr>";
			}
			$("#tbdy").append(tempVal);
		}else{
			$("#tbdy").append("<tr><td>--</td><td>--</td><td>--</td><td>--</td></tr>");
		}
		$("#tbdy").children("tr:odd").css("background-color","#e1e1e1");
	}
	var del_host = function(i_,key_){
//		console.log(i_,key_);
//		console.log($("#tbdy").children("tr").eq(i_));
		$("#tbdy").children("tr").eq(i_).remove();
		var tr = $("#tbdy").children("tr");
		var result = new Array();
		for(i=0; i < tr.length; i++){
//			console.log(tr.eq(i).find("input[name^='save_ip']").eq(0).val());
			var tmp = new Object();
			tmp["ip"] = tr.eq(i).find("input[name^='save_ip']").eq(0).val();
			tmp["mac"] = tr.eq(i).find("input[name^='save_mac']").eq(0).val();
			tmp["host"] = tr.eq(i).find("input[name^='save_host']").eq(0).val();
			result.push(tmp);
		}
		dummyVal = CreateDummy();
		var sobj = new Object();
		sobj['dummyVal'] = dummyVal;
		sobj['act'] = 'del_list';
		sobj["del_list"] = result;
		$.ajax({
			"data":sobj,
			url:proc,
			"dataType":"text",
			"type":"POST",
			success:function(d){
				alert("삭제되었습니다.");
				setTimeout(function(){
					get_static_list();
				},500);
			}
		});
	}
	$(document).ready(function(){
		change_select(document.formStaticDHCP.static_ip);
		change_select(document.formStaticDHCP.static_mac);
		get_static_list();
	});
</script>
</head>
<body>
<blockquote>
<h2>고정 IP 할당</h2>
<form action="proc/skb_tcpip_staticdhcp_proc.php" method="POST" name="formStaticDHCP">
<input type="hidden" name="act" id="act" value="add_ipaddr">
<input type="hidden" name="page" value="skb_tcpip_staticdhcp.php">
<input type="hidden" name="no" id="no" value="1">
<table width="700" border="0" cellpadding="4" cellspacing="0">
	<tr>
		<td><font size="2">고정 IP 할당을 위한 설정페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>
<br>
<br>
<table border="0" width="640">
	<tr>
		<td colspan="4"><font size="2"><b>고정 IP 리스트:</b></font></td>
	</tr>
</table>
<table border="0" width="640">
	<thead>
		<tr class="tbl_head">
			<td align="center" width="30%" ><b>IP 주소</b></td>
			<td align="center" width="30%" ><b>MAC 주소</b></td>
			<td align="center" width="30%" ><b>설명</b></td>
			<td align="center" width="10%" ><b>삭제</b></td>
		</tr>
	</thead>
	<tbody id="tbdy">
		<tr>
			<td>--</td>
			<td>--</td>
			<td>--</td>
			<td>--</td>
		</tr>
	</tbody>
</table>
<br>
<table border="0" width="640">
	<tr>
		<td align="center" width="30%">
			<select name="static_ip" id="static_ip" onchange="change_select(this);" preval="" style="width:90%;">
<?php
				for($i=0; $i < count($devicelist); $i++){
?>
				<option value="<?=$devicelist[$i]["ip"]?>"><?=$devicelist[$i]["ip"]?></option>
<?php
				}
?>
				<option value="">--custom--</option>
			</select>
		</td>
		<td align="center" width="30%">
			<select name="static_mac" id="static_mac" onchange="change_select(this);" preval="" style="width:90%;">
<?php
				for($i=0; $i < count($devicelist); $i++){
?>
				<option value="<?=$devicelist[$i]["mac"]?>"><?=$devicelist[$i]["mac"]?>(<?=$devicelist[$i]["ip"]?>)</option>
<?php
				}
?>
				<option value="">--custom--</option>
			</select>
		</td>
		<td align="center" width="30%"><input type="text" id="static_name" name="static_name" size="20" maxlength="19" value=""></td>
		<td align="center" width="10%"><input type="button" value="적용" name="btn_apply" id="addRsvIP" onclick="addClick()"></td>
	</tr>
</table>
<br>
<input type="hidden" value="ON" name="select">
<input type="hidden" value="/skb_tcpip_staticdhcp.htm" name="submit-url">
</form>

</blockquote>
</body>
</html>