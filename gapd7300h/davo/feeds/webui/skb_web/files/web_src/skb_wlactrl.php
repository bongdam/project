<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$wlan_id = dv_session("wlan_id");
	$uci = new uci();
	$uci->mode("get");
	if(DEF_MODEL != "QCA_REF" && DEF_ANT == "4x4"){
			$uci->get("wireless.wifi1");
			$uci->get("wireless.vap10");
			$uci->get("wireless.vap11");
			$uci->get("wireless.vap12");
			$uci->get("wireless.wifi0");
			$uci->get("wireless.vap00");
			$uci->get("wireless.vap01");
			$uci->get("wireless.vap02");
	}
	$uci->run();
	$wifi = json_decode($uci->result(),true);
	$ssid24 = Array();
	$ssid5 = Array();
	$ssid_disable24 = Array();
	$ssid_disable5 = Array();
	$macauth24 = Array();
	$macauth5 = Array();

	$ssid24[] = get_array_val($wifi,"wireless.vap10.ssid","1");
	$ssid24[] = get_array_val($wifi,"wireless.vap11.ssid","1");
	$ssid24[] = get_array_val($wifi,"wireless.vap12.ssid","1");
	$ssid_disable24[] = get_array_val($wifi,"wireless.vap10.disabled","1");
	$ssid_disable24[] = get_array_val($wifi,"wireless.vap11.disabled","1");
	$ssid_disable24[] = get_array_val($wifi,"wireless.vap12.disabled","1");
	$ssid5[] = get_array_val($wifi,"wireless.vap00.ssid","1");
	$ssid5[] = get_array_val($wifi,"wireless.vap01.ssid","1");
	$ssid5[] = get_array_val($wifi,"wireless.vap02.ssid","1");
	$ssid_disable5[] = get_array_val($wifi,"wireless.vap00.disabled","1");
	$ssid_disable5[] = get_array_val($wifi,"wireless.vap01.disabled","1");
	$ssid_disable5[] = get_array_val($wifi,"wireless.vap02.disabled","1");
	
	if(get_array_val($wifi,"wireless.vap10.macaddr_acl","1") == "2"){
		$macauth24[] = "2";
	}else{
		$macauth24[] = "";
	}
	if(get_array_val($wifi,"wireless.vap11.macaddr_acl","1") == "2"){
		$macauth24[] = "2";
	}else{
		$macauth24[] = "";
	}
	if(get_array_val($wifi,"wireless.vap12.macaddr_acl","1") == "2"){
		$macauth24[] = "2";
	}else{
		$macauth24[] = "";
	}
	if(get_array_val($wifi,"wireless.vap00.macaddr_acl","1") == "2"){
		$macauth5[] = "2";
	}else{
		$macauth5[] = "";
	}
	if(get_array_val($wifi,"wireless.vap01.macaddr_acl","1") == "2"){
		$macauth5[] = "2";
	}else{
		$macauth5[] = "";
	}
	if(get_array_val($wifi,"wireless.vap02.macaddr_acl","1") == "2"){
		$macauth5[] = "2";
	}else{
		$macauth5[] = "";
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
<title>무선 인터넷 접근 제어</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/spin.min.js"></script>
<script type="text/javascript" src="inc/js/jquery.spin.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script>
var wlan_idx = "<?=$wlan_id?>";
var seq = "0";
var mode = "-1";
var proc = "proc/skb_wlactrl_proc.php";
var ssid24 = <?=json_to_array_string($ssid24);?>;
var ssid5 = <?=json_to_array_string($ssid5);?>;
var ssid_disable24 = <?=json_to_array_string($ssid_disable24);?>;
var ssid_disable5 = <?=json_to_array_string($ssid_disable5);?>;
var macauth24 = <?=json_to_array_string($macauth24);?>;
var macauth5 = <?=json_to_array_string($macauth5);?>;
var add_cnt = 0;


var data = new Array();
function macTblClick(url) {
    openWindow(url, 'wlMacTbl', 700, 400 );
}

function addClick(f)
{
	document.formWlAcAdd.comment.value = trim(document.formWlAcAdd.comment.value);

	var comment_val = document.formWlAcAdd.comment.value;

    var str = document.formWlAcAdd.mac.value;
    var tmpMac = "";

	f.addFilterMac_.disabled=true;
	f.reset.disabled=true;
	f.macSearch.disabled=true;
	document.formWlAcDel.reset.disabled=true;
	document.formWlAcDel.deleteSelFilterMac_.disabled=true;
	document.formWlAcDel.deleteAllFilterMac_.disabled=true;
    if (document.formWlAcAdd.wlanAcEnabled.selectedIndex == 0) {
    	f.submit();
        return true;
    }

    str = trim(str);

    if ( !(str.length == 12 || str.length == 17) ) {
        alert("MAC 주소가 올바르지 않습니다. 16진수 12자리 또는 콜론(:)을 포함한 17자리를 입력해주십시오.");
        document.formWlAcAdd.mac.focus();
        f.addFilterMac_.disabled=false;
		f.reset.disabled=false;
		f.macSearch.disabled=false;
		document.formWlAcDel.reset.disabled=false;
		document.formWlAcDel.deleteSelFilterMac_.disabled=false;
		document.formWlAcDel.deleteAllFilterMac_.disabled=false;
        return false;
    }
    if (str.length==17) {
        if (str.charAt(2)!=':' || str.charAt(5)!=':' || str.charAt(8)!=':' || str.charAt(11)!=':' || str.charAt(14)!=':' ) {
            alert("MAC 주소가 올바르지 않습니다. 16진수 12자리 또는 콜론(:)을 포함한 17자리를 입력해주십시오.");
            document.formWlAcAdd.mac.focus();
            f.addFilterMac_.disabled=false;
			f.reset.disabled=false;
			f.macSearch.disabled=false;
			document.formWlAcDel.reset.disabled=false;
			document.formWlAcDel.deleteSelFilterMac_.disabled=false;
			document.formWlAcDel.deleteAllFilterMac_.disabled=false;
            return false;
        }
    }
    for (var i=0; i<str.length; i++) {
        if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
			    (str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
			    (str.charAt(i) >= 'A' && str.charAt(i) <= 'F') ||
			    (str.charAt(i) == ':') ) {
            if(str.charAt(i) != ':')
	            tmpMac += str.charAt(i);
	        continue;
        }
	    alert("MAC 주소가 올바르지 않습니다. 16진수를 입력해주십시오.(0-9 또는 a-f).");
	    document.formWlAcAdd.mac.focus();
	    f.addFilterMac_.disabled=false;
		f.reset.disabled=false;
		f.macSearch.disabled=false;
		document.formWlAcDel.reset.disabled=false;
		document.formWlAcDel.deleteSelFilterMac_.disabled=false;
		document.formWlAcDel.deleteAllFilterMac_.disabled=false;
	    return false;
    }

    if ( IsHtmlComment(comment_val)) {
		alert('Html 주석문을 입력할 수 없습니다.!');
		document.formWlAcAdd.comment.value = document.formWlAcAdd.comment.defaultValue;
		document.formWlAcAdd.comment.focus();
		f.addFilterMac_.disabled=false;
		f.reset.disabled=false;
		f.macSearch.disabled=false;
		document.formWlAcDel.reset.disabled=false;
		document.formWlAcDel.deleteSelFilterMac_.disabled=false;
		document.formWlAcDel.deleteAllFilterMac_.disabled=false;
		return false;
  }

    document.formWlAcAdd.mac.value = tmpMac;

  	f.submit();
    return true;
}


function deleteClick(f)
{
    var target = document.getElementById("dynamicTable");
    acl_num = target.rows.length - 2;

    delNum = 0 ;
    document.formWlAcAdd.addFilterMac_.disabled=true;
	document.formWlAcAdd.reset.disabled=true;
	document.formWlAcAdd.macSearch.disabled=true;
	f.reset.disabled=true;
	f.deleteSelFilterMac_.disabled=true;
	f.deleteAllFilterMac_.disabled=true;
	f.deleteAllFilterMac.disabled=true;
  for(i=1 ; i <= acl_num ; i++){
  	if(document.formWlAcDel.elements["select"+i].checked)
  		delNum ++ ;
  }
  if(document.formWlAcAdd.wlanAcEnabled.selectedIndex==1 && delNum==acl_num){
		if ( !confirm('모든 목록을 삭제하면 어떠한 클라이언트도 AP에 연결할 수 없게 됩니다. 진행하시겠습니까?') ) {
			document.formWlAcAdd.addFilterMac_.disabled=false;
			document.formWlAcAdd.reset.disabled=false;
			document.formWlAcAdd.macSearch.disabled=false;
			f.reset.disabled=false;
			f.deleteSelFilterMac_.disabled=false;
			f.deleteAllFilterMac_.disabled=false;
			f.deleteAllFilterMac.disabled=false;
			return false;
		}
   }
  else if ( !confirm('선택한 목록을 삭제하시겠습니까?') ) {
	document.formWlAcAdd.addFilterMac_.disabled=false;
	document.formWlAcAdd.reset.disabled=false;
	document.formWlAcAdd.macSearch.disabled=false;
	f.reset.disabled=false;
	f.deleteSelFilterMac_.disabled=false;
	f.deleteAllFilterMac_.disabled=false;
	f.deleteAllFilterMac.disabled=false;
	return false;
  }
  f.submit();
  return true;
}

function deleteAllClick(f)
{
	document.formWlAcAdd.addFilterMac_.disabled=true;
	document.formWlAcAdd.reset.disabled=true;
	document.formWlAcAdd.macSearch.disabled=true;
	f.reset.disabled=true;
	f.deleteSelFilterMac_.disabled=true;
	f.deleteAllFilterMac_.disabled=true;
	f.deleteSelFilterMac.disabled=true;

   if(document.formWlAcAdd.wlanAcEnabled.selectedIndex==1){
		if ( !confirm('모든 목록을 삭제하면 어떠한 클라이언트도 AP에 연결할 수 없게 됩니다. 진행하시겠습니까?') ) {
			document.formWlAcAdd.addFilterMac_.disabled=false;
			document.formWlAcAdd.reset.disabled=false;
			document.formWlAcAdd.macSearch.disabled=false;
			f.reset.disabled=false;
			f.deleteSelFilterMac_.disabled=false;
			f.deleteAllFilterMac_.disabled=false;
			f.deleteSelFilterMac.disabled=false;
			return false;
		}
   }else if ( !confirm('선택한 목록을 삭제하시겠습니까?') ) {
	document.formWlAcAdd.addFilterMac_.disabled=false;
	document.formWlAcAdd.reset.disabled=false;
	document.formWlAcAdd.macSearch.disabled=false;
	f.reset.disabled=false;
	f.deleteSelFilterMac_.disabled=false;
	f.deleteAllFilterMac_.disabled=false;
	f.deleteSelFilterMac.disabled=false;
	return false;
  }
  f.submit();
  return true;
}
function enableDelButton()
{
	enableButton(document.formWlAcDel.deleteSelFilterMac);
	enableButton(document.formWlAcDel.deleteAllFilterMac);
}

function disableDelButton()
{
	disableButton(document.formWlAcDel.deleteSelFilterMac);
	disableButton(document.formWlAcDel.deleteAllFilterMac);
}

function enableAc()
{
  enableTextField(document.formWlAcAdd.mac);
  enableTextField(document.formWlAcAdd.comment);
}

function disableAc()
{
  disableTextField(document.formWlAcAdd.mac);
  disableTextField(document.formWlAcAdd.comment);
}


function form_reset()
{
	$("#ssid").children().eq(0).prop("selected",true);
	$("#mac").val("");
	$("#comment").val("");
	get_mac_list();
}


function page_change(selectObj)
{
	if (selectObj.value==1)
		location.href='wlan_redriect.php?redirect-url=skb_wlactrl.php&wlan_id=1';
	else
		location.href='wlan_redriect.php?redirect-url=skb_wlactrl.php&wlan_id=0';
}
var change_mode = function(){
	if($("#mode").children(":selected").val() != mode){
		$("#btn_apply").show();
	}else{
		if(add_cnt == 0){
			$("#btn_apply").hide();
		}
	}
}
var create_ssid = function(){
	var tobj = $("#ssid");
	tobj.children().remove();
	if(wlan_idx == 0){
		for (var i=0; i < ssid24.length ; i++ )
		{
			if(ssid_disable24[i] != "1"){
				if(macauth24[i] != "2"){
					tobj.append("<option value=\""+ssid24[i]+"\" seq=\""+i+"\">"+ssid24[i]+"</option>");
				}
			}
		}
	}else{
		for (var i=0; i < ssid5.length ; i++ )
		{
			if(ssid_disable5[i] != "1"){
				if(macauth5[i] != "2"){
					tobj.append("<option value=\""+ssid5[i]+"\" seq=\""+i+"\">"+ssid5[i]+"</option>");
				}
			}
		}
	}
}
var get_mac_list = function(){
//	console.log($("#ssid").children(":selected").val());
	var ssid_idx = $("#ssid").children("option").index($("#ssid").children(":selected"));
	seq = $("#ssid").children("option").eq(ssid_idx).attr("seq");
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_mac_list';
	sobj['seq'] = seq;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			var radio = "0";
			if(wlan_idx == "0"){
				radio = "1";
			}
			data = new Array();
			var tmp = new Object();
			var mac = get_json_val(d,"wireless.vap"+radio+seq+".maclist");
			var comment = get_json_val(d,"wireless.vap"+radio+seq+".comment");
			if(get_json_val(d,"wireless.vap"+radio+seq+".macaddr_acl","-1") == "-1"){
				mode = "-1";
//				console.log(mode,"wireless.vap"+radio+seq+".macaddr_acl",get_json_val(d,"wireless.vap"+radio+seq+".macaddr_acl"),$("#mode").children(":selected").val());
			}else{
				mode = get_json_val(d,"wireless.vap"+radio+seq+".macaddr_acl");
			}
			
			$("#mode").val(mode);
			if(mac != ""){
				for (var i=0; i < mac.length ; i++ )
				{
					tmp = new Object();
					tmp["mac"] =  mac[i];
					tmp["comment"] = comment[i];
					data.push(tmp);
					
				}
				
			}
			create_table();
		}
	});
}
var create_table = function(){
	$("#tbdy").children().remove();
	var tempVal = "";
	if(data.length > 0){
		for (var i=0; i < data.length ; i++ )
		{
			tempVal += "<tr>\n";
			tempVal += "\t<td>"+data[i].mac+"</td>";
			tempVal += "\t<td>"+data[i].comment+"</td>";
			tempVal += "\t<td><input type=\"checkbox\" name=\"del_mac\" id=\"del_mac"+i+"\" value=\""+data[i].mac+"\"></td>";
			tempVal += "</tr>";

		}
		$("#tbdy").append(tempVal);
	}else{
		tempVal = "<tr><td>--</td><td>--</td><td><input type=\"checkbox\"></td></tr>";
		$("#tbdy").append(tempVal);
	}
}
var form_save = function(){
	mode = $("#mode").children(":selected").val();
	var mac = $("#mac").val();
	var comment = $("#comment").val();
//	sta_name = XSSfilter(sta_name);
	if(mac == ""){
		alert("MAC주소를 입력해주세요.");
		return;
	}
	if(validation_mac(mac) == false){
		alert("MAC주소를 올바르게 입력해주세요.");
		return;
	}
	for (var i=0;i < data.length ; i++)
	{
		if(data[i].mac == mac){
			alert("이미 등록된 MAC주소입니다.");
			return;
		}
	}
	if(comment == ""){
		alert("설명을 입력해주세요.");
		return;
	}
	if(!check_xss(comment)){
		alert(xss_err_msg);
		$("#comment").focus();
		return;
	}
	comment = XSSfilter(comment);
	var tmp = new Object();
	tmp["mac"] = mac;
	tmp['comment'] = comment;
	data.push(tmp);
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'set_mac_list';
	sobj['seq'] = seq;
	sobj['mode'] = mode;
	sobj['data'] = data;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				alert("추가되었습니다.");
				$("#mac").val("");
				$("#comment").val("");
				get_mac_list();
				add_cnt++;
				$("#btn_apply").show();
				return;
			}
		}
	});
}
var del_sel_mac = function(){
	var now_mode = $("#mode").children(":selected").val();
	var tobj = $("[name='del_mac']:checked");
	for (var i=0; i < data.length ; i++ )
	{
		for (var j=0; j < tobj.length; j++)
		{
			if(data[i]["mac"] == tobj.eq(j).val()){
				data.splice(i, 1);
			}
		}
	}
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'set_mac_list';
	sobj['mode'] = now_mode;
	sobj['seq'] = seq;
	sobj['data'] = data;
	$("#btn_apply").show();
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			$("#btn_apply").show();
			add_cnt++;
			create_table();
		}
	});
	
}
var del_all_mac = function(){
	var now_mode = $("#mode").children(":selected").val();
	if(now_mode == "1"){
		if(!confirm("모든 목록을 삭제하면 어떠한 클라이언트도 AP에 연결할 수 없게 됩니다. 진행하시겠습니까?")){
			return;
		}
	}
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'del_all_data';
	sobj['mode'] = now_mode;
	sobj['seq'] = seq;
	$("#btn_apply").show();
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			data = new Array();
			add_cnt++;
			create_table();
		}
	});
}
var form_apply = function(){
	mode = $("#mode").children(":selected").val();
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'data_apply';
	sobj['mode'] = mode;
	sobj['seq'] = seq;
	create_loading();
	$(".btn").prop("disabled",true);
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				alert("적용되었습니다.");
				
				add_cnt = 0;
				get_mac_list();
				$("#btn_apply").hide();
				return;
			}
		},complete:function(){
			remove_loading();
			$(".btn").prop("disabled",false);
		}
	});
}
$(document).ready(function(){
	$("#radio").val(wlan_idx);
	create_ssid();
	get_mac_list();
	$("#btn_apply").hide();
});
</script>
</head>
<body onload="">
<blockquote>
<h2>
<?php
	if(dv_session("wlan_id") == "1"){
		echo("접근 제어 설정 5G");
	}elseif(dv_session("wlan_id") == "0"){
		echo("접근 제어 설정 2.4G");
	}else{
		echo("Wireless Access Control");
	}
?>
</h2>
<form action="/boafrm/formWlAc" method="POST" name="formWlAcAdd">
<input type="hidden" name="page" value="skb_wlactrl.php">
<input type="hidden" value="/skb_wlactrl.php" name="submit-url">
<table border="0" width="540" cellspacing="4" cellpadding="0">
	<tr>
		<td><font size="2">무선 인터넷에 연결하려는 호스트들에 대해 접근을 허용할것인지 차단할것인지 설정할 수 있는 페이지 입니다.</font></td>
	</tr>
</table>

<table width="540" height="25" border="0" cellpadding="0" cellspacing="0">
	<tr>
		<font size="2"><b>무선 : &nbsp;&nbsp;&nbsp;&nbsp;</b>
    		<select name="radio" id="radio" onchange="page_change(this)">
    			<option value="0">2.4 GHz</option>
    			<option value="1">5 GHz</option>
    		</select>
    	</font>
 	</tr>
	<tr>
		<td height="20" class="MainTD"><font size="2"><b>SSID 선택:&nbsp;&nbsp;</b> <select name="ssid" id="ssid" onchange="get_mac_list();"></select></td>
	</tr>
</table>

<table width="540" height="25" border="0" cellpadding="0" cellspacing="0">
	<tr>
		<td><hr size=1 noshade align="top"><br></td>
	</tr>
</table>
<table width="540" height="25" border="0" cellpadding="0" cellspacing="0">
	<tr>
		<td><font size="2"><b>무선 인터넷 접근 제어 모드: &nbsp;&nbsp;&nbsp;&nbsp;<select size="1" name="mode" id="mode" onchange="change_mode();">
			<option value="-1" >사용안함</option>
			<option value="1">연결허용</option>
			<option value="0" >연결차단</option>
		</select></b></font></td>
	</tr>
	<tr>
		<td><p><font size=2><b>MAC 주소: <input type="text" name="mac" id="mac" size="17" maxlength="17">&nbsp;&nbsp;</font></b>
		<b><font size=2>설명: <input type="text" name="comment" id="comment" size="16" maxlength="20"></font></b></p>
		<p><input type="button" value="추가" name="btn_add" id="btn_add" onclick="form_save();" class="btn">&nbsp;&nbsp;
		<input type="button" value="취소" name="reset" onClick="form_reset();" class="btn">&nbsp;&nbsp;&nbsp;<input type="button" value="적용" name="btn_apply" id="btn_apply" onclick="form_apply();" class="btn">
		<input type="hidden" value="/skb_wlactrl.php" name="submit-url"></p></td>
	</tr>
</table>
<br>
<table border="0" width="480"  id="dynamicTable">
	<thead>
		<tr>
			<td colspan="3"><font size="2"><b>현재 접근 제어 목록:</b></font></td>
		</tr>
		<tr>
			<td align="center" width="45%" class="tbl_title"><font size="2" color="white"><b>MAC 주소</b></font></td>
			<td align="center" width="35%" class="tbl_title"><font size="2" color="white"><b>설명</b></font></td>
			<td align="center" width="20%" class="tbl_title"><font size="2" color="white"><b>선택</b></font></td>
		</tr>
	</thead>
	<tbody id="tbdy"></tbody>
</table>
<br>
<input type="button" value="선택 삭제" name="btn_sel_del" onclick="del_sel_mac();" class="btn">&nbsp;&nbsp;
<input type="button" value="전체 삭제" name="btn_all_del" onclick="del_all_mac();" class="btn">&nbsp;&nbsp;&nbsp;
</form>
</blockquote>
</body>
</html>
