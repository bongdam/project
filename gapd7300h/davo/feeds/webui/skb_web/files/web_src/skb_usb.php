<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
//	check_admin($isAdmin );
	$host = $_SERVER["HTTP_HOST"];
	if(strpos($host,":") === false){
		$ip = $host;
	}else{
		$ip = substr($host,0,strpos($host,":"));
	}
	
	function convert_disk_type($type_){
		Switch($type_){
			case "vfat":
				return "FAT32";
				break;
			case "exfat":
				return "exFAT";
				break;
			case "ntfs":
				return "NTFS";
				break;
			default:
				return "UNKNOWN";
				break;
		}
	}
	$smb_enable = 0;
	$index0 = "";
	$index1 = "";
	$server_port = "";

	$cfg = new dvcfg();
	$cfg->read("samba");
	$cfg->read("dvui");
//	print_r($cfg->result("json_string"));
	if($cfg->search("samba.smb_config.enabled") == "1"){
		$smb_enable = 1;
		$server_port = $cfg->search("dvui.nas.port");
		$index0 = $cfg->search("samba.index0.name");
		$index1 = $cfg->search("samba.index1.name");
		$index0_dev = $cfg->search("samba.index0.dev");
		$index1_dev = $cfg->search("samba.index1.dev");
		$index0_disk_type = convert_disk_type($cfg->search("samba.index0.disk_type"));
		$index1_disk_type = convert_disk_type($cfg->search("samba.index1.disk_type"));
		$index0_labal = $cfg->search("samba.index0.label");
		$index1_labal = $cfg->search("samba.index1.label");
		if($index0_dev != ""){
			$index0_use = exec("df ".$index0_dev." | sed '1,1d'");
		}
		if($index1_dev != ""){
			$index1_use = exec("df ".$index1_dev." | sed '1,1d'");
		}
		$cfg->close();
		$index0_info = null;
		$index1_info = null;
		if($index0_dev != ""){
			if(preg_match("/(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+([\S+\/]{1,})/",$index0_use,$d) == true) {
				$index0_info = Array(
					"mount" => $d[1],
					"total" => $d[2],
					"used"	=> $d[3],
					"free"	=> $d[4],
					"use"	=> $d[5],
					"mount_on" => $d[6]
				);
			}
		}
		if($index1_dev != ""){
			if(preg_match("/(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+([\S+\/]{1,})/",$index1_use,$d) == true) {
				$index1_info = Array(
					"mount" => $d[1],
					"total" => $d[2],
					"used"	=> $d[3],
					"free"	=> $d[4],
					"use"	=> $d[5],
					"mount_on" => $d[6]
				);
			}
		}
	}
/*
	vfat = FAT32
	exfat = exFAT
	ntfs = NTFS
*/
	
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>USB 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/modal/remodal.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<link href="inc/js/modal/remodal.css" rel="stylesheet" type="text/css">
<link href="inc/js/modal/remodal-default-theme.css" rel="stylesheet" type="text/css">
<style type="text/css">
.contd{
	background-color:#fff;
	height:26px;
	padding-left:5px;
}
.tltd{
	background-color:#e1e1e1;
	height:26px;
}
</style>
<script type="text/javascript">
function save_valid()
{
	var samba_ = $("#samba").children(":selected").val();
	var server_port_ = $("#server_port").val();
	var allow_wan_ = $("#allow_wan").children(":selected").val();
	if(isNumVal(server_port_) == false){
		alert("포트 번호가 올바르지 않습니다! 1에서 65535 사이의 숫자를 입력해야 합니다.");
		$("#server_port").focus();
		return;
	}
	if(check_min_max(server_port_,1,65535) == false){
		alert("포트 번호가 올바르지 않습니다! 1에서 65535 사이의 숫자를 입력해야 합니다.");
		$("#server_port").focus();
		return;
	}
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'samba_setting';
	sobj['samba_enable'] = samba_;
	sobj['server_port'] = server_port_;
	sobj['allow_wan'] = allow_wan_;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				alert("적용되었습니다.");
				restart_web_server();
			}
		},complete:function(){
			
		}
	});
}
var restart_web_server = function(){
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'web_server_restart';
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			
		},complete:function(){
			window.location.reload();
		}
	});
}

function resetClick()
{
	document.location.assign("skb_usb.php");
}
var proc = "proc/skb_usb_proc.php";
var arruser = new Array();

var convert_permission = function(val_){
	switch(val_){
		case 1:
			return "읽기/쓰기";
			break;
		case 0:
			return "읽기";
			break;
	}
}
var get_user = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_user';
	$("#tbdy").children().remove();
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			var tempVal = "";
			$("#server_port").val(get_json_val(d,"dvui.nas.port"));
			$("#allow_wan").val(get_json_val(d,"dvui.nas.allow_wan"));
			
			if(get_json_val(d,"dvui.nas.user") != ""){
				var cnt = get_json_val(d,"dvui.nas.user").length;
				for (var i=0; i < cnt ; i++ )
				{
					arruser[i] = get_json_val(d,"dvui.nas.user")[i];
					tempVal += "<tr style=\"background-color:#fff;\">";
					tempVal += "<td style=\"text-align:center\">"+get_json_val(d,"dvui.nas.user")[i]+"</td>";
					tempVal += "<td style=\"text-align:center\">"+convert_permission(get_json_val(d,"dvui.nas.permission")[i])+"</td>";
					tempVal += "<td style=\"text-align:center\">"+get_json_val(d,"dvui.nas.comment")[i]+"</td>";
					tempVal += "<td style=\"text-align:center\"><input type=\"button\" name=\"btn_del\" id=\"b\" value=\"삭제\" onclick=\"del_user('"+get_json_val(d,"dvui.nas.user")[i]+"')\"></td>";
					tempVal += "</tr>";
				}
			}else{
				tempVal += "<tr style=\"background-color:#fff;\">";
				tempVal += "<td colspan=\"4\" style=\"text-align:center\">등록 된 사용자 없음.</td>";
				tempVal += "</tr>";
			}
			$("#tbdy").append(tempVal);
		},complete:function(){
			
		}
	});
}
var model = null;
var add_user = function(){
//	$("#user_form").show();
	$("#user_id").val("");
	$("#user_pass").val("");
	$("#user_pass_re").val("");
	$("#user_comment").val("");
	$("#user_permit1").prop("checked",true);
	model.open();
	$("#mode").val("new");
}


var set_user = function(){
	var mode = $("#mode").val();
	var user_id  = $("#user_id").val();
	var user_pass = $("#user_pass").val();
	var user_pass_re = $("#user_pass_re").val();
	var user_permit = $("#user_permit1").prop("checked") ? "1":"0";
	var user_comment = $("#user_comment").val();
	if(user_id == ""){
		alert("아이디를 입력해주세요.");
		$("#user_id").focus();
		return;
	}
	if(arruser.indexOf(user_id) != -1){
		alert("이미 등록된 아이디 입니다.");
		$("#user_id").focus();
		return;
	}
	if(!check_xss(user_id)){
		alert(xss_err_msg);
		$("#user_id").focus();
		return;
	}
	if(user_pass == ""){
		alert("패스워드를 입력해주세요.");
		$("#user_pass").focus();
		return;
	}
	if(!check_xss(user_pass)){
		alert(xss_err_msg);
		$("#user_pass").focus();
		return;
	}
	if(user_pass_re == ""){
		alert("패스워드 확인을 입력해주세요.");
		$("#user_pass_re").focus();
		return;
	}
	if(user_pass != user_pass_re){
		alert("패스워드가 일치하지 않습니다.");
		$("#user_pass").focus();
		return;
	}
	if(user_comment == ""){
		alert("설명을 입력해주세요.");
		$("#user_comment").focus();
		return;
	}
	if(!check_xss(user_comment)){
		alert(xss_err_msg);
		$("#user_comment").focus();
		return;
	}
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'set_user';
	sobj['user'] = user_id;
	sobj['pass'] = user_pass;
	sobj['comment'] = user_comment;
	sobj['permission'] = user_permit;
//	$("#tbdy").children().remove();
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				alert("등록되었습니다.");
				get_user();
			}
		},complete:function(){
			
		}
	});
	model.close();
}
var del_user = function(user_id_){
	if(!confirm("삭제하시겠습니까?")){
		return;
	}
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'del_user';
	sobj['user_id'] = user_id_;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				get_user();
			}
		}
	});
}
$(document).ready(function(){
	get_user();
	if($("#samba").children(":selected").val() == "1"){
		$(".nas").show();
	}else{
		$(".nas").hide();
	}

	
	$(document).on('confirmation', '[data-remodal-id=modal]', function () {
//		console.log('Confirmation button is clicked');
		set_user();
	});
});
</script>
</head>
<blockquote>
<body>
<b><font size="3" face="arial" color="#3c7A95">USB 설정</font></b>
<table border="0" width="550" cellspacing="4" cellpadding="0">
	<tr>
		<td><font size="2"><br>USB 장치의 공유 기능 설정 페이지입니다.</font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>

<form name="formSamba" action="proc/skb_usb_proc.php" method="POST">
	<input type="hidden" name="samba_enable" value="" >
	<input type="hidden" name="mode" id="mode" value="new">
	<input type="hidden" name="act" value="samba_setting" >
	<table border="0" width="550" cellspacing="0" cellpadding="0">
		<tr>
			<td width="15%" align="center">
				&nbsp;선택 :
			</td>
			<td align="left">&nbsp;&nbsp;&nbsp;
				<select name="samba" id="samba" >
					<option value="0" <?php if($smb_enable == "0"){echo("selected");}?>>Disable</option>
					<option value="1" <?php if($smb_enable == "1"){echo("selected");}?>>Enable</option>
					<!--option value=16000>16000 Byte</option-->
				</select>
				<!--input type="checkbox" name="jumbo_check" value="1" -->
			</td>
		</tr>
		<tr class="nas">
			<td width="15%" align="center">
				&nbsp;NAS 포트 :
			</td>
			<td align="left">&nbsp;&nbsp;&nbsp;&nbsp;<input type="text" name="server_port" id="server_port" value="" size="5" maxlength="5"></td>
		</tr>
		<tr class="nas">
			<td width="15%" align="center">
				&nbsp;NAS 외부접속 허용 :
			</td>
			<td align="left">&nbsp;&nbsp;&nbsp;&nbsp;<select name="allow_wan" id="allow_wan">
				<option value="1">허용</option>
				<option value="0">차단</option>
			</select></td>
		</tr>
		<tr class="nas">
			<td width="15%" align="center">
				&nbsp;NAS URL :
			</td>
			<td align="left">&nbsp;&nbsp;&nbsp;&nbsp;<a href="http://<?=$ip?>:<?=$server_port?>" target="_blank">NAS</a></td>
		</tr>
	</table>
	<br>
	<input type="button" value="적용" name="save" onclick="save_valid();">
	<input type="hidden" value="/skb_usb.php" name="submit-url" >
	<input type="reset" value="취소" name="reset" onclick="resetClick();">
	<br><br>
	<?php
		if($smb_enable == "1"){
	?>
	<?php
			if($index0 != "" || $index1 != ""){
	?>
	<table border="0" width="550" cellspacing="1" cellpadding="0" style="background-color:#333;">
		<tr style="background-color:#e1e1e1;">
			<td>USB장치이름</td>
			<td>파일시스템</td>
			<td>총 용량 (KB)</td>
			<td>남은 용량(KB)</td>
		</tr>
		<?if($index0_info != null){?>
		<tr style="background-color:#fff;">
			<td><?=$index0_labal?></td>
			<td><?=$index0_disk_type?></td>
			<td><?=$index0_info["total"]?></td>
			<td><?=$index0_info["free"]?></td>
		</tr>
		<?}?>
		<?if($index1_info != null){?>
		<tr style="background-color:#fff;">
			<td><?=$index1_labal?></td>
			<td><?=$index1_disk_type?></td>
			<td><?=$index1_info["total"]?></td>
			<td><?=$index1_info["free"]?></td>
		</tr>
		<?}?>
	</table>
	<?php
			}
	?>
	<br>
	<table border="0" width="550" cellspacing="1" cellpadding="0" style="background-color:#333;">
		<thead>
			<tr style="background-color:#e1e1e1;">
				<th>사용자</th>
				<th>권한</th>
				<th>설명</th>
				<th>삭제</th>
			</tr>
		</thead>
		<tbody id="tbdy"></tbody>
	</table>
	<br>
	<input type="button" name="btn_add" id="btn_add" value="추가" onclick="add_user();">
	<?php
		}
	?>
</form>
</blockquote>
<div class="remodal" data-remodal-id="modal" role="dialog" aria-labelledby="modal1Title" aria-describedby="modal1Desc">
	<button data-remodal-action="close" class="remodal-close" aria-label="Close"></button>
	<div>
		<table border="0" cellspacing="1" cellpadding="0" style="background-color:#333;width:95%;">
			<tr>
				<td class="tltd" width="25%">사용자 ID</td>
				<td class="contd"><input type="text" name="user_id" id="user_id" value="" maxlength="32"></td>
			</tr>
			<tr>
				<td class="tltd">패스워드</td>
				<td class="contd"><input type="password" name="user_pass" id="user_pass" value="" maxlength="32"></td>
			</tr>
			<tr>
				<td class="tltd">패스워드 확인</td>
				<td class="contd"><input type="password" name="user_pass_re" id="user_pass_re" value="" maxlength="32"></td>
			</tr>
			<tr>
				<td class="tltd">권한</td>
				<td class="contd"><input type="radio" name="user_permit" id="user_permit1" value="1">읽기/쓰기&nbsp;<input type="radio" name="user_permit" id="user_permit0" value="0">읽기</td>
			</tr>
			<tr>
				<td class="tltd">설명</td>
				<td class="contd"><input type="text" name="user_comment" id="user_comment" value="" maxlength="64"></td>
			</tr>
		</table>
	</div>
	<br>
	<button data-remodal-action="confirm" class="remodal-confirm">저장</button>
	<button data-remodal-action="cancel" class="remodal-cancel">취소</button>
</div>
<script type="text/javascript">
model = $('[data-remodal-id=modal]').remodal({closeOnConfirm: false});
</script>
</body>
</html>
