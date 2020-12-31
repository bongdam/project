<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	check_admin($isAdmin );
	$wan_no = dv_session("wan_no");
	$lan1_no = dv_session("lan_no");
	$uci = new uci();
	$uci->mode("ck");
	$uci->ck("igmpproxy.@igmpproxy[0]");
	$uci->run();
	$ck = json_decode($uci->result(),true);
	$uci->mode("get");
	$uci->get("igmpproxy.".$ck["igmpproxy.@igmpproxy[0]"]);
	$uci->get("network.lan");
	$uci->get("mcsd.config");
	for($i=1; $i <= 5; $i++){
		$uci->get("network.igmpPtlearnlimit_".$i);
	}
	$uci->run();
	$get = json_decode($uci->result(),true);
//	print_r($get);
	if($get["network.lan._orig_ifname"] == ""){
		$opmode = 0;
	}else{
		$opmode = 1;
	}
	if($get["igmpproxy.".$ck["igmpproxy.@igmpproxy[0]"].".quickleave"] == "1"){
		$fast_leave = 1;
	}else{
		$fast_leave = 0;
	}
	$ig_join = Array();
	$ig_join_total = 0;
	$ig_join_enable = "";
	for($i=$lan1_no; $i < ($lan1_no+4);$i++){
		if($i == $lan1_no){
			if($get["network.igmpPtlearnlimit_".$i.".learn_limit_status"] == "enable"){
				$ig_join_enable = "checked";
			}
		}
		$ig_join[] = $get["network.igmpPtlearnlimit_".$i.".learn_limit_counter"];
		$ig_join_total += $get["network.igmpPtlearnlimit_".$i.".learn_limit_counter"];
	}
	$ig_member_enable = "";
	if($get["mcsd.config.query_mode"] != "0"){
		$ig_member_enable = "checked";
	}
	$ig_querier_auto = $get["mcsd.config.query_mode"];
	$ig_querier_interval = $get["mcsd.config.query_interval"];
	



//	$dhcpfile = @fopen("/root/igmp", "r");
//	$dhcpinfo = fread($dhcpfile,filesize("/root/igmp"));
//	fclose($dhcpfile);
	$cmd = new dvcmd();
	$cmd->add("igmpshow");
	$cmd->run();
	$dhcpinfo = $cmd->result()[0];
	$cmd->close();
	$igmp = explode("\n",rtrim($dhcpinfo));
	$igmp_list = Array();
	$group_no = 0;
	$group_name = "";
	$sub_cnt = 0;
	$group_list = Array();
	for($i=0; $i < count($igmp);$i++){
		if(preg_match("/^(\d+)\s+(\d+\.\d+\.\d+\.\d+)/",$igmp[$i],$d) == true) {
			$sub_cnt = 0;
//			echo $d[1]."<br>";
//			echo $d[2];
			$igmp_list[$d[1]] = Array();
			$group_no = $d[1];
			$group_name = $d[2];
			$group_list[$d[1]] = Array();
			$group_list[$d[1]]["no"]=$group_no;
			$group_list[$d[1]]["group"]=$group_name;
			$group_list[$d[1]]["lan1"]="";
			$group_list[$d[1]]["lan2"]="";
			$group_list[$d[1]]["lan3"]="";
			$group_list[$d[1]]["lan4"]="";
			$group_list[$d[1]]["age"]=0;
//			$igmp_list[$group_name]["no"] = $group_no;
		}
		if(preg_match("/^\s+(\d+\.\d+\.\d+\.\d+)\s+(\w+\:\w+\:\w+\:\w+\:\w+\:\w+)\s+(\d+)\s+(\d+)/",$igmp[$i],$d) == true) {
//			echo $d[1]."<br>";
//			echo $d[2]."<br>";
//			echo $d[3]."<br>";
//			echo $d[4]."<br>";
			$igmp_list[$group_no][$sub_cnt]["no"] = $group_no;
			$igmp_list[$group_no][$sub_cnt]["group"] = $group_name;
			$igmp_list[$group_no][$sub_cnt]["user"] = $d[1];
			$igmp_list[$group_no][$sub_cnt]["mac"] = $d[2];
			$igmp_list[$group_no][$sub_cnt]["port"] = $d[3];
			$igmp_list[$group_no][$sub_cnt]["age"] = $d[4];
			switch($d[3]){
				case 1:
					$group_list[$group_no]["lan1"]="1";
					break;
				case 2:
					$group_list[$group_no]["lan2"]="1";
					break;
				case 3:
					$group_list[$group_no]["lan3"]="1";
					break;
				case 4:
					$group_list[$group_no]["lan4"]="1";
					break;
			}
			if($d[4] > $group_list[$group_no]["age"]){
				$group_list[$group_no]["age"] = $d[4];
			}
			$sub_cnt+=1;
		}
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
<title>IGMP 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">

var opMode = <?=$opmode?>;
function load_igmp_querier()
{
	var igmp_querier_auto = <?=$ig_querier_auto?>;

	if(opMode==1) {
		document.igmpSet.igmp_querier_enable.disabled = false;

		if(document.igmpSet.igmp_querier_enable.checked){
			document.igmpSet.igmp_querier_interval.disabled = false;
			document.igmpSet.igmp_querier_mode[0].disabled = false;
			document.igmpSet.igmp_querier_mode[1].disabled = false;

			if(igmp_querier_auto == 1){
				document.igmpSet.igmp_querier_mode[0].checked = true;
			}else{
				document.igmpSet.igmp_querier_mode[1].checked = true;
			}
		}
		else{
			document.igmpSet.igmp_querier_mode[1].checked = true;
			document.igmpSet.igmp_querier_interval.disabled = true;
			document.igmpSet.igmp_querier_mode[0].disabled = true;
			document.igmpSet.igmp_querier_mode[1].disabled = true;
		}

	}
	else {
		document.igmpSet.igmp_querier_enable.disabled = true;
		document.igmpSet.igmp_querier_interval.disabled = true;
		document.igmpSet.igmp_querier_mode[0].disabled = true;
		document.igmpSet.igmp_querier_mode[1].disabled = true;
	}
	return;
}

function validateNum(str)
{
  for (var i=0; i<str.length; i++) {
   	if ( !(str.charAt(i) >='0' && str.charAt(i) <= '9')) {
		alert('값이 올바르지 않습니다. 숫자를 입력해야 합니다. (0-9)');
		return false;
  	}
  }
  return true;
}

function load_button(flag)
{
	document.igmpSet.lan1_control.disabled = flag;
	document.igmpSet.lan2_control.disabled = flag;
	document.igmpSet.lan3_control.disabled = flag;
	document.igmpSet.lan4_control.disabled = flag;
}

function load_igmpblock()
{
	if(document.igmpSet.igmp_block_enable.checked){
		document.igmpSet.igmp_thresh_hold.disabled = false;
		document.igmpSet.igmp_block_period.disabled = false;
//		load_button(false);
	}
	else{
		document.igmpSet.igmp_thresh_hold.disabled = true;
		document.igmpSet.igmp_block_period.disabled = true;
//		load_button(true);
	}
	return;
}

function load_button_check()
{
	if(document.igmpSet.port1_status.value == "0")
		document.igmpSet.lan1_control.disabled = true;
	if(document.igmpSet.port2_status.value == "0")
		document.igmpSet.lan2_control.disabled = true;
	if(document.igmpSet.port3_status.value == "0")
		document.igmpSet.lan3_control.disabled = true;
	if(document.igmpSet.port4_status.value == "0")
		document.igmpSet.lan4_control.disabled = true;

	return;
}

function load_join_limit()
{
	if(document.igmpSet.dv_igmp_joinlimit_enable.checked){
		document.igmpSet.dv_igmp_limite_lan1.disabled = false;
		document.igmpSet.dv_igmp_limite_lan2.disabled = false;
		document.igmpSet.dv_igmp_limite_lan3.disabled = false;
		document.igmpSet.dv_igmp_limite_lan4.disabled = false;
		document.igmpSet.dv_igmp_limite_sys.disabled = false;

	}
	else{
		document.igmpSet.dv_igmp_limite_lan1.disabled = true;
		document.igmpSet.dv_igmp_limite_lan2.disabled = true;
		document.igmpSet.dv_igmp_limite_lan3.disabled = true;
		document.igmpSet.dv_igmp_limite_lan4.disabled = true;
		document.igmpSet.dv_igmp_limite_sys.disabled = true;
	}
	return;
}

function check_val()
{
	if(validateNum(document.igmpSet.igmp_querier_interval.value) == 0){
		document.igmpSet.igmp_querier_interval.focus();
		return false;
	}

	if(validateNum(document.igmpSet.dv_igmp_limite_lan1.value) == 0){
		document.igmpSet.dv_igmp_limite_lan1.focus();
		return false;
	}
	if(validateNum(document.igmpSet.dv_igmp_limite_lan2.value) == 0){
		document.igmpSet.dv_igmp_limite_lan2.focus();
		return false;
	}
	if(validateNum(document.igmpSet.dv_igmp_limite_lan3.value) == 0){
		document.igmpSet.dv_igmp_limite_lan3.focus();
		return false;
	}
	if(validateNum(document.igmpSet.dv_igmp_limite_lan4.value) == 0){
		document.igmpSet.dv_igmp_limite_lan4.focus();
		return false;
	}
	if(validateNum(document.igmpSet.dv_igmp_limite_sys.value) == 0){
		document.igmpSet.dv_igmp_limite_sys.focus();
		return false;
	}

	if(validateNum(document.igmpSet.igmp_thresh_hold.value) == 0){
		document.igmpSet.igmp_thresh_hold.focus();
		return false;
	}

	if(validateNum(document.igmpSet.igmp_block_period.value) == 0){
		document.igmpSet.igmp_block_period.focus();
		return false;
	}
	var val_querier_interval = parseInt(document.igmpSet.igmp_querier_interval.value);
	var val_thresh_hold = parseInt(document.igmpSet.igmp_thresh_hold.value);
	var val_block_period = parseInt(document.igmpSet.igmp_block_period.value);

	if(!(val_querier_interval >= 0 && val_querier_interval <= 1800)){
		document.igmpSet.igmp_querier_interval.focus();
		alert('쿼리 간격은 0~1800 사이의 값이어야 합니다.');
		return false;
	}
	if(!(val_thresh_hold >= 0 && val_thresh_hold <= 10000)){
		document.igmpSet.igmp_thresh_hold.focus();
		alert('Block 임계치는 0~10000 사이의 값이어야 합니다.');
		return false;
	}

	if(!(val_block_period >= 0 && val_block_period <= 3600)){
		document.igmpSet.igmp_block_period.focus();
		alert('Block 기간은 0~3600 사이의 값이어야 합니다.');
		return false;
	}
	var total = 0;
	if(document.igmpSet.dv_igmp_limite_lan1.value > 32){
		document.igmpSet.dv_igmp_limite_lan1.focus();
		alert('포트별 IGMP Join 사용 제한은 최대 32입니다.');
		return false;
	}
	total += parseInt(document.igmpSet.dv_igmp_limite_lan1.value,10);
	if(document.igmpSet.dv_igmp_limite_lan2.value > 32){
		document.igmpSet.dv_igmp_limite_lan2.focus();
		alert('포트별 IGMP Join 사용 제한은 최대 32입니다.');
		return false;
	}
	total += parseInt(document.igmpSet.dv_igmp_limite_lan2.value,10);
	if(document.igmpSet.dv_igmp_limite_lan3.value > 32){
		document.igmpSet.dv_igmp_limite_lan3.focus();
		alert('포트별 IGMP Join 사용 제한은 최대 32입니다.');
		return false;
	}
	total += parseInt(document.igmpSet.dv_igmp_limite_lan3.value,10);
	if(document.igmpSet.dv_igmp_limite_lan4.value > 32){
		document.igmpSet.dv_igmp_limite_lan4.focus();
		alert('포트별 IGMP Join 사용 제한은 최대 32입니다.');
		return false;
	}
	total += parseInt(document.igmpSet.dv_igmp_limite_lan4.value,10);
	document.igmpSet.dv_igmp_limite_sys.value = total
	if(total > 100){
		document.igmpSet.dv_igmp_limite_lan1.focus();
		alert('IGMP Join 사용 제한은 최대 100입니다.');
		return false;
	}

	document.igmpSet.hidden_querier_interval.value = val_querier_interval;
	document.igmpSet.hidden_thresh_hold.value = val_thresh_hold;
	document.igmpSet.hidden_block_period.value = val_block_period;

	return true;
}

function resetForm()
{
	document.location.assign("skb_igmp.php");
}

function init()
{
	var vlimit_enable = "<?=$ig_join_enable?>";
	var fast_leave = <?=$fast_leave?>;
	if(fast_leave == 1){
		document.igmpSet.igmpfast.checked = true;
	}else{
		document.igmpSet.igmpfast.checked = false;
	}
	vlimit_enable = trim(vlimit_enable);
	if (vlimit_enable == "checked") {
		document.igmpSet.dv_igmp_limite_lan1.disabled = false;
		document.igmpSet.dv_igmp_limite_lan2.disabled = false;
		document.igmpSet.dv_igmp_limite_lan3.disabled = false;
		document.igmpSet.dv_igmp_limite_lan4.disabled = false;
		document.igmpSet.dv_igmp_limite_sys.disabled = false;
	} else {
		document.igmpSet.dv_igmp_limite_lan1.disabled = true;
		document.igmpSet.dv_igmp_limite_lan2.disabled = true;
		document.igmpSet.dv_igmp_limite_lan3.disabled = true;
		document.igmpSet.dv_igmp_limite_lan4.disabled = true;
		document.igmpSet.dv_igmp_limite_sys.disabled = true;
	}
	if(opMode==1) {
		document.igmpSet.igmp_querier_enable.disabled = false;
		document.igmpSet.igmp_querier_interval.disabled = false;
		document.igmpSet.igmp_querier_mode[0].disabled = false;
		document.igmpSet.igmp_querier_mode[1].disabled = false;
		load_igmp_querier();
	} else {
		document.igmpSet.igmp_querier_enable.disabled = true;
		document.igmpSet.igmp_querier_interval.disabled = true;
		document.igmpSet.igmp_querier_mode[0].disabled = true;
		document.igmpSet.igmp_querier_mode[1].disabled = true;
	}

	load_igmpblock();
}

function showJoinClick(info, port_)
{
	document.igmpSet.choiceButton.value = info;
	openWindow("skb_join.php?info="+info+"&port="+port_+"#form", 'IGMP_JOIN_STATUS', 650, 250 );
}
</script>
</head>
<body onload="init();">
<blockquote>
<h2>IGMP 설정</h2>

<table border=0 width="540" cellspacing=4 cellpadding=0>
<tr><td><font size=2>
IGMP 설정 페이지입니다.
</font></td></tr>
<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<form action="proc/skb_igmp_proc.php" method="POST" name="igmpSet">
<input type="hidden" name="wan_no" value="<?=$wan_no?>">
<input type="hidden" name="lan1_no" value="<?=$lan1_no?>">
	<table border=0 width="540" cellspacing="4" cellpadding="0">
		<tr>
      		<td><input type="checkbox" name="igmpfast" value="1" >
			<font size="2"><b>IGMP Fast Leave </b></font></td>
  		</tr>
 		<tr>
			<td>
				<input type="checkbox" name="igmp_querier_enable" onclick="load_igmp_querier();" value="1" <?=$ig_member_enable?> >
				<font size="2"><b>IGMP Membership Query 발생 (브릿지 모드)</b></font><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				<input type="text" name="igmp_querier_interval" size="5" maxlength="5" style="text-align:center;" value="<?=$ig_querier_interval?>" >
				<font size="2">초 간격으로 발생</font><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				<input type="radio" name="igmp_querier_mode" value="1"><font size="2">Auto</font><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				<input type="radio" name="igmp_querier_mode" value="2"><font size="2">강제 발생</font><br><br>
			</td>
		</tr>
	</table>


	<table border=0 width="350" cellspacing=0 cellpadding=0>
		<tr>
			<td>
				<input type="checkbox" name="dv_igmp_joinlimit_enable" onclick="load_join_limit();" value="1" <?=$ig_join_enable?> >
				<font size="2"><b>IGMP Join 제한 사용 (포트 별: 최대 32개) </b></font>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
			</td>
		</tr>
	</table>

	<table border=0 width="350" cellspacing=1 cellpadding=2>
		<tr class='tbl_head' align="center">
			<td width="70"><b>LAN1</b></td>
			<td width="70"><b>LAN2</b></td>
			<td width="70"><b>LAN3</b></td>
			<td width="70"><b>LAN4</b></td>
			<td width="70"><b>SYSTEM</b></td>
		</tr>
		<tr align="center">
			<td width="70"><input type="text" style="width:100%; text-align:center;" name="dv_igmp_limite_lan1" maxlength="2" value="<?=$ig_join[0]?>" ></td>
			<td width="70"><input type="text" style="width:100%; text-align:center;" name="dv_igmp_limite_lan2" maxlength="2" value="<?=$ig_join[1]?>" ></td>
			<td width="70"><input type="text" style="width:100%; text-align:center;" name="dv_igmp_limite_lan3" maxlength="2" value="<?=$ig_join[2]?>" ></td>
			<td width="70"><input type="text" style="width:100%; text-align:center;" name="dv_igmp_limite_lan4" maxlength="2" value="<?=$ig_join[3]?>" ></td>
			<td width="70"><input type="text" style="width:100%; text-align:center;" name="dv_igmp_limite_sys"  maxlength="3" value="<?=$ig_join_total?>" readonly ></td>
		</tr>
	</table>

	<table border=0 width="540" cellspacing=4 cellpadding=0 style="display:none">
		<tr>
			<td><br>
				<input type="checkbox" name="igmp_block_enable" onclick="load_igmpblock();load_button_check();" value="1"  >
				<font size="2"><b>IGMP Block Control 활성 </b></font><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				<font size="2">Block 임계치</font>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				<input type="text" name="igmp_thresh_hold" style="text-align:center;" size="5" maxlength="5" value="60" ><font size="2">&nbsp;pps(packet per second)</font><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				<font size="2">Block 기간</font>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				<input type="text" name="igmp_block_period"  style="text-align:center;" size="5" maxlength="5" value="50" ><font size="2">&nbsp;초</font><br>
	</table>

<!-- 	<table border=0 width="500" cellspacing=1 cellpadding=2> -->
<!-- 		<tr> -->
<!-- 	 		<td><br><font size="2"><b>IGMP Block 상태</b></font></td> -->
<!-- 		</tr> -->
<!-- 	</table> -->
<!--  -->
<!-- 	<table border=0 width="500" cellspacing=1 cellpadding=2> -->
<!-- 		<tr class='tbl_head' align="center"> -->
<!-- 			<td width="100"><b>포트</b></td><td width="100"><b>전달</b></td><td width="100"><b>드랍</b></td><td width="100"><b>상태</b></td><td width="100"><b>제어</b></td></tr> -->
<!-- 			<tr bgcolor=#DDDDDD align='center'><td>LAN1</td>			<td>0</td><td>0</td><td>사용중</td><td><input type='submit' value='강제해제' name='lan1_control' ></td>			</tr> -->
<!-- <tr bgcolor=#DDDDDD align='center'><td>LAN2</td>			<td>0</td><td>0</td><td>사용중</td><td><input type='submit' value='강제해제' name='lan2_control' ></td>			</tr> -->
<!-- <tr bgcolor=#DDDDDD align='center'><td>LAN3</td>			<td>0</td><td>0</td><td>사용중</td><td><input type='submit' value='강제해제' name='lan3_control' ></td>			</tr> -->
<!-- <tr bgcolor=#DDDDDD align='center'><td>LAN4</td>			<td>0</td><td>0</td><td>사용중</td><td><input type='submit' value='강제해제' name='lan4_control' ></td>			</tr> -->
<!-- </table><input type='hidden' value='0' name='port1_status'> -->
<!-- <input type='hidden' value='0' name='port2_status'> -->
<!-- <input type='hidden' value='0' name='port3_status'> -->
<!-- <input type='hidden' value='0' name='port4_status'> -->




	<table border=0 width="540" cellspacing=0 cellpadding=0>
		<tr>
			<td><br>
				<font size="2"><b>IGMP Snooping 테이블</b></font><br>
			</td>
		</tr>
	</table>

	<table border='0' width='450' cellspacing='1'>
		<tr align='center' class='tbl_head'>
			<td width="50"><b>No.</b></td>
			<td width="150"><b>Group Address</b></td>
			<td width="50"><b>LAN1</b></td>
			<td width="50"><b>LAN2</b></td>
			<td width="50"><b>LAN3</b></td>
			<td width="50"><b>LAN4</b></td>
			<td width="50"><b>AGE</b></td>
		</tr>
<?php
		if(count($group_list) > 0){
			$keys = array_keys($group_list);
			for($i=0; $i < count($keys); $i++){
	//			echo $keys[$i]."<br>";
				$lan1 = "";
				$lan2 = "";
				$lan3 = "";
				$lan4 = "";
				if($group_list[$keys[$i]]["lan1"] == "1"){
					$lan1 = "<input type=\"button\" name=\"\" id=\"\" value=\"LAN1\" onclick=\"showJoinClick('".$group_list[$keys[$i]]["no"]."',1);\">";
				}
				if($group_list[$keys[$i]]["lan2"] == "1"){
					$lan2 = "<input type=\"button\" name=\"\" id=\"\" value=\"LAN2\" onclick=\"showJoinClick('".$group_list[$keys[$i]]["no"]."',2);\">";
				}
				if($group_list[$keys[$i]]["lan3"] == "1"){
					$lan3 = "<input type=\"button\" name=\"\" id=\"\" value=\"LAN3\" onclick=\"showJoinClick('".$group_list[$keys[$i]]["no"]."',3);\">";
				}
				if($group_list[$keys[$i]]["lan4"] == "1"){
					$lan4 = "<input type=\"button\" name=\"\" id=\"\" value=\"LAN4\" onclick=\"showJoinClick('".$group_list[$keys[$i]]["no"]."',4);\">";
				}
				$age = $group_list[$keys[$i]]["age"];
?>
		<tr align='center' bgcolor='#DDDDDD'>
			<td><?=$keys[$i]?></td><td><?=$group_list[$keys[$i]]["group"]?></td><td><?=$lan1?></td><td><?=$lan2?></td><td><?=$lan3?></td><td><?=$lan4?></td><td><?=$age?></td>
		</tr>
<?php
			}
		}else{
?>
		<tr align='center' bgcolor='#DDDDDD'>
			<td>---</td><td>---</td><td>---</td><td>---</td><td>---</td><td>---</td><td>---</td>
		</tr>
<?php
		}
?>
	</table>


<table>
	<tr>
		<td>
			<br>&nbsp;&nbsp;<input type="submit" value="적용" name="apply" onclick="return check_val()">
			&nbsp;&nbsp;<input type='button' name='View' value='다시 보기' onClick="resetForm()">
			<input type='hidden' name='choiceButton' value='0'>
		</td>
	</tr>
</table>
<input type="hidden" value="/skb_igmp.php" name="submit-url">
<input type="hidden" value="0" name="hidden_thresh_hold">
<input type="hidden" value="0" name="hidden_block_period">
<input type="hidden" value="0" name="hidden_querier_interval">
</form>
</blockquote>
</body>
</html>
