<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$radio_ = dv_session("wlan_id");
	if(DEF_MODEL != "QCA_REF" && DEF_ANT == "4x4"){
		if($radio_ == "0"){
			$radio = "1";
		}else{
			$radio = "0";
		}
	}
	$uci = new uci();
	$uci->mode("get");
	$uci->get("wireless.wifi".$radio.".dscp_wmm_map");
	$uci->run();
	$dscp = json_decode($uci->result(),true);
	$dscp_val = get_array_val($dscp,"wireless.wifi".$radio.".dscp_wmm_map");
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>WMM 매핑</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var dscp = "<?=$dscp_val?>";
 function clickReset()
 {
// 	document.location.assign( "skb_wlwmm.php#form");
	window.location.reload();
 }
//
//function init()
//{
//	var get_wmm_mode = "2";
//
//	if (parseInt(get_wmm_mode, 10) == 2) {
//		// dscp
//		document.getElementById('dscp_tbl').style.display = '';
//		document.getElementById('1p_tbl').style.display = 'none';
//		document.formWlwmm.wmm_mode.value = 2;
//	}
//	else {
//		//802.1p
//		document.getElementById('dscp_tbl').style.display = 'none';
//		document.getElementById('1p_tbl').style.display = '';
//		document.formWlwmm.wmm_mode.value = 1;
//	}
//}
//
// function wmm_mode_change()
//{
//	var mode = document.formWlwmm.wmm_mode.value;
//
//	if ( mode == 2 ) {
//		// dscp
//		document.getElementById('dscp_tbl').style.display = '';
//		document.getElementById('1p_tbl').style.display = 'none';
//
//	}
//	else {
//		//802.1p
//		document.getElementById('dscp_tbl').style.display = 'none';
//		document.getElementById('1p_tbl').style.display = '';
//	}
//}
var proc = "proc/skb_wlwmm_proc.php";
var form_save = function(){
	var wmm = "";
	for(var i=0; i < 64; i++){
		wmm += " " + $("#pri_"+i).children(":selected").val();
	}
	if(wmm != ""){
		wmm = wmm.substring(1,wmm.length);
	}
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'set_wmm';
	sobj['dscp'] = wmm;
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			if(d == "1"){
				alert("적용되었습니다.");
				return;
			}else{
				alert("적용에 실패했습니다.");
				return;
			}
		}
	});
}
$(document).ready(function(){
	if(dscp != ""){
		var arr = dscp.split(" ");
		console.log(arr);
		for(var i=0; i< arr.length;i++){
			$("#pri_"+i).val(arr[i]);
		}
	}
});
</script>
</head>
<body>
<blockquote>
<b><font size="3" face="arial" color="#3c7A95">WMM(QoS) 매핑</font></b>
<table border="0" width="550" cellspacing="0" cellpadding="0">
<tr><td><font size=2><br>
 DSCP 의 Priority 매핑 값을 보여주는  페이지입니다.
</font></td></tr>
<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<form action="" method="POST" name="formWlwmm">
<!-- 	WMM(QoS) 모드: -->
<!-- 	<select name="wmm_mode" onChange="wmm_mode_change();" > -->
<!-- 		<option value="2" > DSCP -->
<!-- 		<option value="1" > 802.1p -->
<!-- 	</select> -->
	<div id="dscp_tbl">
		<table border="0" width="490" cellspacing="2">
			<tr class='tbl_head' align="center">
				<td width="250">DSCP Number</td>
				<td colspan="8"> Priority</td>
			</tr>
			<?php
				$x = 0;
				for($i=0; $i<= 7; $i++){
					if($i> 0) $x += 1;
			?>
			<tr align="center" class="content" height="20" bgcolor="#DDDDDD">
				<td width="250">DSCP[ <?=$i+($i*7);?> -  <?=$i+(($i+1)*7);?>]</td>
			<?php
					for($j=0; $j<= 7; $j++){
			?>
					<td width="30"><select name="pri_<?=$j+($i*7)+$x;?>" id="pri_<?=$j+($i*7)+$x;?>"><option value="0" selected>0</option><option value="1" >1</option><option value="2" >2</option><option value="3" >3</option><option value="4" >4</option><option value="5" >5</option><option value="6" >6</option><option value="7" >7</option></select></td>
			<?php
					}
			?>
			</tr>
			<?php
				}
			?>
			
		</table>
	</div>

<!-- 	<div id="1p_tbl" style="display:none"> -->
<!-- 		<table border=0 width="490" cellspacing=2> -->
<!-- 		<tr class='tbl_head' align="center"> -->
<!-- 		<td width=250>802.1p</td> -->
<!-- 		<td colspan=8> Priority</td> -->
<!-- 		</tr> -->
<!-- 			<tr align=center class="content" height="20" bgcolor=#DDDDDD> -->
<!-- <td width=250>PRI[0 - 7]</td><td width=30><select name="wmm_1p_0"><option value="0" selected>0<option value="1" >1<option value="2" >2<option value="3" >3<option value="4" >4<option value="5" >5<option value="6" >6<option value="7" >7</select></td> -->
<!-- <td width=30><select name="wmm_1p_1"><option value="0" >0<option value="1" selected>1<option value="2" >2<option value="3" >3<option value="4" >4<option value="5" >5<option value="6" >6<option value="7" >7</select></td> -->
<!-- <td width=30><select name="wmm_1p_2"><option value="0" >0<option value="1" >1<option value="2" selected>2<option value="3" >3<option value="4" >4<option value="5" >5<option value="6" >6<option value="7" >7</select></td> -->
<!-- <td width=30><select name="wmm_1p_3"><option value="0" >0<option value="1" >1<option value="2" >2<option value="3" selected>3<option value="4" >4<option value="5" >5<option value="6" >6<option value="7" >7</select></td> -->
<!-- <td width=30><select name="wmm_1p_4"><option value="0" >0<option value="1" >1<option value="2" >2<option value="3" >3<option value="4" selected>4<option value="5" >5<option value="6" >6<option value="7" >7</select></td> -->
<!-- <td width=30><select name="wmm_1p_5"><option value="0" >0<option value="1" >1<option value="2" >2<option value="3" >3<option value="4" >4<option value="5" selected>5<option value="6" >6<option value="7" >7</select></td> -->
<!-- <td width=30><select name="wmm_1p_6"><option value="0" >0<option value="1" >1<option value="2" >2<option value="3" >3<option value="4" >4<option value="5" >5<option value="6" selected>6<option value="7" >7</select></td> -->
<!-- <td width=30><select name="wmm_1p_7"><option value="0" >0<option value="1" >1<option value="2" >2<option value="3" >3<option value="4" >4<option value="5" >5<option value="6" >6<option value="7" selected>7</select></td> -->
<!-- </tr> -->
<!-- 		</table> -->
<!--   	</div> -->
<p>
  <input type="button" value="저장" name="saveApply" onclick="form_save()">&nbsp;&nbsp;
  <input type="button" value="다시 보기" name="refresh" onclick="clickReset()">&nbsp;&nbsp;
  <input type="button" value=" 닫기 " name="close" onClick="javascript: window.close();"></p>
   <input type="hidden" value="/skb_wlwmm.php" name="submit-url">
</p></tr>
</form>
 <br>


</blockquote>
</body>
</html>
