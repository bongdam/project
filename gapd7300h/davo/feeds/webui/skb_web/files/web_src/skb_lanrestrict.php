<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	$wan_no = dv_session("wan_no");
	$lan1_no = dv_session("lan_no");
	$uci = new uci();
	$uci->mode("get");
	for($i=0; $i < 4; $i++){
		$uci->get("network.fdbptlearnlimit_".($lan1_no+$i));
		$uci->get("network.fdbptlearnexceedcmd_".($lan1_no+$i));
		$uci->get("network.fdbportlearn_".($lan1_no+$i).".port_id");
		$uci->get("network.fdbportlearn_".($lan1_no+$i).".port_cnt");
	}
	$uci->run();
	$get = json_decode($uci->result(),true);
	$lan_restrict = "0";
	$arr_enable = Array(false, false, false, false);
	$arr_info = Array();
	$arr_dis = Array();
	$arr_dis_cnt = Array();
	if(count($get) > 0){
		$lan_restrict = "1";
		for($i=0; $i < 4; $i++){
			if($get["network.fdbptlearnlimit_".($lan1_no+$i).".learn_limit_status"] == "enable"){
				$arr_enable[$i] = true;
				$arr_info[] = $get["network.fdbptlearnlimit_".($lan1_no+$i).".learn_limit_counter"];
			}else{
				$arr_enable[$i] = false;
				$arr_info[] = 4;
			}
			if($get["network.fdbportlearn_".($lan1_no+$i).".port_id"] != ""){
				$arr_dis[] = $get["network.fdbportlearn_".($lan1_no+$i).".port_id"];
				$arr_dis_cnt[] = $get["network.fdbportlearn_".($lan1_no+$i).".port_cnt"];
			}

		}
	}else{
		$arr_info = Array(4,4,4,4);
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
<title>랜 제한 </title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var enable = "<?$lan_restrict?>";
var init = function(){
	
}
function resetForm()
{
	document.location.assign("skb_lanrestrict.php");
}
$(document).ready(function(){
	if(enable == "1"){
		//사용
	}else{
		//비사용
	}
});
</script>
</head>

<body>
<blockquote>
<h2>랜 제한</h2>
<table border="0" width="500" cellspacing="0" cellpadding="0">
	<tr>
		<td><font size="2">각 랜에 접속 가능한 호스트 수를 제한할 수 있는 페이지입니다. </font></td>
	</tr>
	<tr>
		<td><hr size="1" noshade align="top"></td>
	</tr>
</table>
<form action="proc/skb_lanrestrict_proc.php" method="POST" name="formLanRestrict">
<table border="0" width="500" cellspacing="4" cellpadding="0">
<?php
	
	for($i=0; $i < 4; $i++){
		$ck = "";
		$dis = "";
		if($arr_enable[$i] == true){
			$ck = "checked";
		}
		$cnt_val = array_search((string)($lan1_no+$i),$arr_dis);
		if($cnt_val !== false){
			$dis = "disabled";
		}
?>
<tr>
	<td><input type="checkbox" name="lan_restrict_port_enable<?=($i+1)?>" id="lan_restrict_port_enable<?=($i+1)?>" value="<?=($lan1_no+$i)?>" <?=$ck?> <?=$dis?>>LAN<?=($i+1)?>&nbsp;&nbsp;
	<select name="lan_restrict_num<?=($i+1)?>" id="lan_restrict_num<?=($i+1)?>" <?=$dis?>>
	<?php
		for($j=0; $j < 4; $j++){
		$sel = "";
		if($arr_enable[$i] == true){
			if( $arr_info[$i] == ($j+1)){
				$sel = "selected";
			}
		}else{
			if($j == 3){
				$sel = "selected";
			}
		}
		if($dis != ""){
			if(($j+1) == $arr_dis_cnt[$cnt_val]){
				$sel = "selected";
			}
		}
	?>
		<option value="<?=($j+1)?>" <?=$sel?> ><?=($j+1)?></option>
	<?php
		}
	?>
	</select><input type="hidden" value="<?=($lan1_no+$i)?>" name="lan<?=($i+1)?>_no"><?php
		if($dis != ""){
			echo("<input type=\"hidden\" name=\"skip_port".($i+1)."\" id=\"skip_port".($i+1)."\" value=\"1\">");
		}
	?></td>
</tr>
<tr>
	<td>&nbsp;&nbsp;</td>
</tr>
<?
	}
?>
</table>
<br>
<input type="submit" value="적용" name="apply">&nbsp;&nbsp;
<input type="button" value="취소" name="reset" onClick="resetForm();">
<input type="hidden" value="/skb_lanrestrict.php" name="submit-url">
<input type="hidden" value="<?=$lan1_no?>" name="lan1_no">
</form>

</blockquote>
</body>
</html>
