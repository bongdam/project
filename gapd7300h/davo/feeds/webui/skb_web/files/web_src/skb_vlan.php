<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
	check_admin($isAdmin );
	$wan_no = dv_session("wan_no");
	$lan1_no = dv_session("lan_no");
	$uci = new uci();
	$uci->mode("get");
	$uci->run();
	$vlan_data = $uci->result();
	if($vlan_data == ""){
		$vlan_data = "null";
	}
	$uci->close();
	$uci = new uci();
	$uci->mode("get");
	for($i=1; $i <= 16; $i++){
		$uci->get("network.switch_vlan_".$i);
	}
	$uci->run();
	$vlan = json_encode(json_decode($uci->result(),true));
	for($i=0; $i < 6; $i++){
		$uci->get("network.switch_port_".$i);
	}
	$uci->run();
	$vlan_port = json_encode(json_decode($uci->result(),true));
	$uci->close();
//	print_r($vlan);
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>VLAN 설정</title>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"> </script>
<link href="style.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
//var un_list = <?=$un_list?>;
//var un_plist = <?=$un_plist?>;
//var unnamed_list = <?=$unnamed_list?>;
//var port_data = <?=$port_data?>;
//var vlan_data = <?=$vlan_data ?>;
var wan_port = <?=$wan_no?>;
var first_lan_port = <?=$lan1_no?>;
var vinfo = <?=$vlan?>;
var vport = <?=$vlan_port?>;
function form_onoff(index)
{
	var check 	= eval('document.vlan_form.use'+index);
	var vid 	= eval('document.vlan_form.vid'+index);
	var port0 	= eval('document.vlan_form.vlan'+index+'_port0');
	var port1 	= eval('document.vlan_form.vlan'+index+'_port1');
	var port2 	= eval('document.vlan_form.vlan'+index+'_port2');
	var port3 	= eval('document.vlan_form.vlan'+index+'_port3');
	var port4 	= eval('document.vlan_form.vlan'+index+'_port4');

	if(check.checked == true)
	{
		formEnable(vid);
		formEnable(port0);
		formEnable(port1);
		formEnable(port2);
		formEnable(port3);
		formEnable(port4);
	}
	else
	{
		formDisable(vid);
		formDisable(port0);
		formDisable(port1);
		formDisable(port2);
		formDisable(port3);
		formDisable(port4);
	}
}

function form_autoset(index, addcount)
{
	var check 	= eval('document.vlan_form.use'+index);
	var vid 	= eval('document.vlan_form.vid'+index);
	var port0 	= eval('document.vlan_form.vlan'+index+'_port0');
	var port1 	= eval('document.vlan_form.vlan'+index+'_port1');
	var port2 	= eval('document.vlan_form.vlan'+index+'_port2');
	var port3 	= eval('document.vlan_form.vlan'+index+'_port3');
	var port4 	= eval('document.vlan_form.vlan'+index+'_port4');

	if(check.checked == true)
	{
		formEnable(vid);
		formEnable(port0);
		formEnable(port1);
		formEnable(port2);
		formEnable(port3);
		formEnable(port4);

		if (document.vlan_form.auto_vid.value != '')
			vid.value = parseInt(document.vlan_form.auto_vid.value) + addcount;
		port0.selectedIndex = document.vlan_form.auto_port0.selectedIndex;
		port1.selectedIndex = document.vlan_form.auto_port1.selectedIndex;
		port2.selectedIndex = document.vlan_form.auto_port2.selectedIndex;
		port3.selectedIndex = document.vlan_form.auto_port3.selectedIndex;
		port4.selectedIndex = document.vlan_form.auto_port4.selectedIndex;
	}
}

function auto_apply()
{
	var count;

	for (var i = 0; i < document.vlan_form.elements.length; i++){
		var e = document.vlan_form.elements[i];

		if( e.type == 'checkbox')
		{
			e.checked = true;
		}
	}
	if ( document.vlan_form.auto_count.value != "")
		count = parseInt(document.vlan_form.auto_count.value);
	else
		count = 1;
	for(var i=1; i <= 16; i++){
		var d = i-1;
		form_autoset(i, d*count);
	}
}

function select_all()
{
	for (var i = 0; i < document.vlan_form.elements.length; i++){
		var e = document.vlan_form.elements[i];

		if(e.type == 'checkbox')
		{
			e.checked = true;
		}
	}

	for(var i=1; i <= 16; i++){
		form_onoff(i);
	}

}

function unselect_all()
{
	for (var i = 0; i < document.vlan_form.elements.length; i++){
		var e = document.vlan_form.elements[i];

		if(e.type == 'checkbox')
		{
			e.checked = false;
		}
	}
	for(var i=1; i <= 16; i++){
		form_onoff(i);
	}
}

function check_value()
{
	var flag=0;
	var vid,num,use;
	$("#wan_port_no").val(wan_port);
	$("#lan_port_no").val(first_lan_port);

	if(document.vlan_form.wan_pvid.selectedIndex != 0){
		use = eval('document.vlan_form.use' + (document.vlan_form.wan_pvid.selectedIndex ));
		if(use.checked == false){
			alert("VLAN " + document.vlan_form.wan_pvid.selectedIndex + " 이(가) 비활성화되어 있습니다.");
			flag++;
			return false;
		}
		else{
			vid = eval('document.vlan_form.vid' + (document.vlan_form.wan_pvid.selectedIndex));
			if(vid.value == ""){
				alert("VLAN " + document.vlan_form.wan_pvid.selectedIndex + " 의 VLAN ID가 올바르지 않습니다.");
				flag++;
				return false;
			}
		}
		$("#pvid_wan").val(vid.value);
	}
	for (var i=1; i < 5; i++){
		var pvid = eval('document.vlan_form.lan'+i+'_pvid');
		if(pvid.selectedIndex != 0){
			use = eval('document.vlan_form.use' + (pvid.selectedIndex ));
			if(use.checked == false){
				alert("VLAN " + pvid.selectedIndex + " 이(가) 비활성화되어 있습니다.");
				flag++;
				return false;
			}
			else{
				vid = eval('document.vlan_form.vid' + (pvid.selectedIndex ));
				if(vid.value == ""){
					alert("VLAN " + pvid.selectedIndex + " 의 VLAN ID가 올바르지 않습니다.");
					flag++;
					return false;
				}
			}
			$("#pvid_lan"+i).val(vid.value);
		}
	}
	for (var i=1; i <= 16; i++){
		use = eval('document.vlan_form.use'+i);
		if ( use.checked == true ){
			vid = eval('document.vlan_form.vid'+i);
			num = parseInt(vid.value);
			if (vid.value == ""){
				flag++;
				alert("VLAN ID가 없습니다...");
				return false;
			}
			else if ((num < 1) || (num > 4094)){
				flag++;
				alert("VLAN ID가 올바르지 않습니다.\nVLAN ID는 1부터 4094 사이여야 합니다.");
				return false;
			}
			else if ((num == 1) || (num == 2) || (num == 3)){
				flag++;
				alert("VLAN ID 1, 2, 3번은 설정이 불가합니다.");
				return false;
			}
			else {
				for (var j=i+1; j < 16; j++){
					var use2 = eval('document.vlan_form.use'+j);
					var vid2 = eval('document.vlan_form.vid'+j);
					if(use2.checked == true && vid.value == vid2.value){
						flag++;
						alert("VLAN ID 동일합니다..... [" + vid2.value + "]");
						return false;
					}
				}
			}
		}
	}
	for (var i=1; i <= 16; i++){
		//wan "vlan"+i+"_port4"
		//"vlan"+i+"_port0"
		var temp = "";
		for (var j=0; j < 4 ; j++)
		{
			if($("#vlan"+i+"_port"+j).val() != ""){
				temp += " " + $("#vlan"+i+"_port"+j).val();
			}
		}
		if(temp != ""){
			temp = temp.substring(1,temp.length);
		}
		if($("#vlan"+i+"_port4").val() != ""){
			if(first_lan_port < wan_port){
				temp = temp + " " + $("#vlan"+i+"_port4").val();
			}else{
				temp = $("#vlan"+i+"_port4").val() + " " + temp;
			}
		}
		$("#vlan_ports"+i).val(temp);
	}
	if(!flag)
		vlan_form.submit();
}
function frmOnload()
{
	var i;
	var vLan_val;
	var vlan_port;
	var vlan_tag;
	var check;
	var vid;
	var port0;
	var port1;
	var port2;
	var port3;
	var port4;

	document.vlan_form.wan_pvid.selectedIndex = 0;
	document.vlan_form.lan1_pvid.selectedIndex = 0;
	document.vlan_form.lan2_pvid.selectedIndex = 0;
	document.vlan_form.lan3_pvid.selectedIndex = 0;
	document.vlan_form.lan4_pvid.selectedIndex = 0;

//VLAN_0
	for (var i = 1; i <= 16  ; i++ )
	{
		check = eval('document.vlan_form.use'+i);
		vid 	= eval('document.vlan_form.vid'+i);
		port0 	= eval('document.vlan_form.vlan'+i+'_port0');
		port1 	= eval('document.vlan_form.vlan'+i+'_port1');
		port2 	= eval('document.vlan_form.vlan'+i+'_port2');
		port3 	= eval('document.vlan_form.vlan'+i+'_port3');
		port4 	= eval('document.vlan_form.vlan'+i+'_port4');
//		console.log(un_list[i])
//		console.log(get_obj_val(vinfo,"network.switch_vlan_"+i+".vid"));
		if(get_obj_val(vinfo,"network.switch_vlan_"+i+".vid") != ""){
			vLan_val = 1;
		}else{
			vLan_val = 0;
		}
		if (vLan_val == 0) {
			check.checked = false;
			port0.selectedIndex = 0;
			port1.selectedIndex = 0;
			port2.selectedIndex = 0;
			port3.selectedIndex = 0;
			port4.selectedIndex = 0;
		} else {
			check.checked = false;
			port0.selectedIndex = 0;
			port1.selectedIndex = 0;
			port2.selectedIndex = 0;
			port3.selectedIndex = 0;
			port4.selectedIndex = 0;
			vlan_tag = parseInt(0);
			
			vLan_val = get_obj_val(vinfo,"network.switch_vlan_"+i+".vid");
			vlan_port = get_obj_val(vinfo,"network.switch_vlan_"+i+".ports");
			check.checked = true;
			vid.value = vLan_val;
			if(vlan_port != "" && vlan_port != undefined){
				var arr_vlan_port = vlan_port.split(" ");
				
				$("#vlan"+i+"_port0,#vlan"+i+"_port1,#vlan"+i+"_port2,#vlan"+i+"_port3,#vlan"+i+"_port4").children("option").eq(0).prop("selected",true);
				for (var j =0; j < arr_vlan_port.length ; j++ ){
					var tmpP = arr_vlan_port[j].replace(/[^0-9]/,'');
					var tmpPT = arr_vlan_port[j].replace(/[0-9]/,'');
					if(wan_port == tmpP){
						if(tmpPT != ""){
							
							$("#vlan"+i+"_port4").children("option").eq(2).prop("selected",true);
						}else{
							$("#vlan"+i+"_port4").children("option").eq(1).prop("selected",true);
						}
					}else{
						if(tmpPT != ""){
							$("#vlan"+i+"_port"+(tmpP-first_lan_port)).children("option").eq(2).prop("selected",true);
						}else{
							$("#vlan"+i+"_port"+(tmpP-first_lan_port)).children("option").eq(1).prop("selected",true);
						}
					}
				}
			}
		}
		form_onoff(i);
	}
	for (var i=1 ;i <= 16 ; i++ )
	{
		if( $("#use"+i).prop("checked") == true){
			var tmpvid = $("#vid"+i).val();
//			console.log(tmpvid);
			find_vlan_id(tmpvid, i);
		}
	}
}
function find_vlan_id(vid_, i_){
	var port = "";
	for(i=1; i <= 5; i++){
		if(get_obj_val(vport,"network.switch_port_"+i+".pvid") == vid_){
			port = get_obj_val(vport,"network.switch_port_"+i+".port");
			if(wan_port == port){
				document.vlan_form.wan_pvid.selectedIndex = i_;
			}else{
				$("#lan"+(port-first_lan_port+ 1)+ "_pvid").children("option").eq(i_).prop("selected",true);
			}
		}
	}
}
$(document).ready(function(){
	frmOnload();
});


</script>
</head>
<body>
<blockquote>
<form action="proc/skb_vlan_proc.php" method="POST" name="vlan_form" id="vlan_form">
<input type="hidden" value="/skb_vlan.php" name="submit-url">
<input type="hidden" name="wan_port_no" id="wan_port_no" value="">
<input type="hidden" name="lan_port_no" id="lan_port_no" value="">
<input type="hidden" name="pvid_wan" id="pvid_wan" value="">
<input type="hidden" name="pvid_lan1" id="pvid_lan1" value="">
<input type="hidden" name="pvid_lan2" id="pvid_lan2" value="">
<input type="hidden" name="pvid_lan3" id="pvid_lan3" value="">
<input type="hidden" name="pvid_lan4" id="pvid_lan4" value="">

<?php
for($i = 1; $i <= 16 ; $i++){
?>
<input type="hidden" name="vlan_ports<?=$i?>" id="vlan_ports<?=$i?>" value="">
<?php
}
?>
<h2>VLAN 설정</h2>
	<table border=0 width="550" cellspacing=4 cellpadding=0>
	<tr><td><font size=2>
		VLAN을 설정하여 가상 네트워크를 구성할 수 있는 페이지입니다.
	</font></td></tr>
	<tr><td><hr size="1" align="top" noshade="noshade"></td></tr>
</table>

<table>
	<tr><td colspan="5" align="left" ><font size="2"><b>PVID 설정</b></td></tr>
	<tr class="tbl_head">
	  	<td height="30" align="center" width="20%"><font size="2"><b>WAN</b></font></td>
  		<td align="center" width="20%" ><font size="2"><b>LAN1</b></font></td>
  		<td align="center" width="20%" ><font size="2"><b>LAN2</b></font></td>
		<td align="center" width="20%" ><font size="2"><b>LAN3</b></font></td>
		<td align="center" width="20%" ><font size="2"><b>LAN4</b></font></td>
  	</tr>
	<tr>
	<td class=''>
		<select name="wan_pvid" id="wan_pvid">
			<option value="0"> 사용안함
			<option value="1"> VLAN1
			<option value="2"> VLAN2
			<option value="3"> VLAN3
			<option value="4"> VLAN4
			<option value="5"> VLAN5
			<option value="6"> VLAN6
			<option value="7"> VLAN7
			<option value="8"> VLAN8
			<option value="9"> VLAN9
			<option value="10"> VLAN10
			<option value="11"> VLAN11
			<option value="12"> VLAN12
			<option value="13"> VLAN13
			<option value="14"> VLAN14
			<option value="15"> VLAN15
			<option value="16"> VLAN16
		</select>
	</td>
	<td>
		<select name="lan1_pvid" id="lan1_pvid">
			<option value="0" > 사용안함
			<option value="1"  > VLAN1
			<option value="2"  > VLAN2
			<option value="3"  > VLAN3
			<option value="4"  > VLAN4
			<option value="5"  > VLAN5
			<option value="6"  > VLAN6
			<option value="7"  > VLAN7
			<option value="8"  > VLAN8
			<option value="9"  > VLAN9
			<option value="10"  > VLAN10
			<option value="11"  > VLAN11
			<option value="12"  > VLAN12
			<option value="13"  > VLAN13
			<option value="14"  > VLAN14
			<option value="15"  > VLAN15
			<option value="16"  > VLAN16
		</select>
	</td>
	<td>
		<select name="lan2_pvid" id="lan2_pvid">
			<option value="0"> 사용안함
			<option value="1"> VLAN1
			<option value="2"> VLAN2
			<option value="3"> VLAN3
			<option value="4"> VLAN4
			<option value="5"> VLAN5
			<option value="6"> VLAN6
			<option value="7"> VLAN7
			<option value="8"> VLAN8
			<option value="9"> VLAN9
			<option value="10"> VLAN10
			<option value="11"> VLAN11
			<option value="12"> VLAN12
			<option value="13"> VLAN13
			<option value="14"> VLAN14
			<option value="15"> VLAN15
			<option value="16"> VLAN16
		</select>
	</td>
	<td>
		<select name="lan3_pvid" id="lan3_pvid">
			<option value="0"> 사용안함
			<option value="1"> VLAN1
			<option value="2"> VLAN2
			<option value="3"> VLAN3
			<option value="4"> VLAN4
			<option value="5"> VLAN5
			<option value="6"> VLAN6
			<option value="7"> VLAN7
			<option value="8"> VLAN8
			<option value="9"> VLAN9
			<option value="10"> VLAN10
			<option value="11"> VLAN11
			<option value="12"> VLAN12
			<option value="13"> VLAN13
			<option value="14"> VLAN14
			<option value="15"> VLAN15
			<option value="16"> VLAN16
		</select>
	</td>
	<td>
		<select name="lan4_pvid" id="lan4_pvid">
			<option value="0"> 사용안함
			<option value="1"> VLAN1
			<option value="2"> VLAN2
			<option value="3"> VLAN3
			<option value="4"> VLAN4
			<option value="5"> VLAN5
			<option value="6"> VLAN6
			<option value="7"> VLAN7
			<option value="8"> VLAN8
			<option value="9"> VLAN9
			<option value="10"> VLAN10
			<option value="11"> VLAN11
			<option value="12"> VLAN12
			<option value="13"> VLAN13
			<option value="14"> VLAN14
			<option value="15"> VLAN15
			<option value="16"> VLAN16
		</select>
	</td>
	</tr>
</table>

<br>
<br>
	<table  border=0>
	<tr><td colspan="8" align="left"><font size="2"><b>VLAN 구성</b></font></td>
	</tr>
	<tr height="30" align="center">
		<td colspan="8"><font size="2"><b>멤버 포트</b><font size="2"></font></td>
	</tr>
	<tr class="tbl_head" align="center">
		<td>*</td>
		<td>사용</td>
		<td>VLAN ID</td>
		<td>WAN</td>
		<td>LAN1</td>
		<td>LAN2</td>
		<td>LAN3</td>
		<td>LAN4</td>
	</tr>
	<?php
	for($i = 1; $i <= 16 ; $i++){
	?>
	<tr>
		<td align="center"><?=$i?></td>
		<td align="center">
			<input type="checkbox" name="use<?=$i?>" id="use<?=$i?>" value="1" onclick="form_onoff(<?=$i?>);" >
		</td>
		<td align="center">
			<input type="text" name="vid<?=$i?>" id="vid<?=$i?>" size="10" maxlength="4" style="ime-mode:disabled;" value=''>
		</td>
		<td align="center">
			<select name="vlan<?=$i?>_port4" id="vlan<?=$i?>_port4">
				<option value="">사용안함
				<option value="<?=$wan_no?>">태그없음
				<option value="<?=$wan_no?>t">태그사용
			</select>
		</td>
		<td align="center">
			<select name="vlan<?=$i?>_port0" id="vlan<?=$i?>_port0">
				<option value="">사용안함
				<option value="<?=$lan1_no?>">태그없음
				<option value="<?=$lan1_no?>t">태그사용
			</select>
		</td>
		<td align="center">
			<select name="vlan<?=$i?>_port1" id="vlan<?=$i?>_port1">
				<option value="">사용안함
				<option value="<?=$lan1_no+1?>">태그없음
				<option value="<?=$lan1_no+1?>t">태그사용
			</select>
		</td>
		<td align="center">
			<select name="vlan<?=$i?>_port2" id="vlan<?=$i?>_port2">
				<option value="">사용안함
				<option value="<?=$lan1_no+2?>">태그없음
				<option value="<?=$lan1_no+2?>t">태그사용
			</select>
		</td>
		<td align="center">
			<select name="vlan<?=$i?>_port3" id="vlan<?=$i?>_port3">
				<option value="">사용안함
				<option value="<?=$lan1_no+3?>">태그없음
				<option value="<?=$lan1_no+3?>t">태그사용
			</select>
		</td>
	</tr>
	<?php
	}
	?>

	<tr>
		<td><input type="button" name="auto_conf" value="자동" onClick="auto_apply();"></td>
		<td align="center">	<input type="text" name="auto_count" size="1" maxlength="4" value=""></td>
		<td align="center">	<input type="text" name="auto_vid" size="10" maxlength="4" value=""> </td>
		<td align="center">
			<select name="auto_port4">
				<option value="">사용안함
				<option value="<?=$wan_no?>">태그없음
				<option value="<?=$wan_no?>t">태그사용
			</select>
		</td>
		<td align="center">
			<select name="auto_port0">
				<option value="">사용안함
				<option value="<?=$lan1_no?>">태그없음
				<option value="<?=$lan1_no?>t">태그사용
			</select>
		</td>
		<td align="center">
			<select name="auto_port1">
				<option value="">사용안함
				<option value="<?=$lan1_no+1?>">태그없음
				<option value="<?=$lan1_no+1?>t">태그사용
			</select>
		</td>
		<td align="center">
			<select name="auto_port2">
				<option value="">사용안함
				<option value="<?=$lan1_no+2?>">태그없음
				<option value="<?=$lan1_no+2?>t">태그사용
			</select>
		</td>
		<td align="center">
			<select name="auto_port3">
				<option value="">사용안함
				<option value="<?=$lan1_no+3?>">태그없음
				<option value="<?=$lan1_no+3?>t">태그사용
			</select>
		</td>
	</tr>
</table>
<br>&nbsp;
<input type="button" value="적용" onClick="check_value();">&nbsp;&nbsp;
<input type="button" value="전체선택" onClick="select_all();">&nbsp;&nbsp;
<input type="button" value="전체선택 해제" onClick="unselect_all();">&nbsp;&nbsp;
<input type="button" value="취소" name="reset" onclick="frmOnload()">&nbsp;
</form>
<br>
<br>
<br>
</blockquote>
</body>
</html>
