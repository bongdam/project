<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/skb_common.php");
?>
<html>
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta HTTP-equiv="Cache-Control" content="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="Mon, 01 Jan 1990 00:00:01 GMT">
<title>Firmware Update</title>
<style>
.on {display:on}
.off {display:none}
</style>
<script type="text/javascript" src="inc/js/jquery-1.12.4.min.js"></script>
<script type="text/javascript" src="inc/js/common.js"></script>
<script type="text/javascript" src="js/skb_util_gw.js"></script>
<link href="/style.css" rel="stylesheet" type="text/css">
<script>
var MWJ_progBar = 0;
var time=0;
var delay_time=1000;
var loop_num=0;
var usb_update_img_enabled=0;

function show_usb_update_img()
{
  if(usb_update_img_enabled == 0)
  {
	get_by_id("usb_update_img_ln").style.display = "none";
	get_by_id("usb_update_img_nt").style.display = "none";
	get_by_id("usb_update_img_bt").style.display = "none";
	return false;
  }
  else
  {
	get_by_id("usb_update_img_ln").style.display = "";
	get_by_id("usb_update_img_nt").style.display = "";
	get_by_id("usb_update_img_bt").style.display = "";
	return true;
  }
}


function usb_img_upload(F)
{
  if(show_usb_update_img() == false)
  {
	alert("usb update image function is not enabled!");
          return false;
  }

  F.submit();
  show_div(true, "progress_div");
  progress();
}

function progress()
{
  if (loop_num == 20) {
	alert("펌웨어 업그레이드가 실패하였습니다!");
	return false;
  }
  if (time < 1)
  	time = time + 0.20;
	/*time = time + 0.033;*/
  else {
	time = 0;
	loop_num++;
  }
  setTimeout('progress()',delay_time);
  myProgBar.setBar(time);
}


function sendClicked(F)
{
  if(document.upload.binary.value == ""){
      	document.upload.binary.focus();
  	alert('파일명이 비어있습니다!');
    F.send.disabled=false;
  	F.reset.disabled=false;
  	return false;
  }
  F.submit();
  show_div(true, "progress_div");
  progress();
}

function tftpSendClicked(tftp_form)
{
	document.tftpUpload.server.value = trim(document.tftpUpload.server.value);
	document.tftpUpload.file.value = trim(document.tftpUpload.file.value);

	var addr_val = document.tftpUpload.server.value;
	var filepath_val = document.tftpUpload.file.value;

    if(document.tftpUpload.server.value == ""){
        document.tftpUpload.server.focus();
        alert('서버 주소가 비어있습니다!');

        return false;
    }
    if ( IsHtmlComment(addr_val)) {
		alert('Html 주석문을 입력할 수 없습니다.!');
		document.tftpUpload.server.value = document.tftpUpload.server.defaultValue;
		document.tftpUpload.server.focus();

		return false;
  	}
    if(document.tftpUpload.file.value == ""){
        document.tftpUpload.file.focus();
        alert('파일명이 비어있습니다!');

        return false;
    }
	if ( IsHtmlComment(filepath_val)) {
		alert('Html 주석문을 입력할 수 없습니다.!');
		document.tftpUpload.file.value = document.tftpUpload.file.defaultValue;
		document.tftpUpload.file.focus();

		return false;
	}
    document.tftpUpload.server.value = trim(document.tftpUpload.server.value);
    document.tftpUpload.file.value = trim(document.tftpUpload.file.value);

    tftp_form.tftpSend.disabled=true;
    tftp_form.reset.disabled=true;
    tftp_form.submit();

    show_div(true, "progress_div");
    progress();
}

function update_button()
{
	document.tftpUpload.tftpSend.disabled=false;
	document.tftpUpload.reset.disabled=false;
}

</script>

</head>
<BODY onload="show_usb_update_img();">
<blockquote>
<h2>펌웨어 업그레이드</h2>

<form method="post" action="proc/skb_upload_proc.php" enctype="multipart/form-data" name="upload">
<input type="hidden" name="act" id="act" value="upload">
<table border="0" cellspacing="4" width="500">
 <tr><font size=2>
새로운 버전으로 펌웨어를 업그레이드 할 수 있습니다.<br>
업그레이드중에는 장치의 전원을 끄지말고 잠시 기다려 주시기 바랍니다. 시스템 고장의 원인이 될 수 있습니다.
 </tr>
  <tr><hr size=1 noshade align=top></tr>

  <tr>
      <td width="20%"><font size=2><b>파일 선택:</b>&nbsp;&nbsp;&nbsp;&nbsp;</td>
      <td width="80%"><font size=2><input type="file" name="binary" size=20></td>
  </tr>
  </table>
    <p> <input type="button" name="send" value="업로드" onclick="sendClicked(this.form)">&nbsp;&nbsp;
	<input type="reset" value="취소" name="reset">
<!--
	<input type="hidden" value="0x10000" name="writeAddrWebPages">
	<input type="hidden" value="0x20000" name="writeAddrCode">
-->
	<input type="hidden" value="/skb_upload.php" name="submit-url">

    </p>
 </form>

<form method="post" action="proc/skb_upload_proc.php" name="tftpUpload">
<input type="hidden" name="act" id="act" value="tftp">
<input type="hidden" value="/skb_upload.php" name="submit-url">
<table border="0" cellspacing="4" width="500">
    <tr>
        <td width="50%"><font size=2><b>TFTP 원격업그레이드</b>&nbsp;&nbsp;&nbsp;&nbsp;</td>
    </tr>

    <tr>
	    <td><font size=2><b>서버주소</b></td>
	    <td><input type="text" name="server" maxlength="50" style="width:70%;" > </td>
	</tr>

	<tr>
	    <td><font size=2><b>파일명</b></td>
	    <td><input type="text"  name="file" maxlength="50" style="width:70%;" > </td>
	</tr>

  </table>
    <p> <input onclick="tftpSendClicked(this.form)" type="button" value="실행" name="tftpSend">&nbsp;&nbsp;
        <input type="reset" value="취소" name="reset">
    </p>
    <script> update_button(); </script>
</form>

<form  method="post" action="boafrm/formUploadFromUsb" enctype="multipart/form-data" name="usb_upload">
<table border="0" cellspacing="4" width="500">
  <tr><hr size=1 noshade align=top></tr>
 <tr ><font size=2>
 <td id="usb_update_img_nt"  style="display:"  >This page allows you upgrade the  firmware from usb storage device(ex. /tmp/usb/sda1/fw.bin). Please note,
 do not power off the device during the upload because it may crash the system.</td>
 </tr>

  </table>
    <p> <input id="usb_update_img_bt"  style="display:" onclick=usb_img_upload(this.form) type=button value="Upload from usb" name="submit_usb">&nbsp;&nbsp;
    </p>
 </form>

<tr><td colspan=2> <hr  id="usb_update_img_ln"  style="display:" size=1 noshade align=top></td></tr>

 <script type="text/javascript" language="javascript1.2">
		var myProgBar = new progressBar(
			1,         //border thickness
			'#000000', //border colour
			'#ffffff', //background colour
			'#043db2', //bar colour
			300,       //width of bar (excluding border)
			15,        //height of bar (excluding border)
			1          //direction of progress: 1 = right, 2 = down, 3 = left, 4 = up
		);
</script>

<script>

	function click_dual_fw(clickValue)
	{

		if(clickValue)
		{
			document.formDualFirmware.boot_2bank.disabled =false;
		}
		else
		{
 			document.formDualFirmware.boot_2bank.disabled =true;
		}

	}

	function load_dual_fw()
	{
		if(get_by_id("enable_dual_bank").value == 1)
			get_by_id("dualFw").checked = true;
		else
			get_by_id("dualFw").checked = false;

		get_by_id("act_bank").innerHTML = get_by_id("currFwBank").value;
		get_by_id("bak_bank").innerHTML = get_by_id("backFwBank").value;
	}
	function saveChanges(actValue)
	{
		get_by_id("active").value = actValue;
	}
</script>

<form action=/boafrm/formDualFirmware method=POST name="formDualFirmware">
<input type="hidden" value="/skb_upload.php" name="submit-url">
<input type="hidden" value="1" name="enable_dual_bank" id="enable_dual_bank">
<input type="hidden" value="1" name="currFwBank" id="currFwBank">
<input type="hidden" value="2" name="backFwBank" id="backFwBank">
<input type="hidden" value="no" name="active" id="active">
<input type="hidden" name="model_name" id="model_name" value="<?=DEF_MODEL?>">
<input type="hidden" name="ant_no" id="ant_no" value="<?=DEF_ANT?>">
<!--
<table border="0" >
	<tr><td colspan=2><font size=2><b>
	   	<input type="checkbox" id="dualFw" name="dualFw" value="ON">&nbsp;&nbsp;Enable Dual Firmware</b><br>
	    </td>
	</tr>

	<tr>
		<td width="10%"></td>
		<td><font size=2>Active Bank: <SPAN id=act_bank></SPAN></td>
	</tr>
	<tr>
		<td width="10%"></td>
		<td><font size=2>Backup Bank: <SPAN id=bak_bank></SPAN></td>
	</tr>



</table>
<p>
<input type="submit" value="Apply Changes" name="save" onClick="return saveChanges('save')">&nbsp;&nbsp;
<input type="submit" id="boot_2bank" name="boot_2bank" value="Reboot Form Backup Bank Now" onClick="return saveChanges('reboot')">
<script>
	load_dual_fw();
	click_dual_fw(1*get_by_id("enable_dual_bank").value);


</script>

-->
</form>


 </blockquote>
</body>
</html>
