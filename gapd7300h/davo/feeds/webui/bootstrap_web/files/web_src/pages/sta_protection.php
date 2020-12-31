<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/func/qca_common.php");
	$syscall = new dvcmd();
	$syscall->add("sta_list");
	$syscall->run();
	$syscall->result();
	$syscall->close();
	$sta_list = "";
	if(file_exists("/tmp/station.txt") == true){
		$handle = fopen("/tmp/station.txt", "r");
		$contents = fread($handle, filesize("/tmp/station.txt"));
		fclose($handle);
		$sta_list = explode("\n",rtrim($contents));
	}
	
//	print_r($sta_list);
//	echo "<br>";
	$sta = array();
	for($i=0 ; $i < count($sta_list); $i++){
		if(preg_match("/^[\s+]{0,}\[\s+(\S+)\s+([\w+\:]{6,})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+[\s+\S+]{0,}\]$/",$sta_list[$i],$d) == true) {
			array_push($sta,$d[2]);
		}
	}
	$app = dv_session("child_guard_set") ? dv_session("child_guard_set") : "";
?>
<!DOCTYPE html>
<html lang="en">

<head>

	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="description" content="">
	<meta name="author" content="">
<?=cr_header();?>
	<script type="text/javascript" src="/inc/js/spin.min.js"></script>
	<script type="text/javascript" src="/inc/js/jquery.spin.js"></script>
</head>

<body>
<?=cr_lang();?>
	<div id="wrapper">
		<?=cr_menu();?>
		<!-- Page Content -->
		<div id="page-wrapper">
			<div class="container-fluid">
				<div class="row">
					<div class="col-lg-12">
						<h1 class="page-header">무선접속 제한 서비스</h1>
						<h5>무선접속 제한 서비스 설정을 할 수 있는 페이지입니다.</h5>
						<h5 style="color:red;">* 무선접속차단시간에는 WiFi를 사용할수 없으며 스마트폰의 LTE/3G로 전환 시 데이터소진이 될수 있음에 유의</h5>
					</div>
				</div>
				<div class="row">
					<div class="panel panel-default">
						<div class="panel-heading">
							무선접속 제한 서비스
						</div>
						<!-- /.panel-heading -->
						<div class="panel-body">
					
							<form role="form">
								<div class="form-group">
									<label>단말이름</label>
									<input type="text" name="sta_name" id="sta_name" value="" class="form-control" maxlength="20">
								</div>
								<div class="form-group">
									<label>단말주소(MAC)</label><br>
									<span id="mac_area"></span>
								</div>
								<div class="form-group">
									<label>요일</label><br>
									<label class="checkbox-inline">
										<input type="checkbox" name="week" id="week0" value="1" onchange="sel_week();">일
									</label>
									<label class="checkbox-inline">
										<input type="checkbox" name="week" id="week1" value="1" onchange="sel_week();">월
									</label>
									<label class="checkbox-inline">
										<input type="checkbox" name="week" id="week2" value="1" onchange="sel_week();">화
									</label>
									<label class="checkbox-inline">
										<input type="checkbox" name="week" id="week3" value="1" onchange="sel_week();">수
									</label>
									<label class="checkbox-inline">
										<input type="checkbox" name="week" id="week4" value="1" onchange="sel_week();">목
									</label>
									<label class="checkbox-inline">
										<input type="checkbox" name="week" id="week5" value="1" onchange="sel_week();">금
									</label>
									<label class="checkbox-inline">
										<input type="checkbox" name="week" id="week6" value="1" onchange="sel_week();">토
									</label>
									<label class="checkbox-inline">
										<input type="checkbox" name="all_week" id="all_week" value="1" onchange="sel_all_week();">전체
									</label>
								</div>
								<div class="form-group">
									<label>허용/차단</label><br>
									<label class="radio-inline">
										<input type="radio" name="rule1" id="rule1" value="1"> 허용
									</label>
									<label class="radio-inline">
										<input type="radio" name="rule0" id="rule0" value="0" checked> 차단
									</label>
								</div>
								<div class="form-group form-inline">
									<label>시간</label><br>
									<label><select name="start_time" id="start_time" class="form-control col-md-2">
										<option value="0">0</option>
									</select>시&nbsp;~&nbsp;</label><label><select name="end_time" id="end_time" class="form-control col-md-2">
										<option value="0">0</option>
									</select>시</label>
								</div>
								<input type="button" value="추가" name="btn_apply" onclick="form_add();" class="btn btn-default"> &nbsp;<input type="button" value="적용" name="btn_apply" id="btn_apply" onclick="form_apply();" class="btn btn-default">
							</form>
						</div>
					</div>

				</div>
				<br>
				<div class="row">
					<div class="col-lg-12">
						<div class="table-responsive">
							<table class="table table-striped">
								<thead>
									<tr>
										<th>No</th>
										<th>단말이름</th>
										<th>단말주소(MAC)</th>
										<th>요일(시간)</th>
										<th>허용/차단</th>
										<th>선택</th>
									</tr>
								</thead>
								<tbody id="tbdy" style="background-color:#ddd;"></tbody>
							</table>
						</div>
						<input type="button" value="삭제" name="btn_apply" onclick="form_del();" class="btn btn-default">
						<input type="button" value="전체삭제" name="btn_apply" onclick="form_all_del();" class="btn btn-default">
						<input type="hidden" value="/skb_sta_protection.php" name="submit-url"><br><br>
						<!-- /.table-responsive -->
					</div>
				</div>
				<!-- /.row -->
			</div>
			<!-- /.container-fluid -->
		</div>
		<!-- /#page-wrapper -->

	</div>
	<!-- /#wrapper -->

<?=cr_footer()?>
<script type="text/javascript">
var proc = "/proc/skb_sta_protection_proc.php";
var sta = <?=array_to_json($sta)?>;
var data = new Array();
var change_select = function(obj_){
	var objname = obj_.name;
	var objid = obj_.id;
	var obj = $(obj_);
	if(obj.children(":selected").val() == ""){
		var tempVal = "<input type=\"text\" name=\""+objname+"\" id=\""+objid+"\" class=\"form-control\" value=\""+obj.attr("preval")+"\" maxlength=\"17\">";
		$(tempVal).replaceAll(obj);
	}else{
		obj.attr("preval",obj.children(":selected").val());
	}
}
var get_rule = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'get_rule';
	sobj['data'] = data;
//		alert(JSON.stringify(sobj));
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"json",
		"type":"POST",
		success:function(d){
			if(d != null){
				data = new Array();
				var tmp = new Object();
				for (var i=0; i < Object.keys(d["child_guard"]).length ; i++ )
				{
					var t = d["child_guard"]["child_guard_"+(i+1)];
					tmp = new Object();
					tmp["name"] = t["name"];
					tmp["mac"] = t["mac"];
					tmp["rule"] = t["mode"];
					var wek = new Array(t["sun"],t["mon"],t["tue"],t["wed"],t["thu"],t["fri"],t["sat"]);
					tmp["week"] = wek;
					tmp["start_time"] = t["start_time"];
					tmp["end_time"] = t["end_time"];
					data.push(tmp);
				}
				create_table();
			}
		}
	});
}
var form_add = function(){
	var sta_name = $("#sta_name").val();
	var sta_mac = $("#sta_mac").val();
	var sta_rule = $("#rule1").prop("checked") == true ? "1" : "0";
	var sta_week = new Array();
	var week_ck = false;
	var start_time = parseInt($("#start_time").children(":selected").val(),10);
	var end_time = parseInt($("#end_time").children(":selected").val(),10);
	var time_ck = true;
	var datearr = new Array();
	if(data.length >= 60){
		alert("최대 60개까지 등록가능합니다.");
		return;
	}
	if(sta_name == ""){
		alert("단말 이름을 입력해주세요.");
		return;
	}
	if(!check_xss(sta_name)){
		alert(xss_err_msg);
		$("#sta_name").focus();
		return;
	}
	sta_name = XSSfilter(sta_name);
	if(sta_name == ""){
		alert("단말주소(MAC)을 입력해주세요.");
		return;
	}
	if(validation_mac(sta_mac) == false){
		alert("단말주소(MAC)이 올바르게 입력해주세요.");
		return;
	}
	for (var i=0; i < 7 ; i++ )
	{
		if($("#week"+i).prop("checked") == true){
			sta_week.push("1");
			week_ck = true;
		}else{
			sta_week.push("0");
		}
	}
	if(week_ck == false){
		alert("요일을 선택해주세요.");
		return;
	}
	if(start_time == "0" &&  end_time == "0"){
		alert("시작시간과 끝시간을 0시로 입력 할 수 없습니다.");
		return;
	}
	for (var i=0; i < 7 ; i++ )
	{
		datearr[i] = new Array();
		for (var j =0; j <= 24 ; j++ )
		{
			datearr[i][j] = 0;
		}
	}
	for (var i=0; i < data.length ; i++ )
	{
		if(sta_mac == data[i].mac){
			for(var j=0; j < data[i].week.length; j++){
				if(data[i].week[j] == "1"){
					if(parseInt(data[i].start_time,10) < parseInt(data[i].end_time,10)){
						//시작이 작음
						for(var x=0; x <= 24; x++){
							if(parseInt(data[i].start_time,10) <= x && parseInt(data[i].end_time,10) > x){
								datearr[j][x] = 1;
							}
						}
					}else{
						//시작이 큼
						for(var x=0; x < parseInt(data[i].end_time,10); x++){
							datearr[j][x] = 1;
						}
						for(var x=parseInt(data[i].start_time,10); x <= 24; x++){
							datearr[j][x] = 1;
						}
					}
				}
			}
		}
	}
	var cache_date = new Array();
	for (var i=0; i < 7 ; i++ )
	{
		cache_date[i] = new Array();
		for (var j =0; j <= 24 ; j++ )
		{
			cache_date[i][j] = 0;
		}
	}
	for (var i=0; i < sta_week.length ; i++ )
	{
		if(sta_week[i] == "1"){
			if(start_time < end_time){
				for(var x=0; x <= 24; x++){
					if(start_time <= x && end_time > x){
//						console.log('sdfsfsf',x);
						cache_date[i][x] = 1;
					}
				}
			}else{
				for(var x=0; x < end_time; x++){
					cache_date[i][x] = 1;
				}
				for(var x=start_time; x <= 24; x++){
					cache_date[i][x] = 1;
				}
			}
		}
	}
	for (var i=0; i < 7 ; i++ )
	{
		for (var j =0; j <= 24 ; j++ )
		{
			if(datearr[i][j] == "1" && cache_date[i][j] == "1"){
				time_ck = false;
			}
		}
	}
	if(time_ck == false){
		alert("중복된 일정이 존재합니다.");
		return;
	}
	var sta = new Object();
	sta["name"] = sta_name;
	sta["mac"] = sta_mac;
	sta["rule"] = sta_rule;
	sta['week'] = sta_week;
	sta['start_time'] = start_time;
	sta['end_time'] = end_time;
	data.push(sta);
	create_table();
	form_save();
	$("#sta_name").val("");
	$("#sta_mac").val("");
	$("#rule0").prop("checked",true);
	$("#start_time").val("0");
	$("#end_time").val("0");
	$("[name='week']").prop("checked",false);
	$("#btn_apply").show();
}
var convert_date = function(arr_){
	var rtn = "";
	if(arr_[0] == "1"){
		rtn += ",일";
	}
	if(arr_[1] == "1"){
		rtn += ",월";
	}
	if(arr_[2] == "1"){
		rtn += ",화";
	}
	if(arr_[3] == "1"){
		rtn += ",수";
	}
	if(arr_[4] == "1"){
		rtn += ",목";
	}
	if(arr_[5] == "1"){
		rtn += ",금";
	}
	if(arr_[6] == "1"){
		rtn += ",토";
	}
	rtn = rtn.substring(1,rtn.length);
	return rtn;
}
var convert_mode = function(val_){
	var rtn = "";
	if(val_ == "1"){
		rtn = "허용";
	}else{
		rtn = "차단";
	}
	return rtn;
}
var create_table = function(){
	var null_val = "<tr><td></td><td></td><td></td><td></td><td></td><td><input type=\"checkbox\" name=\"\" id=\"\" value=\"\"></td></tr>";
	var tempVal = "";
	$("#tbdy").children().remove();
	if(data.length > 0){
		for (var i=0; i < data.length ; i++ )
		{
			tempVal += "<tr>\n";
			tempVal += "\t<td>"+(i+1)+"</td>\n";
			tempVal += "\t<td>"+data[i]["name"]+"</td>\n";
			tempVal += "\t<td>"+data[i]["mac"]+"</td>\n";
			tempVal += "\t<td>"+convert_date(data[i]["week"])+" &nbsp;&nbsp;&nbsp;"+data[i]["start_time"]+"시 - "+data[i]["end_time"]+"시</td>\n";
			tempVal += "\t<td>"+convert_mode(data[i]["rule"])+"</td>\n";
			tempVal += "\t<td><input type=\"checkbox\" name=\"sta_del\" id=\"sta_del"+i+"\" value=\""+i+"\" seq=\""+i+"\"></td>\n";
			tempVal += "</tr>\n";
		}
		$("#tbdy").append(tempVal);
	}else{
		$("#tbdy").append(null_val);
	}
}
var form_save = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'add_rule';
	if(data.length > 0){
		sobj['data'] = data;
	}
	$("[name='btn_apply']").prop("disabled",true);
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			
		},complete:function(){
			$("[name='btn_apply']").prop("disabled",false);
		}
	});
}
var form_del = function(){
	var tobj = $("[name='sta_del']:checked");
	var del_list = new Array();
	for (var j=0; j < tobj.length; j++)
	{
		del_list.push(tobj.eq(j).val());
	}
	var cnt = del_list.length -1;
	for (var i=0; i < del_list.length ;i++ )
	{
//		console.log(del_list[(cnt-i)]);
		data.splice(del_list[(cnt-i)], 1);
	}
	
	$("#btn_apply").show();
	form_save();
	create_table();
	
}
var form_all_del = function(){
	if(!confirm("전체 삭제하시겠습니까?")){
		$.cookie("magickey",parseInt(get_timestamp(),10));
		return;
	}
	$.cookie("magickey",parseInt(get_timestamp(),10));
	data = new Array();
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'all_del_rule';
//		alert(JSON.stringify(sobj));
	$("[name='btn_apply']").prop("disabled",true);
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			$("#btn_apply").show();
			create_table();
		},complete:function(){
			$("[name='btn_apply']").prop("disabled",false);
		}
	});
}
var form_apply = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'apply_rule';
	create_loading();
	$("[name='btn_apply']").prop("disabled",true);
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
				alert("적용에 실패했습니다.");
				return;
			}
		},complete:function(){
			remove_loading();
			$("[name='btn_apply']").prop("disabled",false);
		}
	});
}
var create_time = function(){
	var start = $("#start_time");
	var end = $("#end_time");
	start.children().remove();
	end.children().remove();
	for (var i=0; i <= 24 ; i++)
	{
		start.append("<option value=\""+i+"\">"+convert_two_digit(i)+"</option>");
		end.append("<option value=\""+i+"\">"+convert_two_digit(i)+"</option>");
	}
	
}
var now = <?=getTimestamp();?>;
var timeIvt = null;
var ntp_restart = function(){
	dummyVal = CreateDummy();
	var sobj = new Object();
	sobj['dummyVal'] = dummyVal;
	sobj['act'] = 'restart_ntp';
	$.ajax({
		"data":sobj,
		url:proc,
		"dataType":"text",
		"type":"POST",
		success:function(d){
			now = parseInt(d,10);
		}
	});
}
var sel_week = function(){
	var sel_week = $("[name='week']:checked").length;
	if($("#all_week").prop("checked") == true){
		if( sel_week < 7){
			$("#all_week").prop("checked",false);
		}
	}
}
var sel_all_week = function(){
	console.log($("[name='week']:checked").length);
	if($("#all_week").prop("checked") == true){
		$("[name='week']").prop("checked",true);
	}else{
		$("[name='week']").prop("checked",false);
	}
}
$(document).ready(function(){
	$("#mac_area").children().remove();
	if(sta.length > 0){
		var tempVal = "<select name=\"sta_mac\" id=\"sta_mac\" class=\"form-control\" onchange=\"change_select(this)\" preval=\""+sta[0]+"\">\n";
		for (var i=0; i < sta.length ; i++)
		{
			tempVal += "<option value=\""+sta[i]+"\">"+sta[i]+"</option>";
		}
		tempVal += "<option value=\"\">=== 직접입력 ===</option>";
		tempVal += "</select>\n";
		$("#mac_area").append(tempVal);
	}else{
		var tempVal = "<input type=\"text\" name=\"sta_mac\" id=\"sta_mac\" class=\"form-control\" value=\"\" maxlength=\"17\">";

		$("#mac_area").append(tempVal);
	}
	create_time();
	get_rule();
	timeIvt = setInterval(function(){
		now = now+1000;
		$("#time").text(millisecond_to_date(now));
		
//		$("#time").text(Date().yyyymmdd() + " " + Date().hhmmss());
	},1000);
	<?php if($app == ""){?>
	$("#btn_apply").hide();
	<?php }?>
});
</script>
</body>

</html>
