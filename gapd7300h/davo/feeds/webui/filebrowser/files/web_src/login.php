<?php
	require($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_le.php");
?>
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="bootstrap/css/bootstrap.min.css" rel="stylesheet" charset="UTF-8">
<link href="bootstrap/css/ie10-viewport-bug-workaround.css" rel="stylesheet" charset="UTF-8">
<!-- <link href="/inc/css/common.css" rel="stylesheet" charset="UTF-8"> -->
<!-- IE8 에서 HTML5 요소와 미디어 쿼리를 위한 HTML5 shim 와 Respond.js -->
<!-- WARNING: Respond.js 는 당신이 file:// 을 통해 페이지를 볼 때는 동작하지 않습니다. -->
<!--[if lt IE 9]>
	<script src="bootstrap/html5shiv.min.js" charset="UTF-8"></script>
	<script src="bootstrap/respond.min.js" charset="UTF-8"></script>
<![endif]-->
<script src="inc/js/jquery-1.12.4.min.js" charset="UTF-8"></script>
<script src="inc/js/common.js" charset="UTF-8"></script>
<script src="bootstrap/js/bootstrap.min.js" charset="UTF-8"></script>
<style type="text/css">
html,body {
	width:100%;height:100%;
  padding-top: 10px;
  padding-bottom: 40px;
  background-color: #eee;
}
@media (max-width: 320px) {
	.form-signin {
		max-width: 330px;
		padding: 5px;
		margin: 0 auto;
	}
}
@media (min-width: 321px) {
	.form-signin {
		max-width: 400px;
		padding: 5px;
		margin: 0 auto;
	}
}
.form-signin .form-signin-heading,
.form-signin .checkbox {
  margin-bottom: 10px;
}
.form-signin .checkbox {
  font-weight: normal;
}
.form-signin .form-control {
  position: relative;
  height: auto;
  -webkit-box-sizing: border-box;
     -moz-box-sizing: border-box;
          box-sizing: border-box;
  padding: 10px;
  font-size: 16px;
}
.form-signin .form-control:focus {
  z-index: 2;
}
.form-signin input[type="text"] {
  margin-bottom: -1px;
  border-bottom-right-radius: 0;
  border-bottom-left-radius: 0;
}
.form-signin input[type="password"] {
  margin-bottom: 10px;
  border-top-left-radius: 0;
  border-top-right-radius: 0;
}
</style>
<script type="text/javascript">
	var proc = "login_proc.php";
	var frm_login = function(){
		dummyVal = CreateDummy();
		var user_id_ = $("#user_id").val();
		var user_pwd_ = $("#user_pwd").val();
//		alert('sss');
		var sobj = new Object();
		sobj['dummyVal'] = dummyVal;
		sobj['act'] = 'frmSave';
		sobj['user_id'] = $("#user_id").val();
		sobj['user_pwd'] = $("#user_pwd").val();
//		alert(JSON.stringify(sobj));
		$.ajax({
			"data":sobj,
			url:proc,
			"dataType":"text",
			"type":"POST",
			success:function(data){
				if(data == "1"){
					top.parent.window.location.assign("/");
				}else{
					console.log('Login fail');
					alert('Login fail.');
					return;
				}
			}
		});
	}
	$(document).ready(function(){
		$("input").attr("autocomplete","off");
		if($("#ifrm",parent.window.document).length == 1){
			top.window.location.assign("/");
		}
		$('#btn_login').click(function() {
			frm_login();
		});
	});
</script>
</head>
<body>
<!-- container -->
<div class="container">

	<form name="login_form" class="form-signin" method="post" autocomplete="off">
<!-- 		<h2 class="form-signin-heading text-center"><img src="" alt="LOGO"></h2> -->
		<label for="user_id" class="sr-only">Login ID</label>
		<input type="text" id="user_id" class="form-control" placeholder="Login ID" required autofocus>
		<label for="user_pwd" class="sr-only">Password</label>
		<input type="password" id="user_pwd" class="form-control" placeholder="Password" required onkeypress="if(event.keyCode  == 13){frm_login();}">
		<button id="btn_login" class="btn btn-lg btn-primary btn-block" type="button">Login</button>
<!-- 		<br> -->
<!-- 		<div class="panel panel-default"> -->
<!-- 			<div class="panel-heading"> -->
<!-- 				<h3 class="panel-title">accessed IP : <?=$_SERVER['REMOTE_ADDR'];?></h3> -->
<!-- 			</div> -->
		</div>
	</form>
	

</div>
<!-- /container -->
<script src="bootstrap/js/ie10-viewport-bug-workaround.js"></script>
</body>
</html>

