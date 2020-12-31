<?php
	function cr_header($section_ = "normal"){
		$html = "";
		Switch($section_){
			Case "normal":
		$html = <<<EOD
	<title>SKB H824G Bootstrap</title>
	<!-- Bootstrap Core CSS -->
	<link href="../vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
	<!-- MetisMenu CSS -->
	<link href="../vendor/metisMenu/metisMenu.min.css" rel="stylesheet">
	<link href="../dist/css/sb-admin-2.css" rel="stylesheet">
	<link href="../vendor/font-awesome/css/font-awesome.min.css" rel="stylesheet" type="text/css">
	<!--[if lt IE 9]>
		<script src="../vendor/bootstrap/js/html5shiv.js"></script>
		<script src="../vendor/bootstrap/js/respond.min.js"></script>
	<![endif]-->
	<script src="../vendor/jquery/jquery.min.js"></script>
	<script src="/inc/js/common.js"></script>
EOD;
			break;
		}
		return $html;
	}
	function cr_footer($section_ = "normal"){
		$html = "";
		Switch($section_){
			Case "normal":
		$html = <<<EOD
	<!-- Bootstrap Core JavaScript -->
	<script src="../vendor/bootstrap/js/bootstrap.min.js"></script>

	<script src="/inc/js/onready.js"></script>
	<!-- Metis Menu Plugin JavaScript -->
	<script src="../vendor/metisMenu/metisMenu.min.js"></script>

	<!-- Custom Theme JavaScript -->
	<script src="../dist/js/sb-admin-2.js"></script>
	
EOD;
			break;
		}
		return $html;
	}
	function cr_lang(){
		global $lang;
		$cur_url = $_SERVER["HTTP_HOST"] . $_SERVER["REQUEST_URI"];
		$cur_url_pos = strripos($cur_url,"/");
		$cur_url_file = substr($cur_url,$cur_url_pos+1,strlen($cur_url));
		$cur_url_file_pos = strripos($cur_url_file,".");
		$lang_file = substr($cur_url_file,0,$cur_url_file_pos);

		$cur_url_folder_pos = strripos($cur_url,"/");
		$cur_url_folder_name = substr($cur_url,0,$cur_url_pos);
		$cur_url_folder_pos = strripos($cur_url_folder_name,"/");
		$cur_url_folder_name = substr($cur_url_folder_name,$cur_url_folder_pos+1,strlen($cur_url_folder_name));
		$tempVal = "<input type=\"hidden\" name=\"ui_lang\" id=\"ui_lang\" value=\"".$lang."\">\n";
		$tempVal .="<input type=\"hidden\" name=\"ui_file\" id=\"ui_file\" value=\"".$lang_file."\">\n";
		$tempVal .="<input type=\"hidden\" name=\"ui_folder\" id=\"ui_folder\" value=\"".$cur_url_folder_name."\">\n";
		$tempVal .="<input type=\"hidden\" name=\"ui_mode\" id=\"ui_mode\" value=\"".dv_session("standalone")."\">\n";
		return $tempVal;
	}
	function cr_menu(){
		$html = "";
		$html = <<<EOD
		<!-- Navigation -->
		<nav class="navbar navbar-custom navbar-static-top" role="navigation" style="margin-bottom: 0">
			<div class="navbar-header">
				<button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">
					<span class="sr-only">Toggle navigation</span>
					<span class="icon-bar"></span>
					<span class="icon-bar"></span>
					<span class="icon-bar"></span>
				</button>
				<a class="navbar-brand" href="index.php">H824G</a>
			</div>
			<div class="navbar-custom sidebar" role="navigation">
				<div class="sidebar-nav navbar-collapse">
					<ul class="nav" id="side-menu">
						<li class="index">
							<a href="index.php"><i class="fa fa-dashboard fa-fw"></i> Home</a>
						</li>
						<li>
							<a href="#"><i class="fa fa-files-o fa-fw"></i> 무선 설정<span class="fa arrow"></span></a>
							<ul class="nav nav-second-level">
								<li class="sta_protection">
									<a href="sta_protection.php">무선접속 제한 서비스</a>
								</li>
							</ul>
						</li>
					</ul>
				</div>
				<!-- /.sidebar-collapse -->
			</div>
			<!-- /.navbar-static-side -->
		</nav>
EOD;
		return $html;
	}
?>