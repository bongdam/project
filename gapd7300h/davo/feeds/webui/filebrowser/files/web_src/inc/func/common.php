<?php

	function std_get_val($obj_,$key_ = "", $split_ = "|"){
		if(gettype($obj_) == "object"){
			$obj = $obj_;
			$a = explode($split_,$key_);
			switch(count($a)){
				case 0:
					return false;
					break;
				case 1:
					if(isset($obj->{$a[0]})){
						return $obj->{$a[0]};
					}
					break;
				case 2:
					if(isset($obj->{$a[0]}->{$a[1]})){
						return $obj->{$a[0]}->{$a[1]};
					}
					break;
				case 3:
					if(isset($obj->{$a[0]}->{$a[1]}->{$a[2]})){
						return $obj->{$a[0]}->{$a[1]}->{$a[2]};
					}
					break;
				case 4:
					if(isset($obj->{$a[0]}->{$a[1]}->{$a[2]}->{$a[3]})){
						return $obj->{$a[0]}->{$a[1]}->{$a[2]}->{$a[3]};
					}
					break;
				default:
					return false;
					break;
			}
		}else{
			return false;
		}
	}
	function get_array_val($arr_,$key_, $orig_ = ""){
		if(array_key_exists($key_,$arr_) == true){
			return $arr_[$key_];
		}else{
			if($orig_ == ""){
				return "";
			}else{
				if(array_key_exists("_orig_".$key_,$arr_) == true){
					return $arr_["_orig_".$key_];
				}else{
					return "";
				}
			}
		}
	}
	function get_json_val($obj_, $key_ = ""){
		$key = explode(".",$key_);
		switch(count($key)){
			case 1:
				if(isset($obj_->{$key[0]}) === false){
					return "";
				}
				return $obj_->{$key[0]};
				break;
			case 2:
				if(isset($obj_->{$key[0]}) === false){
					return "";
				}
				if(isset($obj_->{$key[0]}->{$key[1]}) === false){
					return "";
				}
				return $obj_->{$key[0]}->{$key[1]};
				break;
			case 3:
				if(isset($obj_->{$key[0]}) === false){
					return "";
				}
				if(isset($obj_->{$key[0]}->{$key[1]}) === false){
					return "";
				}
				if(isset($obj_->{$key[0]}->{$key[1]}->{$key[2]}) === false){
					return "";
				}
				return $obj_->{$key[0]}->{$key[1]}->{$key[2]};
				break;
		}
	}
	function sec_to_date($sec_ = 0){
		$time = $sec_;
		$days = floor($time / (60 * 60 * 24));
		$time -= $days * (60 * 60 * 24);
		$hours = floor($time / (60 * 60));
		$time -= $hours * (60 * 60);
		$minutes = floor($time / 60);
		$time -= $minutes * 60;
		$seconds = floor($time);
		$time -= $seconds;
		return "{$days}d {$hours}h {$minutes}m {$seconds}s";
	}
	function dv_raw_post(){
		$val = "";
		$val = json_decode(file_get_contents('php://input'));
		return $val;
	}
	/*
	* 제작자 : take99
	* 제작일 : 2015/02/13
	* 함수명 : dv_post("")
	* 함수기능 : POST로 전송받은 값 리턴
	이함수로 포스트값을 전송받는 이유는 인젝션 공격에 대한 대비.
	* 함수 사용법 :
		echo(dv_post('키값');
	* 수정사항
	*/
	function dv_post($name_, $replace_ = "")
	{
		if(isset($_POST[$name_])){
			if(!is_array($_POST[$name_])){
				$tmp = $_POST[$name_];
				if($replace_ == "script"){
					$tmp = htmlspecialchars($tmp,ENT_QUOTES);
				}elseif($replace_ == "escape"){
					//					$tmp = str_ireplace("\\", "\\\\", $tmp);
//					$tmp = str_ireplace("'", "\'", $tmp);
					$tmp = stripslashes($tmp);
					$tmp = htmlspecialchars($tmp);
					$tmp = str_ireplace("script", "blocked", $tmp);
					$tmp = str_ireplace("'", "\'", $tmp);
				}
			}else{
				for($i=0; $i < count($_POST[$name_]); $i++){
					if($replace_ == "script"){
						$_POST[$name_][$i] = $tmp = htmlspecialchars($_POST[$name_][$i],ENT_QUOTES);

					}elseif($replace_ == "escape"){
						$_POST[$name_][$i] = htmlspecialchars(stripslashes($_POST[$name_][$i]));
						$_POST[$name_][$i] = str_ireplace("script", "blocked", $_POST[$name_][$i]);
						$_POST[$name_][$i] = str_ireplace("'", "\'", $_POST[$name_][$i]);
					}
				}
				$tmp = $_POST[$name_];
			}
			//$tmp = mysql_escape_string($tmp);
			return $tmp;
		}else{
			return false;
		}
	}
	/*
	* 제작자 : take99
	* 제작일 : 2015/02/13
	* 함수명 : dv_get("")
	* 함수기능 : GET으로 전송받은 값 리턴.
	이함수로 GET 값을 전송받는 이유는 인젝션 공격에 대한 대비.
	* 함수 사용법 :
		echo(dv_get('키값');
	* 수정사항
	*/
	function dv_get($name_, $replace_ = "")
	{
		if(isset($_GET[$name_])){
			$tmp = $_GET[$name_];
			if($replace_ == "escape"){
				$tmp = htmlspecialchars(stripslashes($tmp));
				$tmp = str_ireplace("script", "blocked", $tmp);
				$tmp = str_ireplace("'", "\'", $tmp);
				//$tmp = mysql_real_escape_string($tmp);
			}
			return $tmp;
		}
	}
	/*
	* 제작자 : take99
	* 제작일 : 2015/02/13
	* 함수명 : dv_cookie("")
	* 함수기능 : 쿠기에 저장된 값 리턴
	* 함수 사용법 :
		echo(dv_cookie('쿠키명');
	* 수정사항
	*/
	function dv_cookie($name_){
		if(isset($_COOKIE[$name_])){
		$tmp = $_COOKIE[$name_];
			return $tmp;
		}else{
			return false;
		}
	}
	/*
	* 제작자 : take99
	* 제작일 : 2015/02/13
	* 함수명 : dv_session("")
	* 함수기능 : 세션에 저장된 값 리턴
	* 함수 사용법 :
		echo(dv_session('세션명');
	* 수정사항
	*/
	function dv_session($name_){
		@session_start();
		if(isset($_SESSION[$name_])){
		$tmp = $_SESSION[$name_];
			@session_write_close(); 
			return $tmp;
		}else{
			@session_write_close(); 
			return false;

		}
		
	}
	function dv_set_session($key_, $value_){
		@session_start();
		$_SESSION[$key_] = $value_;
		@session_write_close(); 
		return true;
	}
	/*
		제작자 : take99
		제작일 : 2015/02/13
		DATA 해쉬값 리턴함수
	*/
	function dv_encode($val_ = "", $type_ = "sha256" ){
		return hash ($type_,$val_);
	}
	function getTimestamp()
	{
		$microtime = floatval(substr((string)microtime(), 1, 8));
		$rounded = round($microtime, 3);
		$rounded = substr((string)$rounded, 2, strlen($rounded));
		$millisecond_ = substr($rounded."00",0,3);
		return time().$millisecond_;
	}
	function millisecond_to_date($mil_){
		$date_ = date("Y-m-d H:i:s", $mil_);
		return $date_;
	}
	function AES_Encode($plain_text = "", $flag_ = false)
	{
		global $enckey;
		IF($flag_ == true){
			$plain_text = htmlspecialchars_decode($plain_text);
		}
		return base64_encode(openssl_encrypt($plain_text, "aes-256-cbc", $enckey,  OPENSSL_RAW_DATA, str_repeat(chr(0), 16)));
	}
	/*
		제작자 : take99
		제작일 : 2015/02/13
		PHP 구성에 OpenSSL 포함되어야 작동함.
		AES암호화 작동
	*/
	function AES_Decode($base64_text)
	{
		global $enckey;
		return openssl_decrypt(base64_decode($base64_text), "aes-256-cbc", $enckey,  OPENSSL_RAW_DATA, str_repeat(chr(0), 16));
	}
	function create_post_value($flag_ = ""){
		foreach($_GET as $key => $value)
		{
			if($key == "dummyVal") continue;
			echo("$".$key."_ = dv_get(\"".$key."\");\n");
			if($flag_ != ""){
				echo($key.":".$value."\n");
			}
		}
		foreach($_POST as $key => $value)
		{
			if($key == "dummyVal") continue;
			echo("$".$key."_ = dv_post(\"".$key."\");\n");
			if($flag_ != ""){
				echo($key.":".$value."\n");
			}
		}
	}
	function shift_switch($hex_, $set_, $position_){
		$hexdec = base_convert($hex_,16,10);
		$shift = $hexdec |= 0x01 << $position_;
		if($set_ == 0){
			if($hexdec == $shift){
				$shift = $hexdec ^= 0x01 << $position_;
			}
		}
		return dechex(bindec(decbin($shift)));
	}
	function get_bin_postion($hex_, $position_){
		$hexdec = base_convert($hex_,16,10);
		$bin = decbin($hexdec);
		$bin = substr($bin,($position_*-1-1));
		$bin = substr($bin,0,1);
		return $bin;
	}
	function str2Hex($string_)
	{
		$hex='';
		for ($i=0; $i < strlen($string_); $i++)
		{
			$hex .= dechex(ord($string_[$i]));
		}
		return $hex;
	}
	Function hexstr($hexstr) {
		$hexstr = str_replace(' ', '', $hexstr);
		$hexstr = str_replace('\x', '', $hexstr);
		$retstr = pack('H*', $hexstr);
		return $retstr;
	}

	Function strhex($string) {
		$hexstr = unpack('H*', $string);
		return array_shift($hexstr);
	}
	function mb_basename($path) {
		return end(explode('/',$path));
	}
	function utf2euc($str) { 
		return iconv("UTF-8","cp949//IGNORE", $str);
	}
	function is_ie() {
		return isset($_SERVER['HTTP_USER_AGENT']) && strpos($_SERVER['HTTP_USER_AGENT'], 'MSIE') !== false;
	}
	/*
		제작자 : take99
		제작일 : 2013/10/10
		설명 : 파일다운로드
		인자 : $fileName_ < -- 다운로드할 파일명
		       $filePath_  < -- 파일이 존재하는 상대 경로 Ex) ../files/report
	*/
	function file_download($filePath_,$fileName_){
		$filepath = $filePath_."/".$fileName_;
		$filesize = filesize($filepath);
		$filename = mb_basename($filepath);
//		echo($filepath);
		if( is_ie() ) $filename = utf2euc($filename);
		 
		header("Pragma: public");
		header("Expires: 0");
		header("Content-Type: application/octet-stream");
		header("Content-Disposition: attachment; filename=\"$filename\"");
		header("Content-Transfer-Encoding: binary");
		header("Content-Length: $filesize");
		readfile($filepath);
	}
	function file_delete($filepath_, $filename_){
		if(file_exists($filepath_."/".$filename_)){
			unlink($filepath_."/".$filename_);
		}
	}
	function json_to_array($json_, $break_ = 0){
		$result = json_decode($json_,true);
		$keys = array_keys($result);
		$temp_result = Array();
		for($i=0; $i < count($result); $i++){
			if($break_ == 1){
				if($result[$keys[$i]] == ""){
					break;
				}else{
					$temp_result[] = str_replace("\"","&quot;",str_ireplace("\\","\\\\",$result[$keys[$i]]));
				}
			}elseif($break_ == 2){
				if($result[$keys[$i]] == ""){
					continue;
				}else{
					$temp_result[] = str_replace("\"","&quot;",str_ireplace("\\","\\\\",$result[$keys[$i]]));
				}
			}else{
				$temp_result[] = str_replace("\"","&quot;",str_ireplace("\\","\\\\",$result[$keys[$i]]));
			}
		}
		return $temp_result;
	}
	function json_to_array_string($json_){
		if(gettype($json_) == "array"){
			$json_ = json_encode($json_);
			$result = json_decode($json_,true);
		}elseif(gettype($json_) == "object"){
			$result = json_decode($json_,true);
		}
		$keys = array_keys($result);
		$temp_result = Array();
		for($i=0; $i < count($result); $i++){
			$temp_result[] = str_replace("\"","&quot;",str_ireplace("\\","\\\\",$result[$keys[$i]]));
		}
		return "[\"".implode("\",\"",$temp_result)."\"]";
	}
	function json_to_array_int($json_){
		$result = json_decode($json_,true);
		$keys = array_keys($result);
		$temp_result = Array();
		for($i=0; $i < count($result); $i++){
			$temp_result[] = $result[$keys[$i]];
		}
		return "[".implode(",",$temp_result)."]";
	}
	function uci_decode($str_ = "",$mode_ = "array"){
		if($str_ == "[]"){
			$str_ = "";
		}
		if($mode_ == "array"){
			$rtn = json_decode($str_,true);
		}else{
			$rtn = json_decode($str_);
		}
		
	}
	function array_to_json($arr_,$type_ = "json_string"){
		$rtn = "";
		if($type_ == "json_string"){
			$rtn = json_encode($arr_,JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK );
		}else{
			$rtn = json_encode($arr_);
		}
		return $rtn;
	}
	function json_to_string($json_,$prefix_ = ",", $break_ = 0){
		if(gettype($json_) == "string"){
//			$json_ = json_decode($json_,true);
		}
		$result = json_decode($json_,true);
		$keys = array_keys($result);
		$temp_result = Array();
		for($i=0; $i < count($keys); $i++){
//			print_r($break_);
			if($break_ == 1){
				if($result[$keys[$i]] == ""){
					break;
				}else{
					$temp_result[] = str_replace("\"","&quot;",str_ireplace("\\","\\\\",$result[$keys[$i]]));
				}
			}elseif($break_ == 2){
				if($result[$keys[$i]] == ""){
					continue;
				}else{
					$temp_result[] = str_replace("\"","&quot;",str_ireplace("\\","\\\\",$result[$keys[$i]]));
				}
			}else{
				$temp_result[] = str_replace("\"","&quot;",str_ireplace("\\","\\\\",$result[$keys[$i]]));
			}
		}
		return implode($prefix_,$temp_result);
	}
	function set_head_json(){
		header ("Content-Type: application/json; charset=UTF-8");
	}
	function create_random_str($length = 10) {
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$charactersLength = strlen($characters);
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[rand(0, $charactersLength - 1)];
		}
		return $randomString;
	}
	function byteConvert($bytes)
	{
		if($bytes == 0){
			return "0 bytes";
		}else{
			$s = array('bytes', 'KB', 'MB', 'GB', 'TB', 'PB');
			$e = floor(log($bytes)/log(1024));
			return sprintf('%.2f '.$s[$e], ($bytes/pow(1024, floor($e))));
		}
	}
	function get_mil(){
		$microtime = floatval(substr((string)microtime(), 1, 8));
		$rounded = round($microtime, 3);
		$rounded = substr((string)$rounded, 2, strlen($rounded));
		$millisecond_ = substr($rounded."00",0,3);
		return $millisecond_;
	}
	function web_log_save($filename_, $type_, $text_)
	{
		$filename = $filename_;
		$fh = fopen($filename, "a+") or die("Could not open log file.");
		fwrite($fh, date("Y-m-d H:i:s").".".get_mil()." [".$type_."] - $text_\n") or die("Could not write file!");
		fclose($fh);
	}
?>