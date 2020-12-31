<?php
class rcqm
{
	protected $_config = array(
		'host'			=> '127.0.0.1',
		'protocol'		=> 'tcp',
		'port'			=> 9001,
		'timeout'		=> 30,
		'persistent'	=> false,
	);
	private $config = array();
	private $connection = null;
	private $connected = false;
	private $error = array();
	private $error_rec = true;
	private $req_type = "";
	private $req_num = -1;
	private $req_name = "";
	private $req_param = array();
	private $req_recv = array();
	private $req_recv_temp = null;
	private $rcqm_list = array();
	private $user_ip = "";

	private $start_date = ""; // 프로세스 시작 날짜 시간.
	private $start_time = array(); // 프로세스 시작 시간.
	private $end_time = ""; // 프로세스 끝 시간.

	private $meta = Array();

	private $rcqm_status = 0; //0 : 초기화 1 : 접속단계, 2 : 명령어 전달단계, 3 : 값 리턴단계, 4: 접속 해제단계.

	public function __construct($config = array())
	{
		
		$this->config =	array_merge($this->_config,$config);
		if (!is_numeric($this->config['protocol'])) $this->config['protocol'] = getprotobyname($this->config['protocol']);
		global $rcqm_command;
		$this->rcqm_list = $rcqm_command;
		$this->start_date = $this->get_timestamp();
		$this->start_time = $this->set_start_time();
	}
	public function set_config($key_, $val_){
		$this->_config[$key_]=$val_;
		$config = array();
		$this->config =	array_merge($this->_config,$config);
	}
	private function get_timestamp()
	{
		$microtime = floatval(substr((string)microtime(), 1, 8));
		$rounded = round($microtime, 3);
		$rounded = substr((string)$rounded, 2, strlen($rounded));
		$millisecond_ = substr($rounded."00",0,3);
		return time().$millisecond_;
	}
	public function get_meta(){
		return $this->meta;
	}
	private function set_start_time(){
		return $start_time = explode(" ",microtime());
	}
	private function set_end_time($start_time){
			$end_time = explode(" ",microtime());
			$sec = $end_time[1] - $start_time[1];
			$microsec = $end_time[0] - $start_time[0];
			return $sec + $microsec;
	}
	private function mil_to_date($mil_){
		$date_ = date("Y-m-d H:i:s", $mil_/1000);
		return $date_;
	}
	public function obj_to_str($obj_){
		$tempVal = "";
		if(gettype($obj_) == "array"){
			$x = array_keys($obj_);
			for($i=0; $i < count($x); $i++){
				$val_type = gettype($obj_[$x[$i]]);
				$val_ = "";
				if($tempVal != ""){
					$tempVal .= ", ".$x[$i]."(".$val_type."):";
				}else{
					$tempVal .= " ".$x[$i]."(".$val_type."):";
				}
				if($val_type == "array" || $val_type == "object"){
					$val_ = json_encode($obj_[$x[$i]]);
				}else{
					$val_ = $obj_[$x[$i]];
				}
				$tempVal .= " ".(string)$val_;

			}
		}else{
			$tempVal = $obj_;
		}
		return $tempVal;
	}
	public function connect()
	{
		$this->rcqm_status = 1;
		if ($this->connection != null) $this->disconnect();
		ini_set("default_socket_timeout", $this->config['timeout']);
		if ($this->config['persistent'] == true)
		{
			$tmp = null;
			$this->connection = @pfsockopen($this->config['host'], $this->config['port'], $errNum, $errStr, $this->config['timeout']);
		}
		else
		{
			$this->connection = @fsockopen($this->config['host'], $this->config['port'], $errNum, $errStr, $this->config['timeout']);
		}
		if (!empty($errNum) || !empty($errStr))
		{
			$this->error = array('success'=>false,'err_msg'=>"Socket connection was unsuccessful.",'err_str'=>$errStr,'err_no'=>$errNum,'function'=>__FUNCTION__,'line'=>__LINE__);
			$this->end_time = $this->set_end_time($this->start_time);
		}
//		stream_set_timeout($this->connection, $this->config['timeout']);
		$this->meta = stream_get_meta_data($this->connection);
		$this->connected = is_resource($this->connection);
		$this->error = array('success'=>true,'err_msg'=>"",'err_str'=>"",'err_no'=>"",'function'=>"",'line'=>"");
		$this->end_time = $this->set_end_time($this->start_time);
		$this->user_ip =  $_SERVER['REMOTE_ADDR'];
		return $this->connected;
	}
	public function set_error_rec_status($flag_){
		if($flag_ === false){
			$this->error_rec = false;
		}
	}
	public function get_rcqm_status(){
		return $this->rcqm_status;
	}
	public function set_head_json(){
		header ("Content-Type: application/json; charset=UTF-8");
	}
	public function get_error_rec_status(){
		return $this->error_rec;
	}
	public function error()
	{
		return $this->error;
	}
	public function con(){
		return $this->connected;
	}
	public function write($req_ = "", $param_ = null)
	{
		if($this->error["success"] == true){
			$this->rcqm_status = 2;
		}
		if (!$this->connected)
		{
			$this->error = array('success'=>false,'err_msg'=>"Socket is not connected.",'err_str'=>"",'err_no'=>"",'function'=>"",'line'=>"");
			if (!$this->connect()){
				$this->end_time = $this->set_end_time($this->start_time);
				return false;
			}
		}
		if($req_ == ""){
			$this->error = array('success'=>false,'err_msg'=>"Request command is not entered.",'err_str'=>"",'err_no'=>"",'function'=>"",'line'=>"");
			$this->end_time = $this->set_end_time($this->start_time);
			return false;
		}
		if(array_key_exists($req_,$this->rcqm_list) === false){
			$this->error = array('success'=>false,'err_msg'=>"The requested command does not exist.",'err_str'=>"",'err_no'=>"",'function'=>"",'line'=>"");
			$this->end_time = $this->set_end_time($this->start_time);
			return false;
		}
		$this->req_num = $this->rcqm_list[$req_]["no"];
		$this->req_name = $this->rcqm_list[$req_]["name"];
		$this->req_type = $this->rcqm_list[$req_]["type"];
		$this->req_param = $this->obj_to_str($param_);
		$data = array  (
			"cmd" =>	$this->req_num,
			"param" =>	$param_
		);
		$js_ = json_encode($data);
		$this->doLog("GET",$js_);
//		print_r($js_);
		$this->error = array('success'=>true,'err_msg'=>"",'err_str'=>"",'err_no'=>"",'function'=>"",'line'=>"");
		$this->end_time = $this->set_end_time($this->start_time);
		$bufferSize = strlen($js_);
		if (function_exists('stream_set_read_buffer')) {
				stream_set_read_buffer($this->connection, $bufferSize);
		}
		if (function_exists('stream_set_chunk_size')) {
				stream_set_chunk_size($this->connection, $bufferSize);
		}
//		stream_set_timeout($this->connection, $this->config['timeout']);
		$this->meta = stream_get_meta_data($this->connection);
		return fwrite($this->connection, $js_, strlen($js_));
	}
	public function read($kb_=30)
	{
		if($this->error["success"] == true){
			$this->rcqm_status = 3;
		}
		if (!$this->connected)
		{
			$this->error = array('success'=>false,'err_msg'=>"Socket is not connected.",'err_str'=>"",'err_no'=>"",'function'=>"",'line'=>"");
			
			return false;
//			if (!$this->connect()){
//				
//				
//			}
		}
		$kb_ = 1024 * $kb_;
		if (!feof($this->connection)){
			$this->req_recv_temp = null;
			$this->error = array('success'=>true,'err_msg'=>"",'err_str'=>"",'err_no'=>"",'function'=>"",'line'=>"");
			$this->end_time = $this->set_end_time($this->start_time);
			$bufferSize = $kb;
			if (function_exists('stream_set_read_buffer')) {
					stream_set_read_buffer($this->connection, $bufferSize);
			}
			if (function_exists('stream_set_chunk_size')) {
					stream_set_chunk_size($this->connection, $bufferSize);
			}
//			$this->req_recv_temp = fgets($this->connection, $kb_);
			$this->req_recv_temp = fread($this->connection, $kb_);
			$this->req_recv = $this->obj_to_str($this->req_recv_temp);
			$this->doLog("RTN",$this->req_recv_temp);
			
			return $this->req_recv_temp;
		}else{
			$this->error = array('success'=>false,'err_msg'=>"Receive data error",'err_str'=>"",'err_no'=>"",'function'=>"",'line'=>"");
			$this->end_time = $this->set_end_time($this->start_time);
			return false;
		}
	}
	public function disconnect()
	{
		//echo($this->error["success"]);
		if($this->error["success"] == true){
			$this->rcqm_status = 4;
		}
		if (!is_resource($this->connection))
		{
			$this->connected = false;
			return true;
		}
		$this->connected = !fclose($this->connection);
		if (!$this->connected)
		{
			$this->connection = null;
		}
		return !$this->connected;
	}
 	public function __destruct()
 	{
		if($this->error_rec){
			//정보 저장 기능 온일때만 작동. 기본값 온~! 
			//echo("END");
			if($this->error["success"] == false){
				$this->req_recv = $this->rcqm_status.": Error";
			}
		}
 		$this->disconnect();
 	}
	private function get_mil(){
		$microtime = floatval(substr((string)microtime(), 1, 8));
		$rounded = round($microtime, 3);
		$rounded = substr((string)$rounded, 2, strlen($rounded));
		$millisecond_ = substr($rounded."00",0,3);
		return $millisecond_;
	}
	private function doLog($type_ = "",$text)
	{
//		return;
		// open log file
		$filename = "/tmp/uisock.log";
		$fh = fopen($filename, "a+") or die("Could not open log file.");
		fwrite($fh, date("Y-m-d H:i:s").".".$this->get_mil()." [".$type_."] - $text\n") or die("Could not write file!");
		fclose($fh);
	}
}