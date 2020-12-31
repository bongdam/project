<?php
/*
	Error CODE
	0 : not error
	1 : 
*/
class uci
{
	private $param = Array();
	private $add_param = Array();
	private $set_param = Array();
	private $del_param = Array();
	private $ck_param = Array();
	private $rtn = null;
	private $status = 0;
	private $arr_mode = Array(
		"get"=>0,
		"add"=>1,
		"set"=>2,
		"del"=>3,
		"commit"=>4,
		"ck"=>5
	);
	private $mode_val = Array(
		0=>"uci_get",
		1=>"uci_add",
		2=>"uci_set",
		3=>"uci_del",
		4=>"uci_commit",
		5=>"uci_realname"
	);
	private $mode = 0;
	private $error = Array(
		"result"=>true,
		"msg"=>""
	);
	public function set_head_json(){
		header ("Content-Type: application/json; charset=UTF-8");
	}
	public function mode($mode_){
		$this->mode = $this->arr_mode[$mode_];
	}
	public function getmode(){
		return $this->mode;
	}
	public function getstatus(){
		return $this->status;
	}
	public function get($key_, $separator_ = "|"){
		if(gettype($key_) == "string"){
			$arr_ = explode($separator_, $key_);
		}elseif(gettype($val_) == "array" ){
			$arr_ = $key_;
		}
		for($i = 0; $i < count($arr_); $i++){
			$this->param[] = Array("key"=>$arr_[$i]);
		}
		$this->status = 1;
	}
	public function add($key_, $val_){
		$this->add_param[] = Array($key_=>$val_);
		$this->status = 1;
	}
	public function set($key_, $val_){
		$this->set_param[] = Array($key_=>$val_);
//		print_r($this->set_param);
		$this->status = 1;
	}
	public function del($key_, $separator_ = "|"){
		if(gettype($key_) == "string"){
			$arr_ = explode($separator_, $key_);
		}elseif(gettype($val_) == "array" ){
			$arr_ = $key_;
		}
		for($i = 0; $i < count($arr_); $i++){
			$this->del_param[] = Array("key"=>$arr_[$i]);
		}
		$this->status = 1;
	}
	public function ck($key_, $separator_ = "|"){
		if(gettype($key_) == "string"){
			$arr_ = explode($separator_, $key_);
		}elseif(gettype($val_) == "array" ){
			$arr_ = $key_;
		}
		for($i = 0; $i < count($arr_); $i++){
			$this->ck_param[] = Array("key"=>$arr_[$i]);
		}
		$this->status = 1;
	}
	public function get_param(){
		Switch($this->mode){
			case "0":
				return $this->param;
				break;
			case "1":
				return $this->add_param;
				break;
			case "2":
				return $this->set_param;
				break;
			case "3":
				return $this->del_param;
				break;
			case "5":
				return $this->ck_param;
				break;
		}
	}
	public function run(){
		$json = null;
		$param_ = "";
		if($this->status == 0){
			$this->error["result"] = false;
			$this->error["msg"] = "not ready";
			return false;
		}
		$mode_ = $this->mode_val[$this->mode];
		if($mode_ == "uci_add"){
			$param_ = $this->add_param;
			$this->add_param = Array();
		}elseif($mode_ == "uci_set"){
			$param_ = $this->set_param;
			$this->set_param = Array();
		}elseif($mode_ == "uci_del"){
			$param_ = $this->del_param;
			$this->del_param = Array();
		}elseif($mode_ == "uci_realname"){
			$param_ = $this->ck_param;
			$this->ck_param = Array();
		}elseif($mode_ == "uci_get"){
			$param_ = $this->param;
			$this->param = Array();
		}else{
			$this->error["result"] = false;
			$this->error["msg"] = "not param";
		}
		if(gettype($param_) != "array"){
			$this->error["result"] = false;
			$this->error["msg"] = "No argument there";
			return false;
		}
		$sock = new rcqm();
		$sock->connect();
		if($sock->con()){
		}else{
			exit;
		}
		$this->doLog("GET",json_encode($param_));
		$sock->write($mode_,$param_);
		if($sock->error()["success"] == true){
			$json = $sock->read(50);
			$temp = json_decode($json,true);
			if($temp["success"] == false){
//				print_r($json);
				$this->error["result"] = false;
				$this->error["msg"] = "rcqm return error";
				return false;
			}else{
				$json = json_encode($temp["data"]);
				$this->doLog("SET",$json);
			}
		}else{
			$this->error["result"] = false;
			$this->error["msg"] = "RCQM Write Error";
			return false;
		}
		$sock->disconnect();
//		echo($json);
		$this->rtn = $json;
		$this->status = 2;
		return true;
	}
	public function commit(){
		$sock = new rcqm();
		$sock->connect();
		if($sock->con()){
		}else{
			exit;
		}
		$sock->write($this->mode_val[4],null);
		$json = $sock->read();
		$sock->disconnect();
		$this->rtn = $json;
		$this->status = 4;
		$result = json_decode($json,true);
		if($result["success"] == "true"){
			return true;
		}else{
			return false;
		}
	}
	public function result(){
		return $this->rtn;
	}
	public function error_status(){
		return $this->error["result"];
	}
	public function error_msg(){
		return $this->error["msg"];
	}
	public function __destruct()
 	{
		$this->param = null;
		$this->add_param = null;
		$this->set_param = null;
		$this->del_param = null;
		$this->rtn = null;
		$this->status = null;
		$this->mode = null;
		$this->error = Array(
			"result"=>true,
			"msg"=>""
		);
 	}
	public function close(){
		$this->param = null;
		$this->add_param = null;
		$this->set_param = null;
		$this->del_param = null;
		$this->rtn = null;
		$this->status = null;
		$this->mode = null;
		$this->error = Array(
			"result"=>true,
			"msg"=>""
		);
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
		// open log file
		return;
		$filename = "/tmp/uiuci.log";
		$fh = fopen($filename, "a+") or die("Could not open log file.");
		fwrite($fh, date("Y-m-d H:i:s").".".$this->get_mil()." [".$type_."] - $text\n") or die("Could not write file!");
		fclose($fh);
	}
}