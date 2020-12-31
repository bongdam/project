<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/class/dvcmd/dvcmd_const.php");
/*
	Error CODE
	0 : not error
	1 : 
*/
class dvcmd
{
	private $param = Array();
	private $rtn = null;
	private $status = 0;
	private $arr_mode = Array(
		"add"=>0
	);
	private $mode = 0;
	private $timeout = 0;
	private $readbuf = 4096;
	private $error = Array(
		"result"=>true,
		"msg"=>""
	);
	public function getstatus(){
		return $this->status;
	}
	public function settimeout($time_){
		$this->timeout = $time_;
	}
	public function set_buf($size_){
		$this->readbuf = $size_;
	}
	public function add(string $cmd_val_, $arr_ = null, $split_ = "|"){
		if(isset(SYSCALL[$cmd_val_]) === true){
			$arr = Array();
			if(SYSCALL_P[$cmd_val_] === false){
				$this->task(SYSCALL[$cmd_val_]);
			}else{
				if(gettype($arr_) === "string"){
					$arr = explode($split_,$arr_);
				}elseif(gettype($arr_) === "array"){
					$arr = $arr_;
				}else{
					$this->doLog("ERR","ADD ERROR.");
					return false;
				}
				$cmd = vsprintf(SYSCALL[$cmd_val_],$arr);
				$this->task($cmd);
			}
			return true;
		}else{
			return false;
		}
	}
	private function task($cmd_){
		$this->param[] = Array("cmd"=>$cmd_);
		$this->status = 1;
	}
	public function run($flag_ = null){
		$json = null;
		if($this->status == 0){
			$this->error["result"] = false;
			$this->error["msg"] = "not ready";
			return false;
		}
		$param_ = $this->param;
//		print_r($param_);
		if(gettype($param_) != "array"){
			$this->error["result"] = false;
			$this->error["msg"] = "No argument there";
			$this->doLog("ERR","No argument there");
			return false;
		}
		$this->doLog("GET",json_encode($param_));
		$sock = new rcqm();
		if($this->timeout != 0){
			$sock->set_config("timeout",$timeout);
		}
		$sock->connect();
		if($sock->con()){
		}else{
			$this->doLog("ERR","NOT Connection");
			exit;
		}
		$sock->write("syscall",$param_);
		if($sock->error()["success"] == true){
			if($flag_ == null){
				$json = $sock->read($this->readbuf);
				$temp = json_decode($json,true);
				if($temp["success"] == false){
	//				print_r($json);
					$this->error["result"] = false;
					$this->error["msg"] = "rcqm return error";
					$this->doLog("ERR","rcqm return error");
					$sock->disconnect();
					return false;
				}else{
					$json = $temp["data"];
					$this->doLog("RTN",json_encode($json));
				}
			}else{
				$this->doLog("INFO","Not return. (True)");
			}
		}else{
			$this->error["result"] = false;
			$this->error["msg"] = "RCQM Write Error";
			$this->doLog("ERR","RCQM WRITE ERROR");
			$sock->disconnect();
			return false;
		}
		$sock->disconnect();
//		echo($json);
		$this->rtn = $json;
		$this->status = 2;
		$this->param = array();
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
	public function result($avgs_ = 0){

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
//		return;
		$filename = "/tmp/uicli.log";
		$fh = fopen($filename, "a+") or die("Could not open log file.");
		fwrite($fh, date("Y-m-d H:i:s").".".$this->get_mil()." [".$type_."] - $text\n") or die("Could not write file!");
		fclose($fh);
	}
}