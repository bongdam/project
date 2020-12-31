<?php
class dvshow
{
	private $rtn;
	private $unnamed;
	private $search;
	private $rlist_name;
	private $ori = "";

	function __construct(){
		$this -> rtn = (object)Array();
		$this->unnamed = Array();
		$this->search = (object)Array();
		$this->rlist_name = "";
	}
	private $error = Array(
		"result"=>true,
		"msg"=>""
	);
	public function load($txt_ = ""){
		$this->ori = rtrim($txt_);
//		print_r($this->ori);
		$uci = explode("\n",$this->ori);
		$i = 0;
		for($i = 0; $i < count($uci); $i++){
			if(preg_match("/^([\S+\_\-]{1,})\.([\S+\_\-]{1,})\.([\S+\_\-]{1,})\=([\S+\s+\_\-\']{1,})+/",$uci[$i],$d) == true){
				if(strpos($d[4],"' '") !== false){
					$temp = explode(" ",$d[4]);
					if(isset($this->rtn->{$d[1]}) === false){
						$this->rtn->{$d[1]} = (object)Array();
					}
					if(isset($this->rtn->{$d[1]}->{$d[2]}) === false){
						$this->rtn->{$d[1]}->{$d[2]} = (object)Array();
					}
					if(isset($this->rtn->{$d[1]}->{$d[2]}->{$d[3]}) === false){
						$this->rtn->{$d[1]}->{$d[2]}->{$d[3]} = Array();
					}
					for($x=0; $x < count($temp); $x++){
						if(substr($temp[$x],-1,1) == "'"){
							$temp[$x] = substr($temp[$x],0,-1);
						}
						if(substr($temp[$x],0,1) == "'"){
							$temp[$x] = substr($temp[$x],1);
						}
						array_push($this->rtn->{$d[1]}->{$d[2]}->{$d[3]},$temp[$x]);
					}
				}else{
					if(substr($d[4],-1,1) == "'"){
						$d[4] = substr($d[4],0,-1);
					}
					if(substr($d[4],0,1) == "'"){
						$d[4] = substr($d[4],1);
					}
					if(isset($this->rtn->{$d[1]}) === false){
						$this->rtn->{$d[1]} = (object)Array();
					}
					if(isset($this->rtn->{$d[1]}->{$d[2]}) === false){
						$this->rtn->{$d[1]}->{$d[2]} = (object)Array();
					}
					$this->rtn->{$d[1]}->{$d[2]}->{$d[3]} = $d[4];
				}
			}
		}
	}
	public function search($key_ = ""){
		$key = explode(".",$key_);
		$cnt = count($key);
		$result = Array();
		switch($cnt){
			case 1:
				if(isset($this->rtn->{$key[0]}) === true){
					$result = $this->rtn->{$key[0]};
				}else{
					$result = "";
				}
				break;
			case 2:
				if(isset($this->rtn->{$key[0]}->{$key[1]}) === true){
					$result = $this->rtn->{$key[0]}->{$key[1]};
				}else{
					$result = "";
				}
				break;
			case 3:
				if(isset($this->rtn->{$key[0]}->{$key[1]}->{$key[2]}) === true){
					$result = $this->rtn->{$key[0]}->{$key[1]}->{$key[2]};
				}else{
					$result = "";
				}
				break;
		}
		return $result;
	}
	public function result($type_ = "object"){
		Switch($type_){
			case "object":
				return $this->rtn;
				break;
			case "array":
				return json_decode(json_encode($this->rtn),true);
				break;
			case "json":
				return json_encode($this->rtn);
				break;
			case "json_string":
				return json_encode($this->rtn,JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK );
				break;
		}
		
	}
	public function result_remove($key_ = ""){
		if($key_ != ""){
			$key = explode(".",$key_);
			$cnt = count($key);
			switch($cnt){
				case 1:
					if(isset($this->rtn->{$key[0]}) === true){
						$result = $this->rtn->{$key[0]};
						unset($this->rtn->{$key[0]});
					}
					break;
				case 2:
					if(isset($this->rtn->{$key[0]}->{$key[1]}) === true){
						unset($this->rtn->{$key[0]}->{$key[1]});
					}
					break;
				case 3:
					if(isset($this->rtn->{$key[0]}->{$key[1]}->{$key[2]}) === true){
						unset($this->rtn->{$key[0]}->{$key[1]}->{$key[2]});
					}
					break;
			}
		}
	}
	public function __destruct()
 	{
		$this->rtn = null;
		$this->unnamed = null;
		$this->search = null;
		$this->rlist_name = null;
 	}
	public function close(){
		$this->rtn = null;
		$this->unnamed = null;
		$this->search = null;
		$this->rlist_name = null;
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
		$filename = "/tmp/uishow.log";
		$fh = fopen($filename, "a+") or die("Could not open log file.");
		fwrite($fh, date("Y-m-d H:i:s").".".$this->get_mil()." [".$type_."] - $text\n") or die("Could not write file!");
		fclose($fh);
	}
}
//$sys = new dvshow();
//$dd = "firewall.@rule[6].icmp_type='echo-request' 'echo-reply' 'destination-unreachable' 'packet-too-big' 'time-exceeded' 'bad-header' 'unknown-header-type'
//firewall.@rule[6].icmp_type2='echo-request'
//";
//$sys->load($dd);
//print_r($sys->result("json_string"));
//$sys->close();
?>