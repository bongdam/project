<?php
class dvcfg
{
	private $rtn;
	private $unnamed;
	private $search;
	private $rlist_name;

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
	public function read($package_, $section_ = "", $key_ = ""){
		$package = $package_;
		$filename = "/etc/config/".$package;
		$myfile = fopen($filename, "r") or die("Unable to open file! ".$filename);
		$uci = fread($myfile,filesize($filename));
		fclose($myfile);

		$arr = explode("\n",$uci);
		
		$tmp = (object) Array($package=>(object)Array());
		$section = "";
		$skip_flag = false;
		for($i=0 ; $i < count($arr); $i++){
			if(preg_match("/^config\s+([\S+]{1,})\s+[\']{0,1}([\S+]{1,})[\']{0,1}/",$arr[$i],$d) == true) {
				//named
				$this->rlist_name = "";
				if(isset($d[2]) === true){
					if($section_ !=""){
						if(strpos($d[2],$section_) === false){
							$skip_flag = true;
							continue;
						}else{
							$skip_flag = false;
						}
					}
					if(substr($d[2],-1,1) == "'"){
						$d[2] = substr($d[2],0,-1);
					}
					$tmp->{$package}->{$d[2]} = (object) Array();
					$section = $d[2];
//					if($d[2] == ""){
//						$tmp->{$package}->{$d[1]} = (object) Array();
//						$section = $d[1];
//					}else{
//						
//					}
				}
			}else{
				//unnamed
				if(preg_match("/^config\s+([\S+]{1,})/",$arr[$i],$d) == true) {
					$this->rlist_name = "";
					if($section_ != ""){
						if(strpos($d[1],$section_) === false){
							$skip_flag = true;
							continue;
						}else{
							$skip_flag = false;
						}
					}
					if(array_key_exists($d[1],$this->unnamed) === false){
						//최초
						$section = $d[1]."[0]";
						$this->unnamed[$d[1]] = 1;
					}else{
						//기존있음
						$unnamed_cnt = $this->unnamed[$d[1]];
						$section = $d[1]."[".$unnamed_cnt."]";
						$this->unnamed[$d[1]] = $this->unnamed[$d[1]] + 1;
					}
					$tmp->{$package}->{$section} = (object) Array();
//					$section = $d[1];
				}
			}
			if($skip_flag == false){
				if(preg_match("/^\s+option\s+([\S+\_\-]{1,})\s+[\']{0,1}([\S+\_\-\s+]{1,})[\']{0,1}/",$arr[$i],$d) == true){
					if(substr($d[2],-1,1) == "'"){
						$tmp->{$package}->{$section}->{$d[1]}=substr($d[2],0,-1);
					}else{
						$tmp->{$package}->{$section}->{$d[1]}=$d[2];
					}
				}
				if(preg_match("/^\s+list\s+([\S+\_\-]{1,})\s+[\']{0,1}([\S+\_\-\s+]{1,})[\']{0,1}/",$arr[$i],$d) == true){
					if($d[1] != $this->rlist_name){
						$this->rlist_name = $d[1];
						if(isset($tmp->{$package}->{$section}->{$d[1]}) === false){
							$tmp->{$package}->{$section}->{$d[1]} = Array();
						}
					}
//					print_r($tmp->{$package}->{$section}->{$d[1]});
					if(substr($d[2],-1,1) == "'"){
//						array_push(,);
//						$keys = array_keys($tmp->{$package}->{$section}->{$d[1]});
//						echo(count($keys)."\n");
						array_push($tmp->{$package}->{$section}->{$d[1]},substr($d[2],0,-1));
					}else{
//						$keys = array_keys($tmp->{$package}->{$section}->{$d[1]});
//						$tmp->{$package}->{$section}->{$d[1]}->{count($keys)} = $d[2];
						array_push($tmp->{$package}->{$section}->{$d[1]},$d[2]);
//						$tmp->{$package}->{$section}->{$d[1]}=$d[2];
					}
				}
			}
		}
		if(isset($this->rtn->{$package}) === false){
			$this->rtn->{$package} = $tmp->{$package};
		}else{
			while (list($key, $val) = each($tmp->{$package})) {
				if(isset($this->rtn->{$package}->{$key}) === false){
					$this->rtn->{$package}->{$key} = $tmp->{$package}->{$key};
				}
			}
		}
	}
	public function return_unnamed(){
		return $this->unnamed;
	}
	public function search($key_ = "", $return_type_ = "object"){
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
		Switch($return_type_){
			case "object":
				return $result;
				break;
			case "array":
				return json_decode(json_encode($result),true);
				break;
			case "json":
				return json_encode($result);
				break;
			case "json_string":
				return json_encode($result,JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK );
				break;
		}
//		return $result;
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
		$filename = "/tmp/uicfg.log";
		$fh = fopen($filename, "a+") or die("Could not open log file.");
		fwrite($fh, date("Y-m-d H:i:s").".".$this->get_mil()." [".$type_."] - $text\n") or die("Could not write file!");
		fclose($fh);
	}
}
//$sys = new dvcfg();
//$sys->read("dvui");
//print_r($sys->result("array"));
//$sys->close();
//	print_r(json_encode($tmp,JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK ));
?>