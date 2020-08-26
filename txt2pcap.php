#!/usr/bin/env php -f 
<?php
class pcap_file_writer
{
	private $f;
	private $u32 = "V"; // L ?
	private $u16 = "v"; // S ?
	private $global_header;

	function close(){
		fclose($this->f);
	}

	function open($file)
	{
		$this->f = fopen($file, "wb");
		if ($this->f===FALSE){
			return FALSE;
		}
		return TRUE;
	}

	public function write_global_header($head)
	{
		fwrite($this->f, pack($this->u32, 0xa1b2c3d4));
		fwrite($this->f, pack($this->u16.$this->u16.$this->u32.$this->u32.$this->u32.$this->u32,
					$head['version_major'],
					$head['version_minor'],
					$head['thiszone'],
					$head['sigfigs'],
					$head['snaplen'],
					$head['network']));
	}

	public function write_packet($head)
	{
		fwrite($this->f, pack($this->u32.$this->u32.$this->u32.$this->u32,
				$head['ts_sec'],
				$head['ts_usec'],
				$head['incl_len'],
				$head['orig_len']));
		fwrite($this->f, $head['data']); //$data
	}

}

function usage($str){
	echo "$str\n";
	die("txt2pcap <input-file> <output-file>\n");
}

function str_to_sec_usec($time) {
	$ret=array();
	list($h, $m, $s) = explode(':', substr($time,0,8));
	$ret[0]=($h * 3600) + ($m * 60) + $s;
	$ret[1]=intval(substr($time,9));
	return $ret;
}

## main entry

function main(){
	global $argv;
	// process command line arguments
	if (!isset($argv[1]) || !file_exists($argv[1])) usage("Missing input file\n");
	if (!isset($argv[2])) usage("Missing output file name\n");

	$infd= fopen($argv[1],"r");
	if ($infd===FALSE){
		die("Error opening input file $argv[1]");
	}

	$pcap = new pcap_file_writer();
	if (($pcap->open($argv[2]))===FALSE){
		die("Error creating output file $argv[2]");
	}

	// initialize variables
	$head=[
		"version_major"=> 2,
		"version_minor"=> 4,
		"thiszone"=> 0,
		"sigfigs"=> 0,
		"snaplen"=> 65535,
		"network"=> 1
	];
	$pcap->write_global_header($head);
	$pkt=array();
	$pkt['data']='';
	$lineno=0;
	$ts=array(0,0);

	// process input text line 
	while(!feof($infd)) {
		##14:38:05.356054 000000 45 00 05 DC CB DB ...
		$line=fgets($infd);
		$lineno++;
		if (strlen($line)<8){
			continue;
		}

		//search for timestamp string, in the format of HH:MM:SS.uuuuuu
		if (preg_match('/^[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{1,}/', $line,$matches)==1){
			$ts=str_to_sec_usec($matches[0]);
		}else{
			$ts=array(0,0);
		}

		$pos=strpos($line," 000");
		if ($pos===FALSE){
			die("Error invalid line $lineno: --$line--\n");
		}

		//read in data offset 
		sscanf(substr($line,$pos+1),"%x",$offset);
		//printf("offset pos=%08x, offset=%08x\n",$pos,$offset);
		if ($offset==0){
			//write packet if any
			if (strlen($pkt['data'])>0){
				$pkt['ts_sec']=$ts[0];
				$pkt['ts_usec']=$ts[1];
				$pkt['incl_len']=strlen($pkt['data']);
				$pkt['orig_len']=$pkt['incl_len'];
				$pcap->write_packet($pkt);
			}
			$newpacket=true;
			$pkt['data']=hex2bin('2052454356002053454e44000800');
			$bytes_read=0;
		}else{
			if ($offset!=$bytes_read){
				printf("Error line:$lineno  offset $offset doesn't match bytes_read $bytes_read\n");
				continue;
			}
		}
		//read in data
		if (preg_match('/( [[:xdigit:]]{2})+[ \r\n\t]/', $line,$matches,0,$pos)==1){
			$data_str=str_replace(' ','',trim($matches[0]));
			$data_bin=hex2bin($data_str);
			$pkt['data'].=$data_bin;
			$bytes_read+=strlen($data_bin);
		}
	}

	//write the last packet
	if (strlen($pkt['data'])>0){
		$pkt['ts_sec']=$ts[0];
		$pkt['ts_usec']=$ts[1];
		$pkt['incl_len']=strlen($pkt['data']);
		$pkt['orig_len']=$pkt['incl_len'];
		$pcap->write_packet($pkt);
	}

	fclose($infd);
	$pcap->close();
}

main();
