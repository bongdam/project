<?php
	function listFolders($dir)
	{
		$dh = scandir($dir);
		$return = array();

		foreach ($dh as $folder) {
			if ($folder != '.' && $folder != '..') {
				if (is_dir($dir . '/' . $folder)) {
					$return[] = array($folder => listFolders($dir . '/' . $folder));  
				}
			}
		}
		return $return;
	}
	print_r(listFolders("files/usbdisk1"));
	print_r(exec("df -h /dev/sda1"));
?>