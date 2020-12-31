<?php
	require_once($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi_se.php");
	session_start();
	if (isset($_SESSION)){
		session_destroy();
	}
	session_write_close();
	header("Location: /");
?>