<?php
	require($_SERVER['DOCUMENT_ROOT']."/inc/default_ssi.php");
//ini_set('post_max_size', '1024M');
//ini_set('upload_max_filesize', '1024M');
//echo ini_get('upload_tmp_dir');
//ini_set('upload_tmp_dir', '/tmp/mount');
//echo ini_get('upload_tmp_dir');
/********************************
Simple PHP File Manager
Copyright John Campbell (jcampbell1)

Liscense: MIT
********************************/

//Disable error report for undefined superglobals
error_reporting( error_reporting() & ~E_NOTICE );
//Security options
$allow_delete = true; // Set to false to disable delete button and delete POST request.
$allow_create_folder = true; // Set to false to disable folder creation
$allow_upload = true; // Set to true to allow upload files
$allow_direct_link = true; // Set to false to only allow downloads and not direct link
if( dv_session("wb_permit") == "0"){
	$allow_delete = false; // Set to false to disable delete button and delete POST request.
	$allow_create_folder = false; // Set to false to disable folder creation
	$allow_upload = false; // Set to true to allow upload files
}

/* Uncomment section below, if you want a trivial password protection */

/*
$PASSWORD = 'sfm'; 
session_start();
if(!$_SESSION['_sfm_allowed']) {
	// sha1, and random bytes to thwart timing attacks.  Not meant as secure hashing.
	$t = bin2hex(openssl_random_pseudo_bytes(10));	
	if($_POST['p'] && sha1($t.$_POST['p']) === sha1($t.$PASSWORD)) {
		$_SESSION['_sfm_allowed'] = true;
		header('Location: ?');
	}
	echo '<html><body><form action=? method=post>PASSWORD:<input type=password name=p /></form></body></html>'; 
	exit;
}
*/

// must be in UTF-8 or `basename` doesn't work
setlocale(LC_ALL,'ko-KR.UTF-8');

$tmp = realpath($_REQUEST['file']);
if($tmp === false)
	err(404,'File or Directory Not Found');
//if(substr($tmp, 0,strlen(__DIR__)) !== __DIR__)
//	err(403,"Forbidden".__DIR__);

if(!$_COOKIE['_sfm_xsrf'])
	setcookie('_sfm_xsrf',bin2hex(openssl_random_pseudo_bytes(16)));
if($_POST) {
	if($_COOKIE['_sfm_xsrf'] !== $_POST['xsrf'] || !$_POST['xsrf'])
		err(403,"XSRF Failure");
}

$file = $_REQUEST['file'] ?: './files';

if($_GET['do'] == 'list') {
	if(strpos($file,"files") === false){
		err(404,"Page not found");
	}
	if (is_dir($file)) {
		$directory = $file;
		$result = array();
		$files = array_diff(scandir($directory), array('.','..'));
	    foreach($files as $entry) if($entry !== basename(__FILE__)) {
    		$i = $directory . '/' . $entry;
			$out = null;
	    	$stat = stat($i);
			$filesize = filesize($i);
			$flag = 0;
			if($filesize < 0){
				exec("stat -c %s ".$i,$out);
				$filesize = $out[0];
				$flag = 1;
				if($filesize === null){
					$filesize = sprintf('%u', filesize($i));
				}
				$flag = 1;
			}elseif($filesize > 10000000){
				exec("stat -c %s ".$i,$out);
				$filesize = $out[0];
				$flag = 2;
				if($filesize === null){
					$filesize = sprintf("%u",$stat["blocks"]) * 512;
				}
			}
	        $result[] = array(
				'flag'=> $flag,
				'ddd'		=> $out,
				'realpath' => $i,
				'realsize' =>filesize($i),
	        	'mtime' => $stat['mtime'],
	        	'size' => $filesize,
	        	'name' => $entry,
//				'mime'	=> mime_content_type ($entry),
	        	'path' => preg_replace('@^\./@', '', $i),
	        	'is_dir' => is_dir($i),
	        	'is_deleteable' => $allow_delete && ((!is_dir($i) && is_writable($directory)) ||
                                                           (is_dir($i) && is_writable($directory) && is_recursively_deleteable($i))),
	        	'is_readable' => is_readable($i),
	        	'is_writable' => is_writable($i),
	        	'is_executable' => is_executable($i),
	        );
	    }
	} else {
		err(412,"Not a Directory");
	}
	echo json_encode(array('success' => true, 'is_writable' => is_writable($file), 'results' =>$result));
	exit;
} elseif ($_POST['do'] == 'delete') {
	if($allow_delete) {
		rmrf($file);
	}
	exit;
} elseif ($_POST['do'] == 'mkdir' && $allow_create_folder== true) {
	// don't allow actions outside root. we also filter out slashes to catch args like './../outside'
	$dir = $_POST['name'];
	$dir = str_replace('/', '', $dir);
	if(substr($dir, 0, 2) === '..')
	    exit;
	chdir($file);
	@mkdir($_POST['name']);
	exit;
} elseif ($_POST['do'] == 'upload' && $allow_upload == true) {
	var_dump($_POST);
	var_dump($_FILES);
	var_dump($_FILES['file_data']['tmp_name']);
	var_dump(move_uploaded_file($_FILES['file_data']['tmp_name'], $file.'/'.$_FILES['file_data']['name']));
	exit;
} elseif ($_GET['do'] == 'download') {
//	$filename = basename($file);
//	$filesize = filesize($file);
//	if($filesize < 0){
//		$filesize = exec("stat -c %s ".$file);
//	}elseif($filesize > 1000000){
//		$filesize = exec("stat -c %s ".$file);
//	}
//	header('Content-Type: ' . mime_content_type($file));
//	header('Content-Length: '. $filesize);
//	header(sprintf('Content-Disposition: attachment; filename=%s',
//		strpos('MSIE',$_SERVER['HTTP_REFERER']) ? rawurlencode($filename) : "\"$filename\"" ));
//	ob_flush();
//	readfile($file);
	$filepath = $file;
	$filesize = filesize($filepath);
	$filename = mb_basename($filepath);
	if( is_ie() ) $filename = utf2euc($filename);
//	if($filesize < 0){
//		$filesize = exec("stat -c %s ".$file);
//	}elseif($filesize > 1000000){
//		$filesize = exec("stat -c %s ".$file);
//	}
	header("Pragma: public");
	header("Expires: 0");
	header("Content-Type: application/octet-stream");
	header("Content-Disposition: attachment; filename=\"$filename\"");
	header("Content-Transfer-Encoding: binary");
	header("Content-Length: $filesize");
//	set_time_limit(0);
//	ini_set("max_input_time",1000);
//	ini_set("memory_limit","1000M");
//	ini_set("max_execution_time",240);
//	ini_set("post_max_size","6000M");
	readfile($filepath);
//	$chunksize = 1 * (1024 * 1024); // how many bytes per chunk
//	if ($filesize > $chunksize) {
//		$handle = fopen($filepath, 'rb');
//		$buffer = '';
//		while (!feof($handle)) {
//			$buffer = fread($handle, $chunksize);
//			echo $buffer;
//			ob_flush();
//			flush();
//		}
//		fclose($handle);
//	} else {
//		readfile($filepath);
//	}
//	
	
	exit;
}
function rmrf($dir) {
	if(is_dir($dir)) {
		$files = array_diff(scandir($dir), array('.','..'));
		foreach ($files as $file)
			rmrf("$dir/$file");
		rmdir($dir);
	} else {
		unlink($dir);
	}
}
function is_recursively_deleteable($d) {
	$stack = array($d);
	while($dir = array_pop($stack)) {
		if(!is_readable($dir) || !is_writable($dir)) 
			return false;
		$files = array_diff(scandir($dir), array('.','..'));
		foreach($files as $file) if(is_dir($file)) {
			$stack[] = "$dir/$file";
		}
	}
	return true;
}

function err($code,$msg) {
	echo json_encode(array('error' => array('code'=>intval($code), 'msg' => $msg)));
	exit;
}

function asBytes($ini_v) {
	$ini_v = trim($ini_v);
	$s = array('g'=> 1<<30, 'm' => 1<<20, 'k' => 1<<10);
	return intval($ini_v) * ($s[strtolower(substr($ini_v,-1))] ?: 1);
}
$MAX_UPLOAD_SIZE = min(asBytes(ini_get('post_max_size')), asBytes(ini_get('upload_max_filesize')));
//echo $MAX_UPLOAD_SIZE;
//echo ini_get("upload_tmp_dir");
?>
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style type="text/css">
@import url(inc/css/file.css);
@import url(inc/css/font-awesome.min.css);
</style>
<script type="text/javascript" src="inc/js/jquery-1.8.3.min.js"></script>
<script type="text/javascript" src="inc/js/modal/remodal.min.js"></script>
<link href="inc/js/modal/remodal.css" rel="stylesheet" type="text/css">
<link href="inc/js/modal/remodal-default-theme.css" rel="stylesheet" type="text/css">
<script type="text/javascript">
var model = null;
(function($){
	$.fn.tablesorter = function() {
		var $table = this;
		this.find('th').click(function() {
			var idx = $(this).index();
			var direction = $(this).hasClass('sort_asc');
			$table.tablesortby(idx,direction);
		});
		return this;
	};
	$.fn.tablesortby = function(idx,direction) {
		var $rows = this.find('tbody tr');
		function elementToVal(a) {
			var $a_elem = $(a).find('td:nth-child('+(idx+1)+')');
			var a_val = $a_elem.attr('data-sort') || $a_elem.text();
			return (a_val == parseInt(a_val) ? parseInt(a_val) : a_val);
		}
		$rows.sort(function(a,b){
			var a_val = elementToVal(a), b_val = elementToVal(b);
			return (a_val > b_val ? 1 : (a_val == b_val ? 0 : -1)) * (direction ? 1 : -1);
		})
		this.find('th').removeClass('sort_asc sort_desc');
		$(this).find('thead th:nth-child('+(idx+1)+')').addClass(direction ? 'sort_desc' : 'sort_asc');
		for(var i =0;i<$rows.length;i++)
			this.append($rows[i]);
		this.settablesortmarkers();
		return this;
	}
	$.fn.retablesort = function() {
		var $e = this.find('thead th.sort_asc, thead th.sort_desc');
		if($e.length)
			this.tablesortby($e.index(), $e.hasClass('sort_desc') );
		
		return this;
	}
	$.fn.settablesortmarkers = function() {
		this.find('thead th span.indicator').remove();
		this.find('thead th.sort_asc').append('<span class="indicator">&darr;<span>');
		this.find('thead th.sort_desc').append('<span class="indicator">&uarr;<span>');
		return this;
	}
})(jQuery);
$(function(){
	var XSRF = (document.cookie.match('(^|; )_sfm_xsrf=([^;]*)')||0)[2];
	var MAX_UPLOAD_SIZE = <?php echo $MAX_UPLOAD_SIZE ?>;
	var $tbody = $('#list');
	$(window).bind('hashchange',list).trigger('hashchange');
	$('#table').tablesorter();
	
	$('.delete').live('click',function(data) {
		$.post("",{'do':'delete',file:$(this).attr('data-file'),xsrf:XSRF},function(response){
			list();
		},'json');
		return false;
	});

	$('#mkdir').submit(function(e) {
		var hashval = window.location.hash.substr(1),
			$dir = $(this).find('[name=name]');
		e.preventDefault();
		$dir.val().length && $.post('?',{'do':'mkdir',name:$dir.val(),xsrf:XSRF,file:hashval},function(data){
			list();
		},'json');
		$dir.val('');
		view_create_folder();
		return false;
	});
<?php if($allow_upload == true): ?>
	// file upload stuff
	$('#file_drop_target').bind('dragover',function(){
		$(this).addClass('drag_over');
		return false;
	}).bind('dragend',function(){
		$(this).removeClass('drag_over');
		return false;
	}).bind('drop',function(e){
		e.preventDefault();
		var files = e.originalEvent.dataTransfer.files;
		$.each(files,function(k,file) {
			uploadFile(file);
		});
		$(this).removeClass('drag_over');
	});
	$('input[type=file]').change(function(e) {
		e.preventDefault();
		$.each(this.files,function(k,file) {
			uploadFile(file);
		});
	});


	function uploadFile(file) {
		var folder = window.location.hash.substr(1);

		if(file.size > MAX_UPLOAD_SIZE) {
			var $error_row = renderFileSizeErrorRow(file,folder);
			$('#upload_progress').append($error_row);
			window.setTimeout(function(){$error_row.fadeOut();},5000);
			return false;
		}
		
		var $row = renderFileUploadRow(file,folder);
		$('#upload_progress').append($row);
		var fd = new FormData();
		fd.append('file_data',file);
		fd.append('file',folder);
		fd.append('xsrf',XSRF);
		fd.append('do','upload');
		var xhr = new XMLHttpRequest();
		xhr.open('POST', '?');
		xhr.onload = function() {
			$row.remove();
    		list();
  		};
		xhr.upload.onprogress = function(e){
			if(e.lengthComputable) {
				$row.find('.progress').css('width',(e.loaded/e.total*100 | 0)+'%' );
			}
		};
	    xhr.send(fd);
	}
	function renderFileUploadRow(file,folder) {
		return $row = $('<div/>')
			.append( $('<span class="fileuploadname" />').text( (folder ? folder+'/':'')+file.name))
			.append( $('<div class="progress_track"><div class="progress"></div></div>')  )
			.append( $('<span class="size" />').text(formatFileSize(file.size)) )
	};
	function renderFileSizeErrorRow(file,folder) {
		return $row = $('<div class="error" />')
			.append( $('<span class="fileuploadname" />').text( 'Error: ' + (folder ? folder+'/':'')+file.name))
			.append( $('<span/>').html(' file size - <b>' + formatFileSize(file.size) + '</b>'
				+' exceeds max upload size of <b>' + formatFileSize(MAX_UPLOAD_SIZE) + '</b>')  );
	}
<?php endif; ?>
	function list() {
		var hashval = window.location.hash.substr(1);
		$.get('?',{'do':'list','file':hashval},function(data) {
			$tbody.empty();
//			console.log(hashval);
			$('#breadcrumb').empty().html(renderBreadcrumbs(hashval));
			if(data.success) {
				$.each(data.results,function(k,v){
//					console.log(k,v);
					if(v.is_dir == true){
						$tbody.append(renderFileRow(v));
					}
				});
				$.each(data.results,function(k,v){
//					console.log(k,v);
					if(v.is_dir == false){
						$tbody.append(renderFileRow(v));
					}
				});
				!data.results.length && $tbody.append('<tr><td class="empty" colspan=5>This folder is empty</td></tr>')
				data.is_writable ? $('body').removeClass('no_write') : $('body').addClass('no_write');
			} else {
				console.warn(data.error.msg);
			}
			$('#table').retablesort();
		},'json');
	}
	var movieext = Array(".mp4",".avi",".mov");
	function renderFileRow(data) {
		if(data.is_dir == true){
			var $link = $('<a class="name" />')
				.attr('href', data.is_dir ? '#' + data.path : './'+data.path)
				.append('<i class="fa fa-folder" aria-hidden="true"></i>&nbsp;&nbsp;'+data.name);
		}else{
//			console.log(getExtensionOfFilename(data.name));
			if(movieext.indexOf(getExtensionOfFilename(data.name)) == -1){
				if(parseInt(data.size,10) > 2147483647){
					var $link = $('<a class="name" />')
						.attr('href', encodeURIComponent(data.path)).attr("target","_blank").attr("download",data.name)
						.append('<i class="fa fa-file-o" aria-hidden="true"></i>&nbsp;&nbsp;'+data.name);
				}else{
					var $link = $('<a class="name" />')
						.attr('href', data.is_dir ? '#' + data.path : '?do=download&file='+encodeURIComponent(data.path))
						.append('<i class="fa fa-file-o" aria-hidden="true"></i>&nbsp;&nbsp;'+data.name);
				}
			}else{
				var $link = $('<a class="name" />')
					.attr('href',"javascript:view_movie('"+data.path+"')")
					.append('<i class="fa fa-file-o" aria-hidden="true"></i>&nbsp;&nbsp;'+data.name);
			}
		}
		var allow_direct_link = <?php echo $allow_direct_link?'true':'false'; ?>;
        	if (!data.is_dir && !allow_direct_link)  $link.css('pointer-events','none');
//		var $dl_link = $('<a/>').attr('href','?do=download&file='+encodeURIComponent(data.path))
//			.addClass('download').text('down');
		if(parseInt(data.size,10) > 2147483647){
			var $dl_link = $('<a/>').attr('href',''+encodeURIComponent(data.path)).append('&nbsp;<i class="fa fa-download" aria-hidden="true"></i>').attr("target","_blank").attr("download",data.name);
		}else{
			var $dl_link = $('<a/>').attr('href','?do=download&file='+encodeURIComponent(data.path)).append('&nbsp;<i class="fa fa-download" aria-hidden="true"></i>');
		}
//		var $delete_link = $('<a href="#" />').attr('data-file',data.path).addClass('delete').append('<i class="fa fa-trash" aria-hidden="true"></i>');
		var $delete_link = $('<a href="#" />').attr('data-file',data.path).addClass('delete').append('&nbsp;&nbsp;&nbsp;<i class="fa fa-trash" aria-hidden="true"></i>');
		var perms = [];
		if(data.is_readable) perms.push('read');
		if(data.is_writable) perms.push('write');
		if(data.is_executable) perms.push('exec');
		var $html = $('<tr />')
			.addClass(data.is_dir ? 'is_dir' : '')
			.append( $('<td class="first" />').append($link) )
			.append( $('<td/>').attr('data-sort',data.is_dir ? -1 : data.size)
				.html($('<span class="size" />').text(formatFileSize(data.size))) ) 
			.append( $('<td/>').attr('data-sort',data.mtime).text(formatTimestamp(data.mtime)) )
			.append( $('<td/>').text(perms.join('+')) )
			.append( $('<td/>').append(data.is_dir ? "" : $dl_link).append( data.is_deleteable ? $delete_link : '') )
		return $html;
	}
	function renderBreadcrumbs(path) {
		var base = "",
			$html = $('<div/>').append( $('<a href=#>Home</a></div>') );
		path = path.replace("files","");
		$.each(path.split('/'),function(k,v){
			if(v) {
				$html.append( $('<span/>').text(' ▸ ') )
					.append( $('<a/>').attr('href','#'+"files/"+base+v).text(v) );
				base += v + '/';
			}
		});
		return $html;
	}
	function formatTimestamp(unix_timestamp) {
		var m = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
		var d = new Date(unix_timestamp*1000);
		return [m[d.getMonth()],' ',d.getDate(),', ',d.getFullYear()," ",
			(d.getHours() % 12 || 12),":",(d.getMinutes() < 10 ? '0' : '')+d.getMinutes(),
			" ",d.getHours() >= 12 ? 'PM' : 'AM'].join('');
	}
	function formatFileSize(bytes) {
//		console.log(bytes);
		var s = ['bytes', 'KB','MB','GB','TB','PB','EB'];
		for(var pos = 0;bytes >= 1000; pos++,bytes /= 1024);
		var d = Math.round(bytes*10);
		return pos ? [parseInt(d/10),".",d%10," ",s[pos]].join('') : bytes + ' bytes';
	}
})
var view_create_folder = function(){
	if($("#mkdir_div").css("display") == "none"){
		$("#mkdir_div").show();
	}else{
		$("#mkdir_div").hide();
	}
}
function getExtensionOfFilename(filename) {

	var _fileLen = filename.length;

	/** 
	 * lastIndexOf('.') 
	 * 뒤에서부터 '.'의 위치를 찾기위한 함수
	 * 검색 문자의 위치를 반환한다.
	 * 파일 이름에 '.'이 포함되는 경우가 있기 때문에 lastIndexOf() 사용
	 */
	var _lastDot = filename.lastIndexOf('.');

	// 확장자 명만 추출한 후 소문자로 변경
	var _fileExt = filename.substring(_lastDot, _fileLen).toLowerCase();

	return _fileExt;
}
var view_movie = function(path_){
//	$("#movie_div").show();
	$("#mvdiv").children().remove();
	$("#mvdiv").append("<source src=\""+path_+"\" type=\"video/mp4\">");
	document.getElementById("mvdiv").load();
	 model.open();
}
var close_movie =function(){
	$("#movie_div").hide();
	document.getElementById("mvdiv").pause();
}
var logout = function(){
	window.location.assign("logout.php");
}
$(document).ready(function(){
	$(document).on('closed', '[data-remodal-id=modal]', function () {
	//		console.log('Confirmation button is clicked');
	document.getElementById("mvdiv").pause();
		
	});
});
</script>
</head><body>
<div id="top">
   <?php if($allow_upload == true): ?>

	<div id="file_drop_target">
		Drag Files Here To Upload
		<b>or</b>
		<input type="file" multiple />
	</div>
   <?php endif; ?>
	<div id="breadcrumb">&nbsp;</div>
</div>

<div id="upload_progress"></div>
<table id="table">
	<thead>
		<tr>
			<th>Name</th>
			<th>Size</th>
			<th>Modified</th>
			<th>Permissions</th>
			<th>Actions</th>
		</tr>
	</thead>
	<tbody id="list"></tbody>
</table>
<br>
<i class="fa fa-sign-out" aria-hidden="true" style="font-size:32px;cursor:pointer;" onclick="logout();"></i>
<?php if($allow_upload == true): ?>
<i class="fa fa-pencil-square-o" aria-hidden="true" style="font-size:32px;cursor:pointer;" onclick="view_create_folder();"></i>

<div id="mkdir_div">
	
	<form action="?" method="post" id="mkdir" />
		<label for=dirname>Create New Folder</label><input id=dirname type=text name=name value="" />
		<input type="submit" value="create" />
	</form>

	
</div>
<?php endif; ?>
<!-- <div id="movie_div"> -->
<!-- <button onclick="close_movie();">Close</button> -->
<!-- <video width="320" height="240" id="mvdiv" controls autoplay></video> -->
<!-- </div> -->
<div class="remodal" data-remodal-id="modal" role="dialog" aria-labelledby="modal1Title" aria-describedby="modal1Desc">
	<button data-remodal-action="close" class="remodal-close" aria-label="Close"></button>
	<div>
		<video style="width:95%;height:95%;" id="mvdiv" controls autoplay></video>
	</div>
	<br>
	<button data-remodal-action="cancel" class="remodal-cancel">닫기</button>
</div>
<script type="text/javascript">
model = $('[data-remodal-id=modal]').remodal({closeOnConfirm: false,closeOnOutsideClick:false,closeOnEscape:false,hashTracking:false});
</script>
</body></html>
