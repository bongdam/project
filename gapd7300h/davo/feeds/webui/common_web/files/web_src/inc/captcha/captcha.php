<?php
	$image = @imagecreatetruecolor(120, 30) or die("Cannot Initialize new GD image stream");

  // set background to white and allocate drawing colours
  $background = imagecolorallocate($image, 0xFF, 0xFF, 0xFF);
  imagefill($image, 0, 0, $background);
  $linecolor = imagecolorallocate($image, 0xCC, 0xCC, 0xCC);
  $textcolor = imagecolorallocate($image, 0x33, 0x33, 0x33);

  // draw random lines on canvas
  for($i=0; $i < 6; $i++) {
    imagesetthickness($image, rand(1,3));
    imageline($image, 0, rand(0,30), 120, rand(0,30), $linecolor);
  }

  session_start();

  // add random digits to canvas
  $char = Array(0,1,2,3,4,5,6,7,8,9,'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','W','X','Y','Z');
  $digit = '';
  for($x = 15; $x <= 95; $x += 20) {
//    $digit .= ($num = rand(0, 9));
	$digit .= ($num = $char[rand(0, (count($char)-1))]);
//    imagechar($image, rand(4, 5), $x, rand(4, 14), $num, $textcolor);
//	imagechar($image, 5, $x, rand(4, 14), $num, $textcolor);
	imagettftext($image,12,rand(4, 14),$x,rand(18,25),$textcolor,"times_new_yorker.ttf",$num);
  }

  // record digits in session variable
  $_SESSION['digit'] = $digit;

  // display image and clean up
  header('Content-type: image/png');
  imagepng($image);
  imagedestroy($image);
?>