var window_referrer = document.referrer;
var xss_err_msg = "위험요소의 문자열이 있습니다. (Ex : HTML TAG, XSS공격 문구)";
jQuery.cookie = function (key, value, options) {

    // key and value given, set cookie...
    if (arguments.length > 1 && (value === null || typeof value !== "object")) {
        options = jQuery.extend({}, options);

        if (value === null) {
            options.expires = -1;
        }

        if (typeof options.expires === 'number') {
            var days = options.expires, t = options.expires = new Date();
            t.setDate(t.getDate() + days);
        }

        return (document.cookie = [
            encodeURIComponent(key), '=',
            options.raw ? String(value) : encodeURIComponent(String(value)),
            options.expires ? '; expires=' + options.expires.toUTCString() : '', // use expires attribute, max-age is not supported by IE
            options.path ? '; path=' + options.path : '',
            options.domain ? '; domain=' + options.domain : '',
            options.secure ? '; secure' : ''
        ].join(''));
    }

    // key and possibly options given, get cookie...
    options = value || {};
    var result, decode = options.raw ? function (s) { return s; } : decodeURIComponent;
    return (result = new RegExp('(?:^|; )' + encodeURIComponent(key) + '=([^;]*)').exec(document.cookie)) ? decode(result[1]) : null;
};

window.alert = function(al, $){
	return function(msg) {
		al(msg);
		$(window).trigger("okbuttonclicked");
	};
}(window.alert, window.jQuery);

$(window).on("okbuttonclicked", function() {
	$.cookie("magickey",parseInt(get_timestamp(),10));
//    console.log("you clicked ok");
});
String.prototype.ip_check = function(mask_){
	var ip = this;
	var ip2  = mask_;
	var ip_arr = ip.split('.');
	var ip_int = 0;
	var ip_int2 = 0;
	ip_int = ((((((+ip_arr[0])*256)+(+ip_arr[1]))*256)+(+ip_arr[2]))*256)+(+ip_arr[3]);
	var ip_arr2 = ip2.split('.');
	ip_int2 = ((((((+ip_arr2[0])*256)+(+ip_arr2[1]))*256)+(+ip_arr2[2]))*256)+(+ip_arr2[3]);
	var ipand = Number(ip_int & ip_int2);
	var ipint = ipand < 0 ? Math.ceil(ipand) : Math.floor(ipand);
	var unsign = Math.pow(2, 32);
	var num = ipint - Math.floor(ipint/unsign)*unsign;

	var d = num%256;
	for (var i = 3; i > 0; i--) 
	{ 
		num = Math.floor(num/256);
		d = num%256 + '.' + d;
	}
	return d;
};
Date.prototype.yyyymmdd = function() {
  var mm = this.getMonth() + 1; // getMonth() is zero-based
  var dd = this.getDate();

  return [this.getFullYear(),"-",
          (mm>9 ? '' : '0') + mm,"-",
          (dd>9 ? '' : '0') + dd
         ].join('');
};
Date.prototype.hhmmss = function() {
	var hh = this.getHours();
	var mm = this.getMinutes();
	var ss = this.getSeconds();

	return [
		(hh>9 ? '' : '0') + hh,":",
		(mm>9 ? '' : '0') + mm,":",
		(ss>9 ? '' : '0') + ss
	].join('');
};
String.prototype.trim = function(str) {
	str = this != window ? this : str;
	return str.replace(/^\s+/g,'').replace(/\s+$/g,'');
};
var check_ip_du_band = function(ip1_,mask1_, ip2_, mask2_){
	var mask = mask1_.ip_check(mask2_);
	var ip1 = ip1_.ip_check(mask);
	var ip2 = ip2_.ip_check(mask);
	if (ip1 == ip2)
	{
		return true;
	}else{
		return false;
	}
}
var CreateDummy = function(){
	var DummyVal ="";
	var now = new Date();
	DummyVal = now.getFullYear().toString()+now.getMonth().toString()+now.getDate().toString()+convert_two_digit(now.getHours()).toString()+convert_two_digit(now.getMinutes()).toString()+convert_two_digit(now.getSeconds()).toString()+convert_three_digit(now.getMilliseconds()).toString();
	return DummyVal;
};
var loadScript = function(url, callback)
{
	var head = document.getElementsByTagName('head')[0];
	var script = document.createElement('script');
	script.type = 'text/javascript';
	script.src = url;
	script.onreadystatechange = callback;
	script.onload = callback;
	head.appendChild(script);
}
var get_obj_val = function(obj_, key_, default_){
	if(typeof(obj_) == "object") {
		if( obj_[key_] != undefined){
			return obj_[key_];
		}else{
//			console.log("get_object_val","not found keys.",key_);
			if(default_ == undefined){
				return "";
			}else{
				return default_;
			}
		}
	}else{
//		console.log("get_object_val","not object");
		return "";
	}
}
var get_json_val = function(obj_, key_, default_){
	var def = default_ != undefined ? default_ : "";
	var arrkey = key_.split(".");
	if(typeof(obj_) == "object") {
		switch(arrkey.length){
			case 1:
				if(obj_[arrkey[0]] == undefined){
					return def;
				}
				return obj_[arrkey[0]];
				break;
			case 2:
				if(obj_[arrkey[0]] == undefined){
					return def;
				}
				if(obj_[arrkey[0]][arrkey[1]] == undefined){
					return def;
				}
				return obj_[arrkey[0]][arrkey[1]];
				break;
			case 3:
				if(obj_[arrkey[0]] == undefined){
					return def;
				}
				if(obj_[arrkey[0]][arrkey[1]] == undefined){
					return def;
				}
				if(obj_[arrkey[0]][arrkey[1]][arrkey[2]] == undefined){
					return def;
				}
				return obj_[arrkey[0]][arrkey[1]][arrkey[2]];
				break;
		}
	}
}
function ip_to_int(dot) 
{
	var d = dot.split('.');
	return ((((((+d[0])*256)+(+d[1]))*256)+(+d[2]))*256)+(+d[3]);
}

function int_to_ip(num) 
{
	var d = num%256;
	for (var i = 3; i > 0; i--) 
	{ 
		num = Math.floor(num/256);
		d = num%256 + '.' + d;
	}
	return d;
}
function calc_netmask_for_bits(subnet_)
{
	var s = subnet_ ? subnet_ : "";
	var thisSegment = null;

	var ipArray = s.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	if (ipArray == null){
		return -1;
	}else{
		for (i = 0; i < 5; i++)
		{
			thisSegment = ipArray[i];
			if (thisSegment > 255)
			{
				i = 5;
				return -1;
			}  
			if ((i == 1) && (thisSegment < 0))
			{
				i = 5;
				return -1;
			}
		}
	}
	var sumofbits=0;
	var bitsfromleft = null;
	tmpvar = parseInt(ipArray[1],10);
	if (isNaN(tmpvar)){
		return -1;
	}
	bitsfromleft=count_bit_from_left(tmpvar);
	if (isNaN(bitsfromleft)){
		return -1;
	}
	sumofbits+=bitsfromleft;
	//
	tmpvar = parseInt(ipArray[2],10);
	if (isNaN(tmpvar)){
		return -1;
	}
	bitsfromleft=count_bit_from_left(tmpvar);
	if (isNaN(bitsfromleft)){
		return -1;
	}
	sumofbits+=bitsfromleft;
	tmpvar = parseInt(ipArray[3],10);
	if (isNaN(tmpvar)){
		return -1;
	}
	bitsfromleft=count_bit_from_left(tmpvar);
	if (isNaN(bitsfromleft)){
		return -1;
	}
	sumofbits+=bitsfromleft;
	//
	tmpvar = parseInt(ipArray[4],10);
	if (isNaN(tmpvar)){
		return -1;
	}
	bitsfromleft=count_bit_from_left(tmpvar);
	if (isNaN(bitsfromleft)){
		return -1;
	}
	sumofbits+=bitsfromleft;
	return sumofbits;
}
var ipCheck = function(ip_,zeroflag_, final_){
	var IPvalue = ip_;
	var errorString = "";
	var fi = final_ ? final_ : "";
	var theName = "IPaddress";
	var i = 0;
	var zeroflag_ = zeroflag_ ? zeroflag_ : "";
	if (zeroflag_ != "")
	{
		if(IPvalue == "0.0.0.0"){
			return false;
		}
	}

	var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
	var ipArray = IPvalue.match(ipPattern);
	if (IPvalue == "255.255.255.255"){
		errorString = errorString + theName;
	}
	if (ipArray == null){
		errorString = errorString + theName;
	}else{
		for (i = 0; i < 5; i++)
		{
			thisSegment = ipArray[i];

			if (thisSegment > 255)
			{
				errorString = errorString + theName;
				i = 5;
			}

			if ((i == 1) && (thisSegment < 0))
			{
				errorString = errorString + theName;
				i = 5;
			}
		}
	}
	if(errorString == ""){
		if(IPvalue.split(".")[3] == "255"){
			errorString = "error";
		}
	}
	if(fi != ""){
		if(errorString == ""){
			if(IPvalue.split(".")[3] == "0"){
				errorString = "error";
			}
		}
	}
	if (!(errorString ==""))
	{
		return false;
	}else{
		return true;
	}
};
var maskCheck = function(mask_){
	var MASKvalue = mask_;
	var mask_0_bit = false;
	var ret = true;
	var maskPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
	var maskArray = MASKvalue.match(maskPattern);
	var temp_val;

//	alert(mask_);
	if (maskArray == null){
		ret = false;
	}else{
		for (i = 1; i < 5; i++)
		{
//			alert("mask_"+i+"="+maskArray[i]);
			if (maskArray[i] < 0 || maskArray[i] > 0xFF) {
//					alert("error1");
					ret = false;
					break;
			}
			temp_val = maskArray[i];
	        for (j=0 ; j < 8; j++ ) {
                if ( (temp_val << j) & 0x80 ) {
					if ( mask_0_bit ) {
//						alert("error2."+i+"."+j);
						ret = false;
						break;
					}
                } else {
					mask_0_bit = true;
                }
            }

		}
	}
	return ret;
};
var ipv6Check = function(ip_){
	var IPvalue = ip_;
	errorString = "";
	theName = "IPaddress";
	var ipPattern = /^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i;
	var ipArray = IPvalue.match(ipPattern);
	if (IPvalue == "255.255.255.255" || IPvalue == "::" || IPvalue == "::0" ){
		errorString = errorString + theName;
		return false;
	}

	if (ipArray == null){
		errorString = errorString + theName;
		return false;
	}else{
		return true;
	}
};
var isURL = function(str_, prefix_) {
	var prefix = prefix_ ? prefix_ : "";
	if (prefix == "none")
	{
		str_ = "http://"+str_;
	}
	var urlRegex = '^(?!mailto:)(?:(?:http|https|ftp)://)(?:\\S+(?::\\S*)?@)?(?:(?:(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}(?:\\.(?:[0-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))|(?:(?:[a-z\\u00a1-\\uffff0-9]+-?)*[a-z\\u00a1-\\uffff0-9]+)(?:\\.(?:[a-z\\u00a1-\\uffff0-9]+-?)*[a-z\\u00a1-\\uffff0-9]+)*(?:\\.(?:[a-z\\u00a1-\\uffff]{2,})))|localhost)(?::\\d{2,5})?(?:(/|\\?|#)[^\\s]*)?$';
	var url = new RegExp(urlRegex, 'i');
	return str_.length < 2083 && url.test(str_);
}
var validation_mac = function(val_){
	var mac = val_ ? val_ : false;
	if(mac){
		var reg = /^([0-9|a-f]{2,2}):([0-9|a-f]{2,2}):([0-9|a-f]{2,2}):([0-9|a-f]{2,2}):([0-9|a-f]{2,2}):([0-9|a-f]{2,2})/gi;
		var result = reg.test(mac);
		if(result == true){
			var tmp = mac.split(":");
			var cols = tmp[0];
			var bindata = parseInt(cols, 16).toString(2);
			if(bindata.substring(bindata.length-2) == "00" || bindata.substring(bindata.length-2) == "0"){
				return true;
			}else{
				return false;
			}
		}else{
			return false;
		}
	}else{
		return false;
	}
};
var convert_channel = function(ch_){
	if (ch_ >= 2412 && ch_ <= 2484) {
		return (ch_ - 2412) / 5 + 1;
	} else if (ch_ >= 5170 && ch_ <= 5825) {
		return (ch_ - 5170) / 5 + 34;
	} else {
		return -1;
	}
}
var convert_ghz = function(ch_){
	if (ch_ >= 1 && ch_ <= 16) {
		
		return (ch_ - 1) * 5 + 2412;
	} else if (ch_ >= 34 && ch_ <= 170) {
		// (ch_ - 34) / 2 * 10 + 5170
		return (ch_ - 34) / 2 * 10 + 5170;
	} else {
		return -1;
	}
}
function count_bit_from_left(num)
{
	if (num == 255 ){
		return(8);
	}
	i = 0;
	bitpat=0xff00; 
	while (i < 8){
		if (num == (bitpat & 0xff)){
			return(i);
		}
		bitpat=bitpat >> 1;
		i++;
	}
	return(Number.NaN);
}
/*
	사용법 : isNumVal("0123456789");
	결과값 : ture or false
*/
var isNumVal = function(val_, flag_) {
	val_ = $.trim(val_);
	if ( val_ == null ) {
		return false;
	}

	var reg = /[^0-9]/;
	if (flag_ != undefined)
	{
		reg = /[^0-9\-]/;
	}
	var result = !reg.test(val_);
	return result;
};
/*
	사용법 : isNumVal("1.22");
	결과값 : ture or false
	소수점 포함 숫자 검사.
*/
var isFloat = function(val_){
	val_ = $.trim(val_);
	if ( val_ == null ) {
		return false;
	}

	var reg = /[^0-9.]/;
	var result = !reg.test(val_);
	return result;
}
var check_tcp_port = function(port_){
	if(isNumVal(port_) == true){
		var tmp = parseInt(port_,10);
		if(tmp < 1 || tmp > 65535){
			return false;
		}else{
			return true;
		}
	}else{
		return false;
	}
}
var check_min_max = function(val_, min_, max_){
	if(isNumVal(val_) == true && isNumVal(min_) == true && isNumVal(max_) == true){
		val_ = val_ ? parseInt(val_,10) : 0;
		min_ = min_ ? parseInt(min_,10) : 0;
		max_ = max_ ? parseInt(max_,10) : 0;
		if(min_ > val_ || max_ < val_){
			return false;
		}else{
			return true;
		}
	}else{
		return false;
	}
}
var convert_two_digit = function(num_) {
	//num = num < 10 ? '0' + num : '' + num;
	var tempVal = "";
	if(isNumVal(num_)){
		tempVal = ("00"+num_.toString()).substr(-2);
	}else{
		tempVal = "00";
	}
	return tempVal;
};
var convert_three_digit = function(num_) {
	//num = num < 10 ? '0' + num : '' + num;
	var tempVal = "";
	if(isNumVal(num_)){
		tempVal = ("000"+num_.toString()).substr(-3);
	}else{
		tempVal = "000";
	}
	return tempVal;
};
function byteConvertor(bytes, round_) {
	bytes = parseInt(bytes);
	if (round_ == undefined)
	{
		round_ = 2;
	}
	var s = ['bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
	var e = Math.floor(Math.log(bytes)/Math.log(1024));
	if(e == "-Infinity") return "0 "+s[0];
	else return (bytes/Math.pow(1024, Math.floor(e))).toFixed(round_)+" "+s[e];
};
/*
	함수 설명 : 바이트를 바이트에 맞게 킬로바이트 기가 바이트 자동 리턴 함수
	사용법 : byteConvertor(숫자);
*/
function bitConvertor(bit, round_, flag_) {
	bit = parseInt(bit);
	if (round_ == undefined)
	{
		round_ = 2;
	}
	if (flag_ == undefined)
	{
		flag_ = 0;
	}
	if (flag_ == 1)
	{
		bit = bit * 1000;
	}
	var s = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps', 'Pbps'];
	var e = Math.floor(Math.log(bit)/Math.log(1000));
	if(e == "-Infinity") return "0 "+s[0];
	else return (bit/Math.pow(1000, Math.floor(e))).toFixed(round_)+" "+s[e];
};
/*
	함수 설명 : 숫자 천단위로 컴마 찍어주는 함수
	사용법 : commify(숫자);
*/
function commify(n) {
	var reg = /(^[+-]?\d+)(\d{3})/;
	n += '';

	while (reg.test(n)){
		n = n.replace(reg, '$1' + ',' + '$2');
	}

	return n;
};
var get_timestamp = function(){
	var tempVal =0;
	var now = new Date();
	tempVal = now.getTime();
	
	return tempVal;
};
var millisecond_to_date = function(t){
	if (t.length < 10)
	{
		return "";
	}
	var temp = parseInt(t,10);
	//alert(t);
	var thisDate =  new Date(temp);
	thisDate = new Date(thisDate);
	var thisYear = thisDate.getFullYear();
	var thisMonth = thisDate.getMonth() + 1;
	thisMonth  = "0" + thisMonth;
	thisMonth = thisMonth.substr(thisMonth.length -2,2);
	var thisDay = thisDate.getDate();
	thisDay  = "0" + thisDay;
	thisDay = thisDay.substr(thisDay.length -2,2);
	var thisHour = thisDate.getHours();
	thisHour  = "0" + thisHour;
	thisHour = thisHour.substr(thisHour.length -2,2);
	var thisMin = thisDate.getMinutes();
	thisMin  = "0" + thisMin;
	thisMin = thisMin.substr(thisMin.length -2,2);
	var thisSec = thisDate.getSeconds();
	thisSec  = "0" + thisSec;
	thisSec = thisSec.substr(thisSec.length -2,2);
	//alert(thisDate+"\n"+thisSec);
	var rtn = thisYear+"-"+thisMonth+"-"+thisDay + " " + thisHour + ":" + thisMin + ":" + thisSec;
	return rtn;

};
var date_to_millisecond = function(t, time_){
	if (t != undefined)
	{
		if (t != "")
		{
			var dateString = t;
			if (time_ == undefined)
	//		if (time_ == undefined && time_ == "")
			{
				dateString = dateString + " 00:00:00";
			}else{
				if (time_ != "")
				{
					dateString = dateString + " " +time_;
				}else{
					dateString = dateString + " 00:00:00";
				}
			}
			var reggie = /(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})/;
			var dateArray = reggie.exec(dateString);
			var thisDate = new Date(
				(+dateArray[1]),
				(+dateArray[2])-1, // Careful, month starts at 0!
				(+dateArray[3]),
				(+dateArray[4]),
				(+dateArray[5]),
				(+dateArray[6])
			);
			rtn = thisDate.getTime();
			return rtn;
		}else{
			return;
		}
	}else{
		return;
	}
};
var check_date = function(val_){
	var datePattern = /^(\d{4})\-(\d{2})\-(\d{2})/;
	var dateArray = val_.match(datePattern);
	var errorString = "";
	var theName = "Date";
	var thisSegment = "";
	if (dateArray == null){
		errorString = errorString + theName;
	}else{
		for (var i = 0; i < 3; i++)
		{
			thisSegment = parseInt(dateArray[i+1],10);
			if (i == 0)
			{
				if(thisSegment > 3000 || thisSegment < 1970){
					errorString = errorString + theName;
					i = 5;
				}
			}else if(i == 1){
				if (thisSegment > 12)
				{
					errorString = errorString + theName;
					i = 5;
				}
			}else{
				if (thisSegment > 31)
				{
					errorString = errorString + theName;
					i = 5;
				}
			}
		}
	}
	if (!(errorString ==""))
	{
		return false;
	}else{
		return true;
	}
}
var check_time = function(val_){
	var timePattern = /^(\d{2})\:(\d{2})\:(\d{2})/;
	var timeArray = val_.match(timePattern);
	var errorString = "";
	var theName = "Time";
	var thisSegment = "";
	if (timeArray == null){
		errorString = errorString + theName;
	}else{
		for (var i = 0; i < 3; i++)
		{
			thisSegment = parseInt(timeArray[i+1],10);
			if (i == 0)
			{
				if(thisSegment > 23){
					errorString = errorString + theName;
					i = 5;
				}
			}else{
				if (thisSegment > 59)
				{
					errorString = errorString + theName;
					i = 5;
				}
			}
		}
	}
	if (!(errorString ==""))
	{
		return false;
	}else{
		return true;
	}
}
var clean_auth_type = function(val_){
	var auth = "";
	if(val_.indexOf("psk-mixed") > -1){
		auth = "WPA2";
	}else if(val_.indexOf("wpa-mixed") > -1){
		auth = "WPA2";
	}else if(val_.indexOf("psk2") > -1){
		auth = "WPA2";
	}else if(val_.indexOf("wpa2") > -1){
		auth = "WPA2";
	}else if(val_.indexOf("psk") > -1){
		auth = "WPA";
	}else if(val_.indexOf("wpa") > -1){
		auth = "WPA";
	}else if(val_.indexOf("wep") > -1){
		auth = "WEP";
	}else if(val_.indexOf("none") > -1){
		auth = "OPEN";
	}else{
		auth = "OPEN";
	}
	return auth;
}

var spinner = "";
var create_loading = function(){
	if($("body").find("#foo").length == 0){
		$("body").prepend("<div id=\"foo\"></div>");
	};
	var opts = {
		lines: 13, // The number of lines to draw
		length: 14, // The length of each line
		width: 5, // The line thickness
		radius: 5, // The radius of the inner circle
		scale: 1, // Scales overall size of the spinner
		corners: 0, // Corner roundness (0..1)
		color: '#000', // #rgb or #rrggbb or array of colors
		opacity: 0.25, // Opacity of the lines
		rotate: 0, // The rotation offset
		direction: 1, // 1: clockwise, -1: counterclockwise
		speed: 1, // Rounds per second
		trail: 60, // Afterglow percentage
		fps: 20, // Frames per second when using setTimeout() as a fallback for CSS
		zIndex: 2e9, // The z-index (defaults to 2000000000)
		className: 'spinner', // The CSS class to assign to the spinner
		top: '48%', // Top position relative to parent
		left: '48%', // Left position relative to parent
		shadow: false, // Whether to render a shadow
		hwaccel: false, // Whether to use hardware acceleration
		position: 'absolute' // Element positioning
	};
	var target = document.getElementById('foo');
	spinner = new Spinner(opts).spin(target);
}
var remove_loading =function(){
	spinner.stop();
	$("#foo").remove();
}
//XSS 필터링
var XSSfilter = function(content){
	return content.replace(/</g, "&lt;").replace(/>/g, "&gt;");
};
function check_xss(val_)
{
	var result = true;
	var val_len = val_.length;
	val_ = val_.replace(/<br>/ig, "\n"); // <br>을 엔터로 변경
	val_ = val_.replace(/&nbsp;/ig, " "); // 공백      
	// HTML 태그제거
	val_ = val_.replace(/<(\/)?([a-zA-Z]*)(\s[a-zA-Z]*=[^>]*)?(\s)*(\/)?>/ig, "");

	// shkim.add.
	val_ = val_.replace(/<(no)?script[^>]*>.*?<\/(no)?script>/ig, "");
	val_ = val_.replace(/<style[^>]*>.*<\/style>/ig, "");
	val_ = val_.replace(/<(\"[^\"]*\"|\'[^\']*\'|[^\'\">])*>/ig, "");
	val_ = val_.replace(/<\\w+\\s+[^<]*\\s*>/ig, "");
	val_ = val_.replace(/&[^;]+;/ig, "");
	val_ = val_.replace(/\\s\\s+/ig, "");
	val_ = val_.replace(/(exec)|(shell_exec)|(system)?\([\S+\s+]{1,}\)/ig,"");
	if(val_.length == val_len){
		result = true;
	}else{
		result = false;
	}
	return result;
}
if(jQuery){
	/*마우스 우클릭 방지 & 직접경로 방지*/
	$(document).ready( function() {
		if($("frameset").length == 0){
			if(parent.location.pathname != "/" && parent.location.pathname != "/login.php" && parent.location.pathname != "/index.php" && parent.location.pathname != "/skb_passwd_change.php" && location.hash != "#form"){
				top.parent.window.location.href="/";
			}
			if((top.parent.window.location.pathname == "/index.php" || top.parent.window.location.pathname == "/") && location.pathname == "/login.php" && parent.location.pathname != "/skb_passwd_change.php"){
				top.parent.window.location.href="/";
			}
		}
	});
}