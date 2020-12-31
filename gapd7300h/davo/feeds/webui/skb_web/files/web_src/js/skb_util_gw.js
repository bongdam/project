var wps_wep_key_old;


function trim(value) {
  return value.replace(/^\s+|\s+$/g, "");
}

function IsKorean(str) {
  var koreaCode;

  for (var i = 0; i < str.length; i++) {
    koreaCode = str.charCodeAt(i);
    if (koreaCode > 12592) {
      return true;
    }
  }
  return false;
}

function checkHex(str) {
  var pattern = /^[0-9a-fA-F]*$/;
  return pattern.test(str);
}




function validateNum(str) {
  for (var i = 0; i < str.length; i++) {
    if (!(str.charAt(i) >= '0' && str.charAt(i) <= '9')) {
      alert("값이 올바르지 않습니다. 숫자(0-9)로 입력해야 합니다.");
      return false;
    }
  }
  return true;
}

function isHex(str) {
  if (str.length == 0 || str.length > 4) {
    return false;
  }
  str = str.toLowerCase();
  var ch;
  for (var i = 0; i < str.length; i++) {
    ch = str.charAt(i);
    if (!(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'f')) {
      return false;
    }
  }
  return true;
}

function skip() {
  this.blur();
}

function disableTextField(field) {
  if (document.all || document.getElementById)
    field.disabled = true;
  else {
    field.oldOnFocus = field.onfocus;
    field.onfocus = skip;
  }
}

function enableTextField(field) {
  if (document.all || document.getElementById)
    field.disabled = false;
  else {
    field.onfocus = field.oldOnFocus;
  }
}

function verifyBrowser() {
  var ms = navigator.appVersion.indexOf("MSIE");
  ie4 = (ms > 0) && (parseInt(navigator.appVersion.substring(ms + 5, ms + 6)) >= 4);
  var ns = navigator.appName.indexOf("Netscape");
  ns = (ns >= 0) && (parseInt(navigator.appVersion.substring(0, 1)) >= 4);
  if (ie4)
    return "ie4";
  else
  if (ns)
    return "ns";
  else
    return false;
}


/*==============================================================================*/
function show_div(show, id) {
  var div = document.getElementById(id);
  if (!div) return;
  if (show)
    div.className = "on";
  else
    div.className = "off";
}



function saveChanges_wan(form, MultiPppoeFlag, dynamicWanIP) {
  var wanType = form.wanType.selectedIndex;
  if (form.pppoeNumber)
    var pppoeNumber = form.pppoeNumber.selectedIndex;
  else
    var pppoeNumber = 0;

  var subNetNumber;
  //alert("pppoeNumber value ="+pppoeNumber);

  if (form.lte4g_build.value == 1 && form.lte4g_enable.value == 1)
    wanType = 1;

  if (wanType == 0) { //static IP
    if (checkIpAddr(form.wan_ip, 'IP 주소가 올바르지 않습니다') == false)
      return false;
    if (checkIPMask(form.wan_mask) == false)
      return false;

    if (checkHostIPValid(form.wan_ip, form.wan_mask, 'IP 주소가 올바르지 않습니다') == false)
      return false;

    if (form.wan_gateway.value != "" && form.wan_gateway.value != "0.0.0.0") {

      if (checkIpAddr(form.wan_gateway, '게이트웨이 주소가 올바르지 않습니다') == false)
        return false;
      if (!checkSubnet(form.wan_ip.value, form.wan_mask.value, form.wan_gateway.value)) {
        alert('IP 주소 또는 게이트웨이가 서브넷을 벗어났습니다.');
        form.wan_gateway.value = form.wan_gateway.defaultValue;
        form.wan_gateway.focus();
        return false;
      }
    } else
      form.wan_gateway.value = '0.0.0.0';

    if (form.dns1.value == "") {
      alert('DNS1 주소가 비어있습니다!');
      return false;
    }

    if (form.dns1.value == "0.0.0.0") {
      alert('DNS1 주소가 올바르지 않습니다!');
      return false;
    } else {
      form.dnsMode.value = "dnsManual";
      if (checkIpAddr(form.dns1, 'DNS1 주소가 올바르지 않습니다') == false)
        return false;

      if (form.dns1.value != "180.182.54.1" && form.dns1.value != "180.182.54.2" && form.dns1.value != "168.126.63.1" && form.dns1.value != "168.126.63.2" &&
        form.dns1.value != "164.124.107.9" && form.dns1.value != "164.124.101.2" && form.dns1.value != "203.248.252.2" && form.dns1.value != "203.248.240.31" &&
        form.dns1.value != "210.220.163.82" && form.dns1.value != "219.250.36.130" && form.dns1.value != "210.181.1.24" && form.dns1.value != "210.181.4.25" &&
        form.dns1.value != "202.30.143.11" && form.dns1.value != "203.240.193.11" && form.dns1.value != "211.238.160.21" && form.dns1.value != "208.67.222.222" &&
        form.dns1.value != "208.67.220.220" && form.dns1.value != "8.8.8.8" && form.dns1.value != "8.8.4.4") {
        alert('DNS1 주소가 올바르지 않습니다');
        return false;
      }
    }

    if (form.dns2 != null) {
      if (form.dns2.value == "")
        form.dns2.value = "0.0.0.0";
      if (form.dns2.value != "0.0.0.0") {
        if (checkIpAddr(form.dns2, 'DNS2 주소가 올바르지 않습니다') == false)
          return false;
      }
    } //dns2 != null
    if (form.dns3 != null) {
      if (form.dns3.value == "")
        form.dns3.value = "0.0.0.0";
      if (form.dns3.value != "0.0.0.0") {
        if (checkIpAddr(form.dns3, 'DNS3 주소가 올바르지 않습니다') == false)
          return false;
      }
    } // dns3 != null

    if (form.fixedIpMtuSize != null) {
      d2 = getDigit(form.fixedIpMtuSize.value, 1);
      if (validateKey(form.fixedIpMtuSize.value) == 0 ||
        (d2 > 1500 || d2 < 1400)) {
        alert("MTU 크기가 올바르지 않습니다! 1400에서 1500 사이의 값을 입력해야 합니다.");
        form.fixedIpMtuSize.value = form.fixedIpMtuSize.defaultValue;
        form.fixedIpMtuSize.focus();
        return false;
      }
    }
  } else if (wanType == 1) { //dhcp wanType
    if (form.dhcpMtuSize != null) {
      d2 = getDigit(form.dhcpMtuSize.value, 1);
      if (validateKey(form.dhcpMtuSize.value) == 0 ||
        (d2 > 1500 || d2 < 1400)) {
        alert("MTU 크기가 올바르지 않습니다! 1400에서 1500 사이의 값을 입력해야 합니다.");
        form.dhcpMtuSize.value = form.dhcpMtuSize.defaultValue;
        form.dhcpMtuSize.focus();
        return false;
      }
    }
    if (form.hostName != null) {
      var str = form.hostName.value;
      if (str.length > 63) {
        alert("Host Name이 올바르지 않습니다! Domain Name의 길이는 63 이하 입니다.");
        form.hostName.focus();
        return false;
      }

      for (var i = 0; i < str.length; i++) {
        if ((str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
          (str.charAt(i) >= 'a' && str.charAt(i) <= 'z') ||
          (str.charAt(i) >= 'A' && str.charAt(i) <= 'Z') ||
          str.charAt(i) == '-')
          continue;
        alert("Host Name이 올바르지 않습니다! 문자A(a)~Z(z) 또는 0-9를 '-' 없이 입력해야 합니다.");
        form.hostName.focus();
        return false;
      }
      if (str.charAt(0) == '-' ||
        str.charAt(str.length - 1) == '-' ||
        (str.charAt(0) >= '0' && str.charAt(0) <= '9')) {
        alert("Host Name이 올바르지 않습니다! Host Name은 문자로 시작하거나 문자 또는 숫자로 끝나야 합니다.");
        form.hostName.focus();
        return false;
      }

    }

  } else if (wanType == 2) { //pppoe wanType
    if (form.pppUserName.value == "") {
      alert('PPP 사용자 이름이 비어있습니다.');
      form.pppUserName.value = form.pppUserName.defaultValue;
      form.pppUserName.focus();
      return false;
    }
    if (form.pppPassword.value == "") {
      alert('PPP 비밀번호가 비어있습니다.');
      form.pppPassword.value = form.pppPassword.defaultValue;
      form.pppPassword.focus();
      return false;
    }
    if (form.pppConnectType != null) {
      if (form.pppConnectType.selectedIndex == 1) {
        d1 = getDigit(form.pppIdleTime.value, 1);
        if (validateKey(form.pppIdleTime.value) == 0 ||
          (d1 > 1000 || d1 < 1)) {
          alert("재시도 간격이 올바르지 않습니다! 1에서 1000 사이의 값을 입력해야 합니다.");
          form.pppIdleTime.focus();
          return false;
        }
      }
    }

    if (form.pppMtuSize != null) {
      d2 = getDigit(form.pppMtuSize.value, 1);
      if (validateKey(form.pppMtuSize.value) == 0 ||
        (d2 > 1492 || d2 < 1360)) {
        alert("MTU 크기가 올바르지 않습니다! 1360에서 1492 사이의 값을 입력해야 합니다.");
        form.pppMtuSize.value = form.pppMtuSize.defaultValue;
        form.pppMtuSize.focus();
        return false;
      }
    } // if (pppMtuSize !=null)
    if (MultiPppoeFlag == 1)
      if (ppp_checkSubNetFormat(form.pppSubNet_1, 'IP 주소가 올바르지 않습니다') == false)
        return false;
      //----------------------first pppoe info check  End--------------------------------
      //----------------------Second pppoe info check  Begin-----------------------------
    if (pppoeNumber >= 1) {
      if (form.pppUserName2.value == "") {
        alert('PPP 사용자 이름이 비어있습니다!');
        form.pppUserName2.value = form.pppUserName2.defaultValue;
        form.pppUserName2.focus();
        return false;
      }
      if (form.pppPassword2.value == "") {
        alert('PPP 비밀번호가 비어있습니다!');
        form.pppPassword2.value = form.pppPassword2.defaultValue;
        form.pppPassword2.focus();
        return false;
      }
      if (form.pppConnectType2 != null) {
        if (form.pppConnectType2.selectedIndex == 1) {
          d1 = getDigit(form.pppIdleTime2.value, 1);
          if (validateKey(form.pppIdleTime2.value) == 0 ||
            (d1 > 1000 || d1 < 1)) {
            alert("재시도 간격이 올바르지 않습니다! 1에서 1000사이의 값을 입력해야 합니다.");
            form.pppIdleTime2.focus();
            return false;
          }
        }
      }
      if (form.pppMtuSize2 != null) {
        d2 = getDigit(form.pppMtuSize2.value, 1);
        if (validateKey(form.pppMtuSize2.value) == 0 ||
          (d2 > 1492 || d2 < 1360)) {
          alert("MTU 크기가 올바르지 않습니다! 1360에서 1492 사이의 값을 입력해야 합니다.");
          form.pppMtuSize2.value = form.pppMtuSize2.defaultValue;
          form.pppMtuSize2.focus();
          return false;
        }
      }
      if (ppp_checkSubNetFormat(form.pppSubNet_2, 'IP 주소가 올바르지 않습니다') == false)
        return false;

    }
    //----------------------Second pppoe info check  End---------------------------------
    //----------------------Third pppoe info check  Begin--------------------------------

    if (pppoeNumber >= 2) {
      if (form.pppUserName3.value == "") {
        alert('PPP 사용자 이름이 비어있습니다!');
        form.pppUserName3.value = form.pppUserName3.defaultValue;
        form.pppUserName3.focus();
        return false;
      }

      if (form.pppPassword3.value == "") {
        alert('PPP 비밀번호가 비어있습니다!');
        form.pppPassword3.value = form.pppPassword3.defaultValue;
        form.pppPassword3.focus();
        return false;
      }
      if (form.pppConnectType3 != null) {
        if (form.pppConnectType3.selectedIndex == 1) {
          d1 = getDigit(form.pppIdleTime3.value, 1);
          if (validateKey(form.pppIdleTime3.value) == 0 ||
            (d1 > 1000 || d1 < 1)) {
            alert("재시도 간격이 올바르지 않습니다! 1에서 1000사이의 값을 입력해야 합니다.");
            form.pppIdleTime3.focus();
            return false;
          }
        }
      }
      if (form.pppMtuSize3 != null) {
        d2 = getDigit(form.pppMtuSize3.value, 1);
        if (validateKey(form.pppMtuSize3.value) == 0 ||
          (d2 > 1492 || d2 < 1360)) {
          alert("MTU 크기가 올바르지 않습니다! 1360에서 1492 사이의 값을 입력해야 합니다.");
          form.pppMtuSize3.value = form.pppMtuSize3.defaultValue;
          form.pppMtuSize3.focus();
          return false;
        }
      }
      if (ppp_checkSubNetFormat(form.pppSubNet_3, 'IP 주소가 올바르지 않습니다') == false)
        return false;
    }
    //----------------------Third pppoe info check  End----------------------------------
    //----------------------Fourth pppoe info check  Begin--------------------------------
    if (pppoeNumber >= 3) {
      if (form.pppUserName4.value == "") {
        alert('PPP 사용자 이름이 비어있습니다!');
        form.pppUserName4.value = form.pppUserName4.defaultValue;
        form.pppUserName4.focus();
        return false;
      }

      if (form.pppPassword4.value == "") {
        alert('PPP 비밀번호가 비어있습니다!');
        form.pppPassword4.value = form.pppPassword4.defaultValue;
        form.pppPassword4.focus();
        return false;
      }
      if (form.pppConnectType4 != null) {
        if (form.pppConnectType4.selectedIndex == 1) {
          d1 = getDigit(form.pppIdleTime4.value, 1);
          if (validateKey(form.pppIdleTime4.value) == 0 ||
            (d1 > 1000 || d1 < 1)) {
            alert("재시도 간격이 올바르지 않습니다! 1에서 1000사이의 값을 입력해야 합니다.");
            form.pppIdleTime4.focus();
            return false;
          }
        }
      }
      if (form.pppMtuSize4 != null) {
        d2 = getDigit(form.pppMtuSize4.value, 1);
        if (validateKey(form.pppMtuSize4.value) == 0 ||
          (d2 > 1492 || d2 < 1360)) {
          alert("MTU 크기가 올바르지 않습니다! 1360에서 1492 사이의 값을 입력해야 합니다.");
          form.pppMtuSize4.value = form.pppMtuSize4.defaultValue;
          form.pppMtuSize4.focus();
          return false;
        }
      }
      if (ppp_checkSubNetFormat(form.pppSubNet_4, 'IP 주소가 올바르지 않습니다') == false)
        return false;
    }

    //----------------------Fourth pppoe info check  End----------------------------------

  } else if (wanType == 3) { //pptp wanType

    if (dynamicWanIP == 0) {
      if (checkIpAddr(form.pptpIpAddr, 'IP 주소가 올바르지 않습니다') == false)
        return false;
      if (checkIPMask(form.pptpSubnetMask) == false)
        return false;

      if (checkHostIPValid(form.pptpIpAddr, form.pptpSubnetMask, 'IP 주소가 올바르지 않습니다') == false)
        return false;

      if (checkIpAddr(form.pptpServerIpAddr, '서버 IP 주소가 올바르지 않습니다') == false)
        return false;
      if (!checkSubnet(form.pptpIpAddr.value, form.pptpSubnetMask.value, form.pptpDefGw.value)) {
        alert('서버 IP 주소가 올바르지 않습니다!\n로컬 IP 주소의 서브넷과 같아야 합니다.');
        form.pptpDefGw.value = form.pptpDefGw.defaultValue;
        form.pptpDefGw.focus();
        return false;
      }
    }
    if (form.pptpServerDomainName) {
      if ((!form.pptpServerDomainName.disabled) &&
        !checkFieldEmpty(form.pptpServerDomainName, '도메인 이름은 비워둘 수 없습니다'))
        return false;
    }
    if ((!form.pptpServerIpAddr.disabled) &&
      !checkIpAddr(form.pptpServerIpAddr, '서버 IP 주소가 올바르지 않습니다'))
      return false;

    if (form.pptpUserName.value == "") {
      alert('PPTP 사용자 이름이 비어있습니다!');
      form.pptpUserName.value = form.pptpUserName.defaultValue;
      form.pptpUserName.focus();
      return false;
    }
    if (form.pptpPassword.value == "") {
      alert('PPTP 비밀번호가 비어있습니다!');
      form.pptpPassword.value = form.pptpPassword.defaultValue;
      form.pptpPassword.focus();
      return false;
    }
    if (form.pptpConnectType != null) {
      if (form.pptpConnectType.selectedIndex == 1) {
        var d1 = getDigit(form.pptpIdleTime.value, 1);
        if (validateKey(form.pptpIdleTime.value) == 0 ||
          (d1 > 1000 || d1 < 1)) {
          alert("재시도 간격이 올바르지 않습니다! 1에서 1000사이의 값을 입력해야 합니다.");
          form.pptpIdleTime.focus();
          return false;
        }
      }
    }
    if (form.pptpMtuSize != null) {
      var d2 = getDigit(form.pptpMtuSize.value, 1);
      if (validateKey(form.pptpMtuSize.value) == 0 ||
        (d2 > 1460 || d2 < 1400)) {
        alert("MTU 크기가 올바르지 않습니다! 1400에서 1460 사이의 값을 입력해야 합니다.");
        form.pptpMtuSize.value = form.pptpMtuSize.defaultValue;
        form.pptpMtuSize.focus();
        return false;
      }
    }
  }
  /*-- keith: add l2tp support. 20080515  */
  else if (wanType == 4) { //l2tp wanType


    if (dynamicWanIP == 0) {
      if (checkIpAddr(form.l2tpIpAddr, 'IP 주소가 올바르지 않습니다') == false)
        return false;
      if (checkIPMask(form.l2tpSubnetMask) == false)
        return false;

      if (checkHostIPValid(form.l2tpIpAddr, form.l2tpSubnetMask, 'IP 주소가 올바르지 않습니다') == false)
        return false;

      if (checkIpAddr(form.l2tpServerIpAddr, '서버 IP 주소가 올바르지 않습니다') == false)
        return false;
      if (!checkSubnet(form.l2tpIpAddr.value, form.l2tpSubnetMask.value, form.l2tpDefGw.value)) {
        alert('서버 IP 주소가 올바르지 않습니다!\n로컬 IP 주소의 서브넷과 같아야 합니다.');
        form.l2tpDefGw.value = form.l2tpDefGw.defaultValue;
        form.l2tpDefGw.focus();
        return false;
      }
    }
    if (form.l2tpServerDomainName) {
      if ((!form.l2tpServerDomainName.disabled) &&
        !checkFieldEmpty(form.l2tpServerDomainName, '도메인 이름은 비워둘 수 없습니다.'))
        return false;
    }
    if ((!form.l2tpServerIpAddr.disabled) &&
      !checkIpAddr(form.l2tpServerIpAddr, '서버 IP 주소가 올바르지 않습니다'))
      return false;

    if (form.l2tpUserName.value == "") {
      alert('L2TP 사용자 이름이 비어있습니다!');
      form.l2tpUserName.value = form.l2tpUserName.defaultValue;
      form.l2tpUserName.focus();
      return false;
    }
    if (form.l2tpPassword.value == "") {
      alert('L2TP 비밀번호가 비어있습니다!');
      form.l2tpPassword.value = form.l2tpPassword.defaultValue;
      form.l2tpPassword.focus();
      return false;
    }
    if (form.l2tpConnectType != null) {
      if (form.l2tpConnectType.selectedIndex == 1) {
        d1 = getDigit(form.l2tpIdleTime.value, 1);
        if (validateKey(form.l2tpIdleTime.value) == 0 ||
          (d1 > 1000 || d1 < 1)) {
          alert("재시도 간격이 올바르지 않습니다! 1에서 1000사이의 값을 입력해야 합니다.");
          form.l2tpIdleTime.focus();
          return false;
        }
      }
    }
    if (form.l2tpMtuSize != null) {
      d2 = getDigit(form.l2tpMtuSize.value, 1);
      if (validateKey(form.l2tpMtuSize.value) == 0 ||
        (d2 > 1460 || d2 < 1400)) {
        alert("MTU 크기가 올바르지 않습니다! 1400에서 1460 사이의 값을 입력해야 합니다.");
        form.l2tpMtuSize.value = form.l2tpMtuSize.defaultValue;
        form.l2tpMtuSize.focus();
        return false;
      }
    }
  }
  // --------------- USB3G wanType ---------------
  else if (wanType == 5) {
    if (form.wanType.options[5].text == "USB3G") {
      if (form.USB3G_APN.value == "") {
        alert('APN name cannot be empty!');
        form.USB3G_APN.value = form.USB3G_APN.defaultValue;
        form.USB3G_APN.focus();
        return false;
      }

      if (form.USB3G_DIALNUM.value == "") {
        alert('Dial number cannot be empty!');
        form.USB3G_DIALNUM.value = form.USB3G_DIALNUM.defaultValue;
        form.USB3G_DIALNUM.focus();
        return false;
      }

      if (form.USB3GConnectType != null) {
        if (form.USB3GConnectType.selectedIndex == 1) {
          d1 = getDigit(form.USB3GIdleTime.value, 1);
          if (validateKey(form.USB3GIdleTime.value) == 0 || (d1 > 1000 || d1 < 1)) {
            alert("Invalid idle time value! You should set a value between 1-1000.");
            form.USB3GIdleTime.focus();
            return false;
          }
        }
      }
      if (form.USB3GMtuSize != null) {
        d2 = getDigit(form.USB3GMtuSize.value, 1);
        if (validateKey(form.USB3GMtuSize.value) == 0 || (d2 > 1490 || d2 < 1420)) {
          alert("Invalid MTU size! You should set a value between 1420-1490.");
          form.USB3GMtuSize.value = form.USB3GMtuSize.defaultValue;
          form.USB3GMtuSize.focus();
          return false;
        }
      }
    }
  }

  if (wanType != 0) { // not static IP
    var group = form.dnsMode;
    for (var r = 0; r < group.length; r++)
      if (group[r].checked)
        break;
    if (wanType == 5) {
      if (form.wanType.options[5].text != "USB3G")
        r = 0;
    }

    if (r == 1) {
      if (form.dns1.value == "") {
        alert('DNS1 주소가 비어있습니다!');
        return false;
      }
      if (form.dns1.value == "0.0.0.0") {
        alert('DNS1 주소가 올바르지 않습니다!');
        return false;
      } else {
        if (checkIpAddr(form.dns1, 'DNS1 주소가 올바르지 않습니다') == false)
          return false;

        if (form.dns1.value != "180.182.54.1" && form.dns1.value != "180.182.54.2" && form.dns1.value != "168.126.63.1" && form.dns1.value != "168.126.63.2" &&
          form.dns1.value != "164.124.107.9" && form.dns1.value != "164.124.101.2" && form.dns1.value != "203.248.252.2" && form.dns1.value != "203.248.240.31" &&
          form.dns1.value != "210.220.163.82" && form.dns1.value != "219.250.36.130" && form.dns1.value != "210.181.1.24" && form.dns1.value != "210.181.4.25" &&
          form.dns1.value != "202.30.143.11" && form.dns1.value != "203.240.193.11" && form.dns1.value != "211.238.160.21" && form.dns1.value != "208.67.222.222" &&
          form.dns1.value != "208.67.220.220" && form.dns1.value != "8.8.8.8" && form.dns1.value != "8.8.4.4") {
          alert('DNS1 주소가 올바르지 않습니다');
          return false;
        }
      }
      if (form.dns2 != null) {
        if (form.dns2.value == "")
          form.dns2.value = "0.0.0.0";
        if (form.dns2.value != "0.0.0.0") {
          if (checkIpAddr(form.dns2, 'DNS2 주소가 올바르지 않습니다') == false)
            return false;
        }
      } //dns2 != null
      if (form.dns3 != null) {
        if (form.dns3.value == "")
          form.dns3.value = "0.0.0.0";
        if (form.dns3.value != "0.0.0.0") {
          if (checkIpAddr(form.dns3, 'DNS3 주소가 올바르지 않습니다') == false)
            return false;
        }
      } // dns3 != null
    }
  } else {
    if (form.dns1.value == "") {
      alert('DNS1 주소가 비어있습니다!');
      return false;
    }
    if (form.dns1.value == "0.0.0.0") {
      alert('DNS1 주소가 올바르지 않습니다');
      return false;
    } else {
      if (checkIpAddr(form.dns1, 'DNS1 주소가 올바르지 않습니다') == false)
        return false;
    }

    if (form.dns2 != null) {
      if (form.dns2.value == "")
        form.dns2.value = "0.0.0.0";
      if (form.dns2.value != "0.0.0.0") {
        if (checkIpAddr(form.dns2, 'DNS2 주소가 올바르지 않습니다') == false)
          return false;
      }
    }
    if (form.dns3 != null) {
      if (form.dns3.value == "")
        form.dns3.value = "0.0.0.0";
      if (form.dns3.value != "0.0.0.0") {
        if (checkIpAddr(form.dns3, 'DNS3 주소가 올바르지 않습니다') == false)
          return false;
      }
    }
  }
  if (form.wan_macAddr != null) {
    if (form.wan_macAddr.value == "")
      form.wan_macAddr.value = "000000000000";
    var str = form.wan_macAddr.value;
    if (str.length < 12) {
      alert("MAC 주소가 올바르지 않습니다. 16진수 12자리를 입력해야 합니다.");
      form.wan_macAddr.value = form.wan_macAddr.defaultValue;
      form.wan_macAddr.focus();
      return false;
    }

    // fixed "All MAC Address field can't reject 00:00:00:00:00:00/ff:ff:ff:ff:ff:ff MAC Address" issue
    if (str == "ffffffffffff") {
      alert("잘못된 MAC 주소입니다. ff:ff:ff:ff:ff:ff는 MAC 주소가 될 수 없습니다.");
      form.wan_macAddr.value = form.wan_macAddr.defaultValue;
      form.wan_macAddr.focus();
      return false;
    }

    //var reg = /01005[eE][0-7][0-9a-fA-F]{5}/;
    //if(reg.exec(str))
    if (parseInt(str.substr(0, 2), 16) & 0x01 != 0) {
      form.wan_macAddr.value = form.wan_macAddr.defaultValue;
      form.wan_macAddr.focus();
      alert("잘못된 MAC 주소입니다. 멀티 캐스트 MAC 주소가 될 수 없습니다.");
      return false;
    }

    for (var i = 0; i < str.length; i++) {
      if ((str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
        (str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
        (str.charAt(i) >= 'A' && str.charAt(i) <= 'F'))
        continue;
      alert("MAC 주소가 올바르지 않습니다. 16진수를 입력해야 합니다. (0-9 또는 a-f).");
      form.wan_macAddr.value = form.wan_macAddr.defaultValue;
      form.wan_macAddr.focus();
      return false;
    }
  }

  return true;
}


function disableButton(button) {
  //if (verifyBrowser() == "ns")
  //	return;
  if (document.all || document.getElementById)
    button.disabled = true;
  else if (button) {
    button.oldOnClick = button.onclick;
    button.onclick = null;
    button.oldValue = button.value;
    button.value = 'DISABLED';
  }
}

function enableButton(button) {
  //if (verifyBrowser() == "ns")
  //	return;
  if (document.all || document.getElementById)
    button.disabled = false;
  else if (button) {
    button.onclick = button.oldOnClick;
    button.value = button.oldValue;
  }
}

function showChannel5G(form, wlan_id) {
  var sideBand = form.elements["controlsideband" + wlan_id].value;
  var dsf_enable = form.elements["dsf_enable"].value;
  var idx = 0;
  var wlan_support_8812e = 0;
  if (form.elements["wlan_support_8812e"])
    wlan_support_8812e = form.elements["wlan_support_8812e"].value;
  var defChanIdx;
  form.elements["chan" + wlan_id].length = startChanIdx[wlan_id];

  if (startChanIdx[wlan_id] == 0)
    defChanIdx = 0;
  else
    defChanIdx = 1;

  if (startChanIdx[wlan_id] == 0) {
    //if(dsf_enable == 1)
    //	form.elements["chan"+wlan_id].options[0] = new Option("Auto(DFS)", 0, false, false);
    //else
    form.elements["chan" + wlan_id].options[0] = new Option("Auto", 0, false, false);

    if (0 == defaultChan[wlan_id]) {
      form.elements["chan" + wlan_id].selectedIndex = 0;
      defChanIdx = 0;
    }
    startChanIdx[wlan_id]++;
  }

  idx = startChanIdx[wlan_id];


  if (wlan_support_8812e == 1) {
    var bound = form.elements["channelbound" + wlan_id].selectedIndex;
    var inc_scale;
    var chan;
    inc_scale = 4;
    var chan_str = 36;
    var chan_end = 64;

    var reg_chan_8812_full = new Array(16);
    var i;
    var ii;
    var iii;
    var iiii;
    var found;
    var chan_pair;
    var reg_8812 = regDomain[wlan_id];

    /* FCC */
    reg_chan_8812_full[0] = new Array("36", "40", "44", "48", "52", "56", "60", "64", "100", "104", "108", "112", "116", "136", "140", "149", "153", "157", "161", "165");
    /* IC */
    reg_chan_8812_full[1] = new Array("36", "40", "44", "48", "52", "56", "60", "64", "149", "153", "157", "161");
    /* ETSI */
    reg_chan_8812_full[2] = new Array("36", "40", "44", "48", "52", "56", "60", "64", "100", "104", "108", "112", "116", "120", "124", "128", "132", "136", "140");
    /* SPAIN */
    reg_chan_8812_full[3] = new Array("36", "40", "44", "48", "52", "56", "60", "64", "100", "104", "108", "112", "116", "120", "124", "128", "132", "136", "140");
    /* FRANCE */
    reg_chan_8812_full[4] = new Array("36", "40", "44", "48", "52", "56", "60", "64", "100", "104", "108", "112", "116", "120", "124", "128", "132", "136", "140");
    /* MKK */
    reg_chan_8812_full[5] = new Array("36", "40", "44", "48", "52", "56", "60", "64", "100", "104", "108", "112", "116", "120", "124", "128", "132", "136", "140");
    /* ISRAEL */
    reg_chan_8812_full[6] = new Array("36", "40", "44", "48", "52", "56", "60", "64", "100", "104", "108", "112", "116", "120", "124", "128", "132", "136", "140");
    /* MKK1 */
    reg_chan_8812_full[7] = new Array("34", "38", "42", "46");
    /* MKK2 */
    reg_chan_8812_full[8] = new Array("36", "40", "44", "48");
    /* MKK3 */
    reg_chan_8812_full[9] = new Array("36", "40", "44", "48", "52", "56", "60", "64");
    /* NCC (Taiwan) */
    reg_chan_8812_full[10] = new Array("56", "60", "64", "100", "104", "108", "112", "116", "136", "140", "149", "153", "157", "161", "165");
    /* RUSSIAN */
    reg_chan_8812_full[11] = new Array("36", "40", "44", "48", "52", "56", "60", "64", "132", "136", "140", "149", "153", "157", "161", "165");
    /* CN */
    reg_chan_8812_full[12] = new Array("36", "40", "44", "48", "52", "56", "60", "64", "149", "153", "157", "161", "165");
    /* Global */
    reg_chan_8812_full[13] = new Array("36", "40", "44", "48", "52", "56", "60", "64", "100", "104", "108", "112", "116", "136", "140", "149", "153", "157", "161", "165");
    /* World_wide */
    reg_chan_8812_full[14] = new Array("36", "40", "44", "48", "52", "56", "60", "64", "100", "104", "108", "112", "116", "136", "140", "149", "153", "157", "161", "165");
    /* Test reg_chan_8812_full[15]= new Array("36","40","44","48","52","56","60","64","100","104","108","112","116","120","124","128"," 132","136","140","144","149","153","157","161","165","169","173","177");*/

    if (bound == 1 && sideBand == 0) { //upper
      reg_chan_8812_full[15] = new Array("40", "48", "56", "64", "104", "112", "120", "153", "161");
    } else if (bound == 1 && sideBand == 1) { //lower
      reg_chan_8812_full[15] = new Array("36", "44", "52", "60", "100", "108", "116", "149", "157");
    } else { //20, 80MHz
      /* Test*/
      reg_chan_8812_full[15] = new Array("36", "40", "44", "48", "52", "56", "60", "64", "100", "104", "108", "112", "116", "120", "124", "149", "153", "157", "161");
    }

    /*if(reg_8812 > 0)
			reg_8812 = reg_8812 - 1;
		if(reg_8812 > 15)*/
    reg_8812 = 15;

    if (reg_8812 == 7) //MKK1 are special case
    {
      if (bound <= 2)
        for (i = 0; i < reg_chan_8812_full[reg_8812].length; i++) {
          chan = reg_chan_8812_full[reg_8812][i];

          form.elements["chan" + wlan_id].options[idx] = new Option(chan, chan, false, false);
          if (chan == defaultChan[wlan_id]) {
            form.elements["chan" + wlan_id].selectedIndex = idx;
            defChanIdx = idx;
          }
          idx++;
        }
    } else {
      for (i = 0; i < reg_chan_8812_full[reg_8812].length; i++) {
        chan = reg_chan_8812_full[reg_8812][i];

        if (reg_8812 != 15 && reg_8812 != 10)
          if ((dsf_enable == 0) && (chan >= 52) && (chan <= 144))
            continue;

        if (reg_8812 == 10)
          if ((dsf_enable == 0) && (chan >= 100) && (chan <= 140))
            continue;

        if (reg_8812 != 15)
          if (bound == 1) {
            for (ii = 0; ii < reg_chan_8812_full[15].length; ii++) {
              if (chan == reg_chan_8812_full[15][ii])
                break;
            }

            if (ii % 2 == 0)
              chan_pair = reg_chan_8812_full[15][ii + 1];
            else
              chan_pair = reg_chan_8812_full[15][ii - 1];

            found = 0;
            for (ii = 0; ii < reg_chan_8812_full[reg_8812].length; ii++) {
              if (chan_pair == reg_chan_8812_full[reg_8812][ii]) {
                found = 1;
                break;
              }
            }

            if (found == 0)
              chan = 0;

          } else if (bound == 2) {
          for (ii = 0; ii < reg_chan_8812_full[15].length; ii++) {
            if (chan == reg_chan_8812_full[15][ii])
              break;
          }

          for (iii = (ii - (ii % 4)); iii < ((ii - (ii % 4) + 3)); iii++) {
            found = 0;
            chan_pair = reg_chan_8812_full[15][iii];

            for (iiii = 0; iiii < reg_chan_8812_full[reg_8812].length; iiii++) {
              if (chan_pair == reg_chan_8812_full[reg_8812][iiii]) {
                found = 1;
                break;
              }
            }

            if (found == 0) {
              chan = 0;
              break;
            }

          }

        }

        if (chan != 0) {
          form.elements["chan" + wlan_id].options[idx] = new Option(chan, chan, false, false);
          if (chan == defaultChan[wlan_id]) {
            form.elements["chan" + wlan_id].selectedIndex = idx;
            defChanIdx = idx;
          }
          idx++;
        }

      }
    }

  } else {
    reg_chan_plan = new Array(17);
    reg_chan_plan[0] = [2, [36, 4], [149, 5]]; //FCC
    reg_chan_plan[1] = [2, [36, 4], [149, 4]]; //IC
    reg_chan_plan[2] = [1, [36, 4]]; //ETSI
    reg_chan_plan[3] = [1, [36, 4]]; //SPAIN
    reg_chan_plan[4] = [1, [36, 4]]; //FRANCE
    reg_chan_plan[5] = [1, [36, 4]]; //MKK
    reg_chan_plan[6] = [1, [36, 4]]; //ISRAEL
    reg_chan_plan[7] = [1, [34, 4]]; //MKK1
    reg_chan_plan[8] = [1, [36, 4]]; //MKK2
    reg_chan_plan[9] = [1, [36, 4]]; //MKK3
    reg_chan_plan[10] = [2, [56, 3], [149, 5]]; //NCC
    reg_chan_plan[11] = [2, [36, 4], [149, 5]]; //RUSSIAN
    reg_chan_plan[12] = [2, [36, 4], [149, 5]]; //CN
    reg_chan_plan[13] = [2, [36, 4], [149, 5]]; //Global
    reg_chan_plan[14] = [2, [36, 4], [149, 5]]; //World_wide
    //if(!dsf_enable){
    //reg_chan_plan[15] = [3, [36,8],[100,12],[149,8]]; //Test
    //}else{
    reg_chan_plan[15] = [2, [36, 4], [149, 8]]; //Test
    //}
    reg_chan_plan[16] = [1, [146, 170]]; //5M10M

    var index = regDomain[wlan_id] - 1;
    var seg_num = reg_chan_plan[index][0];
    var bandstep;
    var bound = form.elements["channelbound" + wlan_id].selectedIndex;
    var idx_value = form.elements["band" + wlan_id].selectedIndex;
    var band_value = form.elements["band" + wlan_id].options[idx_value].value;

    if (regDomain[wlan_id] >= 1 && regDomain[wlan_id] < 17) { //step by 4
      bandstep = 4;
    } else if (regDomain[wlan_id] == 17) { //step by 1
      bandstep = 1;
    } else {
      return;
    }

    for (var bn = 0; bn < seg_num; bn++) {
      var base = reg_chan_plan[index][bn + 1][0];
      var bandnum = reg_chan_plan[index][bn + 1][1];
      var startindex = 0;
      var indexstep = 1;
      if (regDomain[wlan_id] != 17) {
        if (band_value != 3) { // not 11a, maybe: 11AC,11n,11a+11n,...
          if (bound == 1) { //40M
            indexstep = 2;
            if (sideBand == 0) { //upper
              startindex = 1;
            }
          }
        }
      }
      for (var bindex = startindex; bindex < bandnum; idx++, bindex += indexstep) {
        var chan = base + bindex * bandstep;
        form.elements["chan" + wlan_id].options[idx] = new Option(chan, chan, false, false);
        if (chan == defaultChan[wlan_id]) {
          form.elements["chan" + wlan_id].selectedIndex = idx;
          defChanIdx = idx;
        }
      }
    }
    reg_chan_plan = null;
  }

  form.elements["chan" + wlan_id].length = idx;
  if (defChanIdx == 0)
    form.elements["chan" + wlan_id].selectedIndex = 0;
}


function showChannel2G(form, wlan_id, bound_40, band_value) {
  var start = 1;
  var end = 14;
  if (regDomain[wlan_id] == 1 || regDomain[wlan_id] == 2 || regDomain[wlan_id] == 11) {
    start = 1;
    end = 11;
  }
  if (regDomain[wlan_id] == 3 || regDomain[wlan_id] == 4 || regDomain[wlan_id] == 12 || regDomain[wlan_id] == 13 || regDomain[wlan_id] == 15) {
    start = 1;
    end = 13;
  }
  if (regDomain[wlan_id] == 5) {
    start = 10;
    end = 13;
  }
  if (regDomain[wlan_id] == 6 || regDomain[wlan_id] == 8 || regDomain[wlan_id] == 9 || regDomain[wlan_id] == 10 || regDomain[wlan_id] == 14 || regDomain[wlan_id] == 16) {
    start = 1;
    end = 14;
  }
  if (regDomain[wlan_id] == 7) {
    start = 3;
    end = 13;
  }


  if (band_value == 9 || band_value == 10 || band_value == 7) {
    if (bound_40 == 1) {
      var sideBand_idex = form.elements["controlsideband" + wlan_id].selectedIndex;
      var sideBand = form.elements["controlsideband" + wlan_id].options[sideBand_idex].value;
      if (regDomain[wlan_id] == 4) {
        if (sideBand == 0) { //upper
          start = 11;
          end = 11;
        } else if (sideBand == 1) { //lower
          start = 10;
          end = 10;
        }
      } else if (regDomain[wlan_id] == 5) {
        if (sideBand == 0) { //upper
          start = 13;
          end = 13;
        } else if (sideBand == 1) { //lower
          start = 10;
          end = 10;
        }
      } else {
        if (sideBand == 0) { //upper
          //start = 5;
          start = 1;
          if (regDomain[wlan_id] == 1 || regDomain[wlan_id] == 2 || regDomain[wlan_id] == 11)
            end = 11;
          else
            end = 13;

        } else if (sideBand == 1) { //lower
          //end = 9;
          if (regDomain[wlan_id] == 1 || regDomain[wlan_id] == 2 || regDomain[wlan_id] == 11)
            end = 11;
          else
            end = 13;
          //end = 7; orig
          if (regDomain[wlan_id] == 7)
            start = 3;
          else
            start = 1;
        }
      }
    }
  }
  var defChanIdx = 0;
  form.elements["chan" + wlan_id].length = 0;

  idx = 0;
  form.elements["chan" + wlan_id].options[0] = new Option("Auto", 0, false, false);

  if (wlan_channel[wlan_id] == 0) {
    form.elements["chan" + wlan_id].selectedIndex = 0;
    defChanIdx = 0;
  }

  idx++;
  var chan;

  //ac2g
  if (band_value == 74) {
    start = 1;
    end = 13;
    for (chan = start; chan <= end; idx++) {
      form.elements["chan" + wlan_id].options[idx] = new Option(chan, chan, false, false);
      if (chan == wlan_channel[wlan_id]) {
        form.elements["chan" + wlan_id].selectedIndex = idx;
        defChanIdx = idx;
      }
      chan = chan + 4;
    }
  } else {
    for (chan = start; chan <= end; chan++, idx++) {
      form.elements["chan" + wlan_id].options[idx] = new Option(chan, chan, false, false);
      if (chan == wlan_channel[wlan_id]) {
        form.elements["chan" + wlan_id].selectedIndex = idx;
        defChanIdx = idx;
      }
    }
  }
  form.elements["chan" + wlan_id].length = idx;
  startChanIdx[wlan_id] = idx;
}

function updateChan_channebound(form, wlan_id) {
  var idx_value = form.elements["band" + wlan_id].selectedIndex;
  var band_value = form.elements["band" + wlan_id].options[idx_value].value;
  var bound = form.elements["channelbound" + wlan_id].selectedIndex;
  var adjust_chan;
  var Band2G5GSupport = form.elements["Band2G5GSupport"].value;
  var wlBandMode = form.elements["wlBandMode"].value;


  if (form.name == "wizard") {
    switch (wlan_id) {
      case 0:
        if (form.elements["wlan1_phyband"].value == "5GHz")
          Band2G5GSupport = 2;
        else
          Band2G5GSupport = 1;
        break;

      case 1:
        if (form.elements["wlan2_phyband"].value == "5GHz")
          Band2G5GSupport = 2;
        else
          Band2G5GSupport = 1;
        break;

    }

  }
  var currentBand;

  if (band_value == 3 || band_value == 11 || band_value == 63 || band_value == 71 || band_value == 75) {
    currentBand = 2;
  } else if (band_value == 0 || band_value == 1 || band_value == 2 || band_value == 9 || band_value == 10 || band_value == 74) { //ac2g
    currentBand = 1;
  } else if (band_value == 4 || band_value == 5 || band_value == 6 || band_value == 14) {
    currentBand = 3;
  } else if (band_value == 7) //7:n
  {
    if (Band2G5GSupport == 1) //1:2g
      currentBand = 1;
    else
      currentBand = 2;

    if (wlBandMode == 3) {
      if (idx_value != 1)
        currentBand = 1;
      else
        currentBand = 2;
    }
  }
  if (band_value == 9 || band_value == 10 || band_value == 7 || band_value == 74) { // 8812 ?? adjust channel ?? //ac2g
    if (bound == 0)
      adjust_chan = 0;
    if (bound == 1)
      adjust_chan = 1;
    if (bound == 2)
      adjust_chan = 2;
  } else
    adjust_chan = 0;


  if (currentBand == 3) {
    showChannel2G(form, wlan_id, adjust_chan, band_value);
    showChannel5G(form, wlan_id);
  }

  if (currentBand == 2) {
    startChanIdx[wlan_id] = 0;
    showChannel5G(form, wlan_id);
    Band2G5GSupport = 2;
  }

  if (currentBand == 1) {
    showChannel2G(form, wlan_id, adjust_chan, band_value);
    Band2G5GSupport = 1;
  }

  if (band_value == 9 || band_value == 10 || band_value == 7 || band_value == 11 || band_value == 14) {
    if (form.elements["chan" + wlan_id].value == 0) { // 0:auto
      disableTextField(form.elements["controlsideband" + wlan_id]);
    } else {
      enableTextField(form.elements["controlsideband" + wlan_id]);
    }
  }
}

function updateChan(form, wlan_id) {
  var idx_value = form.elements["band" + wlan_id].selectedIndex;
  var band_value = form.elements["band" + wlan_id].options[idx_value].value;
  var Band2G5GSupport = form.elements["Band2G5GSupport"].value;
  var currentBand;
  if (form.name == "wizard") {
    switch (wlan_id) {
      case 0:
        if (form.elements["wlan1_phyband"].value == "5GHz")
          Band2G5GSupport = 2;
        else
          Band2G5GSupport = 1;
        break;

      case 1:
        if (form.elements["wlan2_phyband"].value == "5GHz")
          Band2G5GSupport = 2;
        else
          Band2G5GSupport = 1;
        break;

    }

  }
  //ac2g
  if (band_value == 3 || band_value == 11 || (band_value == 7 && Band2G5GSupport == 2) || band_value == 63 || band_value == 71 || band_value == 75) { // 3:5g_a 11:5g_an 7:n 2:PHYBAND_5G
    currentBand = 2;
  } else if (band_value == 0 || band_value == 1 || band_value == 2 || band_value == 9 || band_value == 10 || band_value == 74 || (band_value == 7 && Band2G5GSupport == 1)) {
    currentBand = 1;
  } else if (band_value == 4 || band_value == 5 || band_value == 6 || band_value == 14) {
    currentBand = 3;
  }


  if ((lastBand[wlan_id] != currentBand) || (lastRegDomain[wlan_id] != regDomain[wlan_id])) {
    lastBand[wlan_id] = currentBand;
    lastRegDomain[wlan_id] = regDomain[wlan_id];
    if (currentBand == 3) {
      showChannel2G(form, wlan_id, 0, band_value);
      showChannel5G(form, wlan_id);
    }

    if (currentBand == 2) {
      startChanIdx[wlan_id] = 0;
      showChannel5G(form, wlan_id);
    }

    if (currentBand == 1)
      showChannel2G(form, wlan_id, 0, band_value);
  }

  if (band_value == 9 || band_value == 10 || band_value == 7 || band_value == 11 || band_value == 14) {
    if (form.elements["chan" + wlan_id].selectedIndex == 0) { // 0:auto
      disableTextField(form.elements["controlsideband" + wlan_id]);
    } else {
      enableTextField(form.elements["controlsideband" + wlan_id]);
    }
  }
}

function showBand_MultipleAP(form, wlan_id, band_root, index_id) {
  var idx = 0;
  var band_value = bandIdx[wlan_id];

  if (band_root == 0) {
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("2.4 GHz (B)", "0", false, false);
  } else if (band_root == 1) {
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);
  } else if (band_root == 2) {
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("2.4 GHz (B)", "0", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("2.4 GHz (B+G)", "2", false, false);
  } else if (band_root == 9) {
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("2.4 GHz (G+N)", "9", false, false);
  } else if (band_root == 10) {
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("2.4 GHz (B)", "0", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("2.4 GHz (B+G)", "2", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("2.4 GHz (G+N)", "9", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("2.4 GHz (B+G+N)", "10", false, false);
  } else if (band_root == 3) {
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (A)", "3", false, false);
  } else if (band_root == 7) {
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (N)", "7", false, false);
  } else if (band_root == 11) {
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (A)", "3", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (N)", "7", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (A+N)", "11", false, false);
  } else if (band_root == 63) {
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (AC)", "63", false, false);
  } else if (band_root == 71) {
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (N)", "7", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (AC)", "63", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (N+AC)", "71", false, false);
  } else if (band_root == 75) {
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (A)", "3", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (N)", "7", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (A+N)", "11", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (AC)", "63", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (N+AC)", "71", false, false);
    form.elements["wl_band_ssid" + index_id].options[idx++] = new Option("5 GHz (A+N+AC)", "75", false, false);
  }


  form.elements["wl_band_ssid" + index_id].selectedIndex = 0;
  form.elements["wl_band_ssid" + index_id].length = idx;
}


function showBandAP(form, wlan_id) {
  var idx = 0;
  var band_value = bandIdx[wlan_id];
  var Band2G5GSupport = form.elements["Band2G5GSupport"].value;
  var wlBandMode = form.elements["wlBandMode"].value;
  var i;
  var wlan_support_8812e;
  var wlan_support_8192f;
  var wlan_support_ac2g; //ac2g
  if (form.elements["wlan_support_8812e"])
    wlan_support_8812e = form.elements["wlan_support_8812e"].value;
  if (form.elements["wlan_support_8192f"])
    wlan_support_8192f = form.elements["wlan_support_8192f"].value;
  if (form.elements["wlan_support_ac2g"])
    wlan_support_ac2g = form.elements["wlan_support_ac2g"].value;
  if (form.name == "wizard") {
    switch (wlan_id) {
      case 0:
        if (form.elements["wlan1_phyband"].value == "5GHz")
          Band2G5GSupport = 2;
        else
          Band2G5GSupport = 1;
        break;

      case 1:
        if (form.elements["wlan2_phyband"].value == "5GHz")
          Band2G5GSupport = 2;
        else
          Band2G5GSupport = 1;
        break;

    }

  }

  if (Band2G5GSupport == 2 || wlBandMode == 3) // 2:PHYBAND_5G 3:BANDMODESIGNLE
  {
    form.elements["band" + wlan_id].options[idx++] = new Option("5 GHz (A)", "3", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("5 GHz (N)", "7", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("5 GHz (A+N)", "11", false, false);

    if ((wlan_support_8812e == 1) && (wlan_support_8192f != 1)) {
      form.elements["band" + wlan_id].options[idx++] = new Option("5 GHz (AC)", "63", false, false);
      form.elements["band" + wlan_id].options[idx++] = new Option("5 GHz (N+AC)", "71", false, false);
      form.elements["band" + wlan_id].options[idx++] = new Option("5 GHz (A+N+AC)", "75", false, false); //8812
    }
  }

  if (Band2G5GSupport == 1 || wlBandMode == 3) // 1:PHYBAND_2G 3:BANDMODESIGNLE
  {
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz (B)", "0", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz (N)", "7", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz (B+G)", "2", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz (G+N)", "9", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz (B+G+N)", "10", false, false);

    //ac2g
    //if(wlan_support_ac2g==1)
    //form.elements["band"+wlan_id].options[idx++] = new Option("2.4 GHz (B+G+N+AC)", "74", false, false);
  }


  for (i = 0; i < idx; i++) {
    if (form.elements["band" + wlan_id].options[i].value == band_value) {
      if (band_value == 7 && wlBandMode == 3) // 2g and 5g has the same band value in N.
      {
        var selectText = form.elements["band" + wlan_id].options[i].text.substr(0, 1);

        if ((Band2G5GSupport == 2 && selectText == '5') //2:PHYBAND_5G
          || (Band2G5GSupport == 1 && selectText == '2') //1:PHYBAND_2G
        ) {
          form.elements["band" + wlan_id].selectedIndex = i;
          break;
        }
      } else {
        form.elements["band" + wlan_id].selectedIndex = i;
        break;
      }
    }
  }

  form.elements["band" + wlan_id].length = idx;
}


function showBandClient(form, wlan_id) {
  var idx = 0;
  var band_value = bandIdx[wlan_id];
  var Band2G5GSupport = form.elements["Band2G5GSupport"].value;
  var wlBandMode = form.elements["wlBandMode"].value;
  var i;
  var wlan_support_8812e;
  var wlan_support_8192f;
  var wlan_support_ac2g; //ac2g
  if (form.elements["wlan_support_8812e"])
    wlan_support_8812e = form.elements["wlan_support_8812e"].value;
  if (form.elements["wlan_support_8192f"])
    wlan_support_8192f = form.elements["wlan_support_8192f"].value;
  if (form.elements["wlan_support_ac2g"])
    wlan_support_ac2g = form.elements["wlan_support_ac2g"].value;
  if (form.name == "wizard") {
    switch (wlan_id) {
      case 0:
        if (form.elements["wlan1_phyband"].value == "5GHz")
          Band2G5GSupport = 2;
        else
          Band2G5GSupport = 1;
        break;

      case 1:
        if (form.elements["wlan2_phyband"].value == "5GHz")
          Band2G5GSupport = 2;
        else
          Band2G5GSupport = 1;
        break;

    }

  }


  if (Band2G5GSupport == 2 || wlBandMode == 3) // 2:PHYBAND_5G 3:BANDMODESIGNLE
  {
    form.elements["band" + wlan_id].options[idx++] = new Option("5 GHz (A)", "3", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("5 GHz (N)", "7", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("5 GHz (A+N)", "11", false, false);

    if ((wlan_support_8812e == 1) && (wlan_support_8192f != 1)) {
      form.elements["band" + wlan_id].options[idx++] = new Option("5 GHz (AC)", "63", false, false);
      form.elements["band" + wlan_id].options[idx++] = new Option("5 GHz (N+AC)", "71", false, false);
      form.elements["band" + wlan_id].options[idx++] = new Option("5 GHz (A+N+AC)", "75", false, false); //8812
    }
  }

  if (Band2G5GSupport == 1 || wlBandMode == 3) // 1:PHYBAND_2G 3:BANDMODESIGNLE
  {
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz (B)", "0", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz (N)", "7", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz (B+G)", "2", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz (G+N)", "9", false, false);
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz (B+G+N)", "10", false, false);

    //ac2g
    //if(wlan_support_ac2g==1)
    //form.elements["band"+wlan_id].options[idx++] = new Option("2.4 GHz (B+G+N+AC)", "74", false, false);
  }

  if (wlBandMode == 3) //ac2g
  {
    form.elements["band" + wlan_id].options[idx++] = new Option("2.4GHz + 5 GHz (A+B+G+N)", "14", false, false);

    if (wlan_support_ac2g == 1)
      form.elements["band" + wlan_id].options[idx++] = new Option("2.4 GHz + 5 GHz (A+B+G+N+AC)", "78", false, false);
  }

  for (i = 0; i < idx; i++) {
    if (form.elements["band" + wlan_id].options[i].value == band_value) {
      if (band_value == 7 && wlBandMode == 3) // 2g and 5g has the same band value in N.
      {
        var selectText = form.elements["band" + wlan_id].options[i].text.substr(0, 1);

        if ((Band2G5GSupport == 2 && selectText == '5') //2:PHYBAND_5G
          || (Band2G5GSupport == 1 && selectText == '2') //1:PHYBAND_2G
        ) {
          form.elements["band" + wlan_id].selectedIndex = i;
          break;
        }
      } else {
        form.elements["band" + wlan_id].selectedIndex = i;
        break;
      }
    }
  }

  form.elements["band" + wlan_id].length = idx;
}

function showBand(form, wlan_id) {
  if (APMode[wlan_id] != 1)
    showBandAP(form, wlan_id);
  else
    showBandClient(form, wlan_id);
}

function get_by_id(id) {
  with(document) {
    return getElementById(id);
  }
}

function get_by_name(name) {
  with(document) {
    return getElementsByName(name);
  }
}

function updateMode(form, wlan_id) {
  var chan_boundid;
  var controlsidebandid;
  var wlan_wmm1;
  var wlan_wmm2;
  var networktype;
  var mode_idx = form.elements["mode" + wlan_id].selectedIndex;
  var mode_value = form.elements["mode" + wlan_id].options[mode_idx].value;
  var idx_value = form.elements["band" + wlan_id].selectedIndex;
  var band_value = form.elements["band" + wlan_id].options[idx_value].value;

  if (form.elements["mode" + wlan_id].selectedIndex != 1) {
    if (APMode[wlan_id] == 1) {
      if (bandIdxAP[wlan_id] < 0) {
        bandIdx[wlan_id] = 2; // set B+G as default
      } else {
        bandIdx[wlan_id] = bandIdxAP[wlan_id];
      }
    }
  } else {
    if (APMode[wlan_id] != 1) {
      if (bandIdxClient[wlan_id] < 0) {
        if (RFType[wlan_id] == 10)
          bandIdx[wlan_id] = 2; // set B+G as default
        else
          bandIdx[wlan_id] = 6; // set A+B+G as default
      } else {
        bandIdx[wlan_id] = bandIdxClient[wlan_id];
      }
    }
  }
  APMode[wlan_id] = form.elements["mode" + wlan_id].selectedIndex;
  showBand(form, wlan_id);
  if (form == document.wlanSetup) {
    wlan_wmm1 = form.elements["wlanwmm" + wlan_id];
    wlan_wmm2 = get_by_id("wlan_wmm");
  }

  networktype = form.elements["type" + wlan_id];
  if (mode_value != 1) {
    networktype.disabled = true;
  } else {
    networktype.selectedIndex = networkType[wlan_id];
    networktype.disabled = false;
  }

  if (form.name == "wlanSetup") {
    chan_boundid = get_by_id("channel_bounding");
    controlsidebandid = get_by_id("control_sideband");
  } else {
    chan_boundid = get_by_id("channel_bounding" + wlan_id);
    controlsidebandid = get_by_id("control_sideband" + wlan_id);
  }
  if (bandIdx[wlan_id] == 9 || bandIdx[wlan_id] == 10 || bandIdx[wlan_id] == 7 || bandIdx[wlan_id] == 11 || bandIdx[wlan_id] == 14 || bandIdx[wlan_id] == 63 || bandIdx[wlan_id] == 71 || bandIdx[wlan_id] == 75) {
    chan_boundid.style.display = "";
    controlsidebandid.style.display = "";
    if (form == document.wlanSetup) {
      //wlan_wmm1.disabled = true;
      //wlan_wmm2.disabled = true;
    }
  } else {
    chan_boundid.style.display = "none";
    controlsidebandid.style.display = "none";
    if (form == document.wlanSetup) {
      //wlan_wmm1.disabled = false;
      //wlan_wmm2.disabled = false;
    }
  }
  updateIputState(form, wlan_id);
  if (form == document.wizard) {
    var chan_number_idx = form.elements["chan" + wlan_id].selectedIndex;
    var chan_number = form.elements["chan" + wlan_id].options[chan_number_idx].value;
    if (chan_number == 0)
      disableTextField(form.elements["controlsideband" + wlan_id]);
    else {
      if (form.elements["channelbound" + wlan_id].selectedIndex == "0")
        disableTextField(form.elements["controlsideband" + wlan_id]);
      else if (form.elements["channelbound" + wlan_id].selectedIndex == "2") //8812
        disableTextField(form.elements["controlsideband" + wlan_id]);
      else
        enableTextField(form.elements["controlsideband" + wlan_id]);
    }
  }
}

function updateBand(form, wlan_id) {
  var band_index = form.elements["band" + wlan_id].selectedIndex;
  var band_value = form.elements["band" + wlan_id].options[band_index].value;
  if (APMode[wlan_id] != 1) {
    bandIdxAP[wlan_id] = band_value;
  } else {
    bandIdxClient[wlan_id] = band_value;
  }

  updateChan(form, wlan_id);

}

function updateType(form, wlan_id) {
  var mode_selected = 0;
  var Type_selected = 0;
  var index_channelbound = 0;
  updateChan(form, wlan_id);
  updateIputState(form, wlan_id);
  //updateRepeaterState(form, wlan_id);
  //Type_selected = form.elements["type"+wlan_id].selectedIndex;
  mode_selected = form.elements["mode" + wlan_id].selectedIndex;
  //if client and infrastructure mode
  if (mode_selected == 1) {
    //if(Type_selected == 0){
    disableTextField(form.elements["controlsideband" + wlan_id]);
    disableTextField(form.elements["channelbound" + wlan_id]);
    /*}else{
			enableTextField(form.elements["channelbound"+wlan_id]);
			index_channelbound=form.elements["channelbound"+wlan_id].selectedIndex;
		if(index_channelbound ==0)
			disableTextField(form.elements["controlsideband"+wlan_id]);
		else if(index_channelbound ==2)
			disableTextField(form.elements["controlsideband"+wlan_id]);
		else
			enableTextField(form.elements["controlsideband"+wlan_id]);
		}*/
  }

  var chan_number_idx = form.elements["chan" + wlan_id].selectedIndex;
  var chan_number = form.elements["chan" + wlan_id].options[chan_number_idx].value;
  if (chan_number == 0)
    disableTextField(form.elements["controlsideband" + wlan_id]);
  else {
    if (form.elements["channelbound" + wlan_id].selectedIndex == "0")
      disableTextField(form.elements["controlsideband" + wlan_id]);
    else if (form.elements["channelbound" + wlan_id].selectedIndex == "2")
      disableTextField(form.elements["controlsideband" + wlan_id]);
    else
      enableTextField(form.elements["controlsideband" + wlan_id]);
  }
}

function pskFormatChange(form, wlan_id) {
  if (form.elements["pskFormat" + wlan_id].selectedIndex == 0) {
    form.elements["pskValue" + wlan_id].maxLength = "63";
  } else {
    form.elements["pskValue" + wlan_id].maxLength = "64";
  }
}
/*==============================================================================*/
/*   wlwpa.htm */
function disableRadioGroup(radioArrOrButton) {
  if (radioArrOrButton.type && radioArrOrButton.type == "radio") {
    var radioButton = radioArrOrButton;
    var radioArray = radioButton.form[radioButton.name];
  } else
    var radioArray = radioArrOrButton;
  radioArray.disabled = true;
  for (var b = 0; b < radioArray.length; b++) {
    if (radioArray[b].checked) {
      radioArray.checkedElement = radioArray[b];
      break;
    }
  }
  for (var b = 0; b < radioArray.length; b++) {
    radioArray[b].disabled = true;
    radioArray[b].checkedElement = radioArray.checkedElement;
  }
}

function enableRadioGroup(radioArrOrButton) {
  if (radioArrOrButton.type && radioArrOrButton.type == "radio") {
    var radioButton = radioArrOrButton;
    var radioArray = radioButton.form[radioButton.name];
  } else
    var radioArray = radioArrOrButton;

  radioArray.disabled = false;
  radioArray.checkedElement = null;
  for (var b = 0; b < radioArray.length; b++) {
    radioArray[b].disabled = false;
    radioArray[b].checkedElement = null;
  }
}

function preserve() {
  this.checked = this.storeChecked;
}

function disableCheckBox(checkBox) {
  if (!checkBox.disabled) {
    checkBox.disabled = true;
    if (!document.all && !document.getElementById) {
      checkBox.storeChecked = checkBox.checked;
      checkBox.oldOnClick = checkBox.onclick;
      checkBox.onclick = preserve;
    }
  }
}

function enableCheckBox(checkBox) {
  if (checkBox.disabled) {
    checkBox.disabled = false;
    if (!document.all && !document.getElementById)
      checkBox.onclick = checkBox.oldOnClick;
  }
}

function openWindow(url, windowName, wide, high) {
  if (document.all)
    var xMax = screen.width,
      yMax = screen.height;
  else if (document.layers)
    var xMax = window.outerWidth,
      yMax = window.outerHeight;
  else
    var xMax = 640,
      yMax = 500;
  var xOffset = (xMax - wide) / 2;
  var yOffset = (yMax - high) / 3;

  var settings = 'width=' + wide + ',height=' + high + ',screenX=' + xOffset + ',screenY=' + yOffset + ',top=' + yOffset + ',left=' + xOffset + ', resizable=yes, toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes';
  window.open(url, windowName, settings);
}

function ppp_getDigit(str, num) {
  i = 1;
  // replace the char '/' with character '.'
  str = str.replace(/[/]/, ".");
  if (num != 1) {
    while (i != num && str.length != 0) {
      if (str.charAt(0) == '.') {
        i++;
      }
      str = str.substring(1);
    }
    if (i != num)
      return -1;
  }
  for (i = 0; i < str.length; i++) {
    if (str.charAt(i) == '.') {
      str = str.substring(0, i);
      break;
    }
  }
  if (str.length == 0)
    return -1;
  d = parseInt(str, 10);
  return d;
}

function ppp_checkDigitRange(str, num, min, max) {
  d = ppp_getDigit(str, num);
  if (d > max || d < min)
    return false;
  return true;
}

function ppp_validateKey(str) {
  for (var i = 0; i < str.length; i++) {
    if ((str.charAt(i) >= '0' && str.charAt(i) <= '9') || (str.charAt(i) == '.') || (str.charAt(i) == '/'))
      continue;
    return 0;
  }
  return 1;
}

function validateKey(str) {
  for (var i = 0; i < str.length; i++) {
    if ((str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
      (str.charAt(i) == '.'))
      continue;
    return 0;
  }
  return 1;
}

function getDigit(str, num) {
  var i = 1;
  if (num != 1) {
    while (i != num && str.length != 0) {
      if (str.charAt(0) == '.') {
        i++;
      }
      str = str.substring(1);
    }
    if (i != num)
      return -1;
  }
  for (i = 0; i < str.length; i++) {
    if (str.charAt(i) == '.') {
      str = str.substring(0, i);
      break;
    }
  }
  if (str.length == 0)
    return -1;
  var d = parseInt(str, 10);
  return d;
}

function checkDigitRange(str, num, min, max) {
  var d = getDigit(str, num);
  if (d > max || d < min)
    return false;
  return true;
}

function saveChanges_passwd(form) {
	var str = form.elements["newpass"].value;
    if (IsKorean(str)) {
      alert("비밀번호에는 한글을 입력할 수 없습니다!.");
      form.elements["newpass"].focus();
      return false;
    }
    return true;
}

function check_wpa_psk(form, wlan_id, is_changed) {
  var wpapsk_format_idx = form.elements["pskFormat" + wlan_id].selectedIndex;
  var str = form.elements["pskValue" + wlan_id].value;

  if (wpapsk_format_idx == 0) {
    if (str.length < 8) {
      alert('Pre-Shared Key가 8자 이상이어야 합니다');
      form.elements["pskValue" + wlan_id].focus();
      return false;
    }
    if (str.length > 63) {
      alert('Pre-Shared Key가 63자 이하이어야 합니다.');
      form.elements["pskValue" + wlan_id].focus();
      return false;
    }
  } else {
    if (str.length != 64) {
      alert('Hex 타입의 Pre-Shared Key는 64자 입니다.');
      form.elements["pskValue" + wlan_id].focus();
      return false;
    }
  }
  /* KDH DAVO, APNRTL-181*/
  if (wpapsk_format_idx == 0) {
    //ASCII
    if (IsKorean(str)) {
      alert("Pre-Shared Key는 한글을 입력할 수 없습니다.");
      form.elements["pskValue" + wlan_id].focus();
      return false;
    }
  } else {
    //HEX
    if(is_changed) {
    	if (checkHex(str) == 0) {
      		alert("Pre-Shared Key는 Hex 타입(0-9/A-F)만 입력 가능 합니다.");
      		form.elements["pskValue" + wlan_id].focus();
      	return false;
    	}
    }
  }

  return true;
}

function check_to_passwd(str) {

  for (var i = 0; i < str.length; i++) {
    if ((str.charAt(i) >= '0' && str.charAt(i) <= '9') || (str.charAt(i) >= 'a' && str.charAt(i) <= 'z') || (str.charAt(i) >= 'A' && str.charAt(i) <= 'Z') ||
    	(str.charAt(i) == '`') || (str.charAt(i) == '~') || (str.charAt(i) == '!') || (str.charAt(i) == '@') || (str.charAt(i) == '#') || (str.charAt(i) == '$') ||
    	(str.charAt(i) == '%') || (str.charAt(i) == '^') || (str.charAt(i) == '&') || (str.charAt(i) == '*') || (str.charAt(i) == '(') || (str.charAt(i) == ')') ||
    	(str.charAt(i) == '-') || (str.charAt(i) == '_') || (str.charAt(i) == '+') || (str.charAt(i) == '=') || (str.charAt(i) == ' ') ) {
      	continue;
    }
    return 0;
  }
  return 1;
}

function saveChanges_wpa(form, wlan_id, is_changed) {
  method = form.elements["method" + wlan_id];
  wpaAuth = form.elements["wpaAuth" + wlan_id];


  if (method.selectedIndex <= 2 && (wpaAuth.value == "psk" || wpaAuth[1].checked))
    return check_wpa_psk(form, wlan_id, is_changed);

  if (form.elements["use1x" + wlan_id].value != "OFF" && form.elements["radiusPort" + wlan_id].disabled == false) {
    if (form.elements["radiusPort" + wlan_id].value == "") {
      alert("인증 서버 포트 번호가 비어있습니다! 1에서 65535 사이의 값을 정수를 입력해야 합니다.");
      form.elements["radiusPort" + wlan_id].focus();
      return false;
    }
    if (validateKey(form.elements["radiusPort" + wlan_id].value) == 0) {
      alert("인증 서버의 포트 번호가 올바르지 않습니다! 1에서 65535 사이의 값을 정수를 입력해야 합니다.");
      form.elements["radiusPort" + wlan_id].focus();
      return false;
    }
    port = parseInt(form.elements["radiusPort" + wlan_id].value, 10);

    if (port > 65535 || port < 1) {
      alert("인증 서버의 포트 번호가 올바르지 않습니다! 1에서 65535 사이의 값을 정수를 입력해야 합니다.");
      form.elements["radiusPort" + wlan_id].focus();
      return false;
    }

    if (checkIpAddr(form.elements["radiusIP" + wlan_id], '인증 서버의 IP 주소가 올바르지 않습니다!') == false)
      return false;
  }

  return true;
}
/*==============================================================================*/
/*   tcpiplan.htm  */
function checkMask(str, num) {
  var d = getDigit(str, num);
  if (num == 1) {
    if (!(d == 128 || d == 192 || d == 224 || d == 240 || d == 248 || d == 252 || d == 254 || d == 255))
      return false;
  } else {
    if (!(d == 0 || d == 128 || d == 192 || d == 224 || d == 240 || d == 248 || d == 252 || d == 254 || d == 255))
      return false;
  }
  return true;
}

function checkWholeMask(str) {
  if (str.length == 0)
    return false;
  var d1 = getDigit(str, 1);
  var d2 = getDigit(str, 2);
  var d3 = getDigit(str, 3);
  var d4 = getDigit(str, 4);
  if (d1 == -1 || d2 == -1 || d3 == -1 || d4 == -1 || d1 == 0 || d1 != 255)
    return false;
  if (d1 != 255 && d2 != 0)
    return false;
  if (d2 != 255 && d3 != 0)
    return false;
  if (d3 != 255 && d4 != 0)
    return false;
  return true;
}

function checkSubnet(ip, mask, client) {
  ip_d = getDigit(ip, 1);
  mask_d = getDigit(mask, 1);
  client_d = getDigit(client, 1);
  if ((ip_d & mask_d) != (client_d & mask_d))
    return false;

  ip_d = getDigit(ip, 2);
  mask_d = getDigit(mask, 2);
  client_d = getDigit(client, 2);
  if ((ip_d & mask_d) != (client_d & mask_d))
    return false;

  ip_d = getDigit(ip, 3);
  mask_d = getDigit(mask, 3);
  client_d = getDigit(client, 3);
  if ((ip_d & mask_d) != (client_d & mask_d))
    return false;

  ip_d = getDigit(ip, 4);
  mask_d = getDigit(mask, 4);
  client_d = getDigit(client, 4);
  if ((ip_d & mask_d) != (client_d & mask_d))
    return false;

  return true;
}

function checkIPMask(field) {

  if (field.value == "") {
    alert("Subnet mask는 비워둘 수 없습니다! 4자리 숫자로 채워야 합니다( ex: xxx.xxx.xxx.xxx).");
    field.value = field.defaultValue;
    field.focus();
    return false;
  }

  if (field.value == "0.0.0.0") {
    alert("Subnet mask 주소는 0.0.0.0을 사용할 수 없습니다!");
    field.value = field.defaultValue;
    field.focus();
    return false;
  }

  if (validateKey(field.value) == 0) {
    alert("Subnet mask가 올바르지 않습니다. 반드시 숫자(0-9)를 입력해야 합니다.");
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!checkMask(field.value, 1)) {
    alert('Invalid subnet mask in 1st digit.\nIt should be the number of 128, 192, 224, 240, 248, 252 or 254');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }

  if (!checkMask(field.value, 2)) {
    alert('Invalid subnet mask in 2nd digit.\nIt should be the number of 0, 128, 192, 224, 240, 248, 252 or 254');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!checkMask(field.value, 3)) {
    alert('Invalid subnet mask in 3rd digit.\nIt should be the number of 0, 128, 192, 224, 240, 248, 252 or 254');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!checkMask(field.value, 4)) {
    alert('Invalid subnet mask in 4th digit.\nIt should be the number of 0, 128, 192, 224, 240, 248, 252 or 254');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!checkWholeMask(field.value)) {
    alert("Invalid subnet mask.");
    field.value = field.defaultValue;
    field.focus;
    return false;
  }

}

function checkIpAddr(field, msg) {
  if (field.value == "") {
    alert("IP 주소가 비어있습니다! 예) xxx.xxx.xxx.xxx.");
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (validateKey(field.value) == 0) {
    alert(msg + ' 값. 0에서 9 사이의 값을 입력해야 합니다.');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!checkDigitRange(field.value, 1, 0, 255)) {
    alert(msg + ' 1번째 영역. 0에서 255사이의 값을 입력해야 합니다.');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!checkDigitRange(field.value, 2, 0, 255)) {
    alert(msg + ' 2번째 영역. 0에서 255사이의 값을 입력해야 합니다.');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!checkDigitRange(field.value, 3, 0, 255)) {
    alert(msg + ' 3번째 영역. 0에서 255사이의 값을 입력해야 합니다.');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!checkDigitRange(field.value, 4, 0, 255)) {
    alert(msg + ' 4번째 영역. 0에서 255사이의 값을 입력해야 합니다.');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  return true;
}

/*
 * ipv4_to_unsigned_integer
 *	Convert an IPv4 address dotted string to an unsigned integer.
 */
function ipv4_to_unsigned_integer(ipaddr) {
  var ip = ipaddr + "";
  var got = ip.match(/^\s*(\d{1,3})\s*[.]\s*(\d{1,3})\s*[.]\s*(\d{1,3})\s*[.]\s*(\d{1,3})\s*$/);
  if (!got) {
    return null;
  }
  var x = 0;
  var q = 0;
  for (var i = 1; i <= 4; i++) {
    q = parseInt(got[i], 10);
    if (q < 0 || q > 255) {
      return null;
    }
    x = x * 256 + q;
  }
  return x;
}

function checkHostIPValid(ipAddr, mask, msg) {
  if (!checkIpAddr(ipAddr, msg)) return false;
  var ip_int = ipv4_to_unsigned_integer(ipAddr.value);
  var mask_int = ipv4_to_unsigned_integer(mask.value);
  var mask_str = mask_int.toString(2);
  //alert(mask_str);
  var index0 = 32 - mask_str.indexOf('0');
  //alert("mask len:"+index0);

  var tmp = Math.pow(2, index0) - 1;
  //alert("tmp:"+tmp);

  //var tmp_str = tmp.toString(2);
  //alert("tmp_str:"+tmp_str);

  var host = ip_int & tmp;
  //alert("host:"+host);

  if (host == 0 || host == tmp) {
    alert(msg);
    return false;
  }
  return true;

}

//check ipv6 addr available
function checkIpv6DigitRange(ipField) {
  var reg = /[0-9a-fA-F]{4}/;
  var value = parseInt(ipField.value, 16);
  if (value < 0 || value > parseInt("ffff", 16) || isNaN(value) || !reg.exec(ipField.value)) {
    //ipField.value = ipField.defaultValue;
    ipField.focus();
    ipField.select();
    return false;
  }
  return true;
}

function checkIpv6Addr(ipField0, ipField1, ipField2, ipField3, ipField4, ipField5, ipField6, ipField7, prefixField, msg) {
  if (!checkIpv6DigitRange(ipField0) || !checkIpv6DigitRange(ipField1) || !checkIpv6DigitRange(ipField2) ||
    !checkIpv6DigitRange(ipField3) || !checkIpv6DigitRange(ipField4) || !checkIpv6DigitRange(ipField5) ||
    !checkIpv6DigitRange(ipField6) || !checkIpv6DigitRange(ipField7)) {
    alert(msg + ' ipv6 address invalid!');
    return false;
  }
  var reg = /[^0-9]/;
  if (!prefixField) return false;
  if (reg.exec(prefixField.value) || prefixField.value < 0 || prefixField.value > 128) {
    //prefixField.value = prefixField.defaultValue;
    prefixField.focus();
    prefixField.select();
    alert(msg + ' ipv6 prefix must between 0-128!');
    return false;
  }
  return true;
}

function isIntVal(strVal) {
  var reg = /^[1-9][0-9]*$/;
  if (!reg.exec(strVal))
    return false;
  else
    return true;
}

function checkFieldDigitRange(field, start, end, msg) {
  var value = parseInt(field.value, 10);
  if (value < start || value > end || isNaN(value) || !isIntVal(field.value)) {
    //field.value = field.defaultValue;
    field.focus();
    field.select();
    alert(msg + ' must between ' + start + '-' + end);
    return false;
  }
  return true;
}

function checkFieldEmpty(field, msg) {
  if (!field) return false;
  if (field.value == "") {
    //field.value = field.defaultValue;
    field.focus();
    field.select();
    alert(msg);
    return false;
  }
  return true;
}
// add for "All MAC Address field can't reject 00:00:00:00:00:00/ff:ff:ff:ff:ff:ff MAC Address" issue
function checkMacAddr_is_legal(field) {
  var reg = /[0-9a-fA-F]{12}/;
  if (!field) return false;
  if (!reg.exec(field.value)) {
    field.focus();
    field.select();
    alert("MAC 주소가 올바르지 않습니다. 반드시 hex(0-9 or a-f)로 입력해야 합니다.");
    return false;
  }
  return true;
}

function checkMacAddr_is_zero(field) {
  if (!field) return false;
  if (field.value == "000000000000") {
    field.focus();
    field.select();
    alert("MAC 주소가 올바르지 않습니다. 00:00:00:00:00:00 과 같이 입력해야 합니다.");
    return false;
  }
  return true;
}

function checkMacAddr_is_broadcast(field) {
  if (!field) return false;
  if (field.value == "ffffffffffff") {
    field.focus();
    field.select();
    alert("MAC 주소가 올바르지 않습니다. ff:ff:ff:ff:ff:ff과 같이 입력해야 됩니다.");
    return false;
  }
  return true;
}

function checkMacAddr_is_muticast(field) {
  //var reg = /01005[eE][0-7][0-9a-fA-F]{5}/;
  //if(reg.exec(field.value))
  if (parseInt(field.value.substr(0, 2), 16) & 0x01 != 0) {
    field.focus();
    field.select();
    alert("MAC 주소가 올바르지 않습니다. Multicast mac 주소가 01:00:5e:00:00:00 과 01:00:5e:7f:ff:ff 사이가 아닙니다.");
    return false;
  }
  return true;
}

function checkMacAddr(field, msg) {
  return (checkMacAddr_is_legal(field) && checkMacAddr_is_zero(field) && checkMacAddr_is_broadcast(field) && checkMacAddr_is_muticast(field));
}

function ppp_checkSubNetFormat(field, msg) {
  if (field.value == "") {
    alert("IP address cannot be empty! It should be filled with 4 digit numbers as xxx.xxx.xxx.xxx.");
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (ppp_validateKey(field.value) == 0) {
    alert(msg + ' value. It should be the decimal number (0-9).');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!ppp_checkDigitRange(field.value, 1, 0, 255)) {
    alert(msg + ' range in 1st digit. It should be 0-255.');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!ppp_checkDigitRange(field.value, 2, 0, 255)) {
    alert(msg + ' range in 2nd digit. It should be 0-255.');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!ppp_checkDigitRange(field.value, 3, 0, 255)) {
    alert(msg + ' range in 3rd digit. It should be 0-255.');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!ppp_checkDigitRange(field.value, 4, 0, 254)) {
    alert(msg + ' range in 4th digit. It should be 1-254.');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  if (!ppp_checkDigitRange(field.value, 5, 1, 32)) {
    alert(msg + ' range in 5th digit. It should be 1-32.');
    field.value = field.defaultValue;
    field.focus();
    return false;
  }
  return true;
}

/////////////////////////////////////////////////////////////////////////////
/*wlwep.htm*/
function validateKey_wep(form, idx, str, len, wlan_id) {
  if (idx >= 0) {

  	if (str.length ==0) {
  		idx++;
  		alert('Key ' + idx + '의 값이 비어있습니다.');
  		return 0;
  	}

    if (str.length != len) {
      idx++;
      alert('Key ' + idx + ' 의 길이가 올바르지 않습니다. ' + len + '자 로 입력해 주세요.');
      return 0;
    }
  } else {
    if (str.length != len) {
      alert('WEP Key 의 길이가 올바르지 않습니다. ' + len + '자로 입력해 주세요.');
      return 0;
    }
  }
  if (str == "*****" ||
    str == "**********" ||
    str == "*************" ||
    str == "**************************")
    return 1;

  if (form.elements["format" + wlan_id].selectedIndex == 0) {
    if (IsKorean(str)) {
      idx++;
      alert('Key ' + idx + '에 한글을 입력할 수 없습니다.');
      return 0;
    }
    return 1;
  }

  for (var i = 0; i < str.length; i++) {
    if ((str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
      (str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
      (str.charAt(i) >= 'A' && str.charAt(i) <= 'F'))
      continue;

    alert("key 값이 올바르지 않습니다. 16진수를 입력해야 합니다. (0-9 또는 a-f)");
    return 0;
  }

  return 1;
}








function lengthClick(form, wlan_id) {
  updateFormat(form, wlan_id);
}





function getRefToDivNest(divID, oDoc) {
  if (!oDoc) {
    oDoc = document;
  }
  if (document.layers) {
    if (oDoc.layers[divID]) {
      return oDoc.layers[divID];
    } else {
      for (var x = 0, y; !y && x < oDoc.layers.length; x++) {
        y = getRefToDivNest(divID, oDoc.layers[x].document);
      }
      return y;
    }
  }
  if (document.getElementById) {
    return document.getElementById(divID);
  }
  if (document.all) {
    return document.all[divID];
  }
  return document[divID];
}

function progressBar(oBt, oBc, oBg, oBa, oWi, oHi, oDr) {
  MWJ_progBar++;
  this.id = 'MWJ_progBar' + MWJ_progBar;
  this.dir = oDr;
  this.width = oWi;
  this.height = oHi;
  this.amt = 0;
  //write the bar as a layer in an ilayer in two tables giving the border
  document.write('<span id = "progress_div" class = "off" > <table border="0" cellspacing="0" cellpadding="' + oBt + '">' +
    '<tr><td>Please wait...</td></tr><tr><td bgcolor="' + oBc + '">' +
    '<table border="0" cellspacing="0" cellpadding="0"><tr><td height="' + oHi + '" width="' + oWi + '" bgcolor="' + oBg + '">');
  if (document.layers) {
    document.write('<ilayer height="' + oHi + '" width="' + oWi + '"><layer bgcolor="' + oBa + '" name="MWJ_progBar' + MWJ_progBar + '"></layer></ilayer>');
  } else {
    document.write('<div style="position:relative;top:0px;left:0px;height:' + oHi + 'px;width:' + oWi + ';">' +
      '<div style="position:absolute;top:0px;left:0px;height:0px;width:0;font-size:1px;background-color:' + oBa + ';" id="MWJ_progBar' + MWJ_progBar + '"></div></div>');
  }
  document.write('</td></tr></table></td></tr></table></span>\n');
  this.setBar = resetBar; //doing this inline causes unexpected bugs in early NS4
  this.setCol = setColour;
}

function resetBar(a, b) {
  //work out the required size and use various methods to enforce it
  this.amt = (typeof(b) == 'undefined') ? a : b ? (this.amt + a) : (this.amt - a);
  if (isNaN(this.amt)) {
    this.amt = 0;
  }
  if (this.amt > 1) {
    this.amt = 1;
  }
  if (this.amt < 0) {
    this.amt = 0;
  }
  var theWidth = Math.round(this.width * ((this.dir % 2) ? this.amt : 1));
  var theHeight = Math.round(this.height * ((this.dir % 2) ? 1 : this.amt));
  var theDiv = getRefToDivNest(this.id);
  if (!theDiv) {
    window.status = 'Progress: ' + Math.round(100 * this.amt) + '%';
    return;
  }
  if (theDiv.style) {
    theDiv = theDiv.style;
    theDiv.clip = 'rect(0px ' + theWidth + 'px ' + theHeight + 'px 0px)';
  }
  var oPix = document.childNodes ? 'px' : 0;
  theDiv.width = theWidth + oPix;
  theDiv.pixelWidth = theWidth;
  theDiv.height = theHeight + oPix;
  theDiv.pixelHeight = theHeight;
  if (theDiv.resizeTo) {
    theDiv.resizeTo(theWidth, theHeight);
  }
  theDiv.left = ((this.dir != 3) ? 0 : this.width - theWidth) + oPix;
  theDiv.top = ((this.dir != 4) ? 0 : this.height - theHeight) + oPix;
}

function setColour(a) {
  //change all the different colour styles
  var theDiv = getRefToDivNest(this.id);
  if (theDiv.style) {
    theDiv = theDiv.style;
  }
  theDiv.bgColor = a;
  theDiv.backgroundColor = a;
  theDiv.background = a;
}


function showcontrolsideband_updated(form, band, wlan_id, rf_num, index) {
  var idx = 0;
  var i;
  var controlsideband_str;

  if ((band == 7 && index == 1) || band == 11 || band == 63 || band == 71 || band == 75) {
    form.elements["controlsideband" + wlan_id].options[idx++] = new Option("Auto", "0", false, false);
    form.elements["controlsideband" + wlan_id].options[idx++] = new Option("Auto", "1", false, false);
  } else {
    form.elements["controlsideband" + wlan_id].options[idx++] = new Option("Upper", "0", false, false);
    form.elements["controlsideband" + wlan_id].options[idx++] = new Option("Lower", "1", false, false);
  }

  form.elements["controlsideband" + wlan_id].length = idx;
  form.elements["controlsideband" + wlan_id].selectedIndex = 0;

  for (i = 0; i < idx; i++) {
    controlsideband_str = form.elements["controlsideband" + wlan_id].options[i].value;
    if (wlan_controlsideband[wlan_id] == controlsideband_str)
      form.elements["controlsideband" + wlan_id].selectedIndex = i;
  }
}

function showchannelbound_updated(form, band, wlan_id, rf_num, wlchan_setupmode) {
  var idx = 0;
  var i;
  var channelbound_str;
  var backup_chanbond = -1;
  var ac_mode = 0;
  
  if ( wlan_id == 0 ) {
  	  //5G
  	  if ( form.elements["channelbound" + wlan_id].selectedIndex >= 0)
  	  	backup_chanbond = form.elements["channelbound" + wlan_id].selectedIndex;
  	  
	  form.elements["channelbound" + wlan_id].options[idx++] = new Option("20MHz", "0", false, false);
	  form.elements["channelbound" + wlan_id].options[idx++] = new Option("20/40MHz", "1", false, false);
	
	  if (band == 75 || band == 71 || band == 63 || band == 74) { //ac2g
	    form.elements["channelbound" + wlan_id].options[idx++] = new Option("20/40/80MHz", "2", false, false);
	    ac_mode = 1;
	  }
	  form.elements["channelbound" + wlan_id].length = idx;
	  if ( backup_chanbond >= 0) {
	  	form.elements["channelbound" + wlan_id].selectedIndex = ((ac_mode == 1)?backup_chanbond:(backup_chanbond-1));
	  }
	  else {
	  	form.elements["channelbound" + wlan_id].selectedIndex = (idx-1);
	  }
  } else {
  	  //2.4G  	  
  	  if ( wlchan_setupmode == 0 ) {
  	  	  //자동
  	  	  backup_chanbond = form.elements["channelbound" + wlan_id].selectedIndex;
  	  	  if ( backup_chanbond < 0) {
  	  	  	backup_chanbond = (form.elements["channelbound_manual" + wlan_id].selectedIndex +1);
  	  	  }
  	  	  	
  	  	  form.elements["channelbound" + wlan_id].options[idx++] = new Option("자동", "5", false, false);
  	  	  form.elements["channelbound" + wlan_id].options[idx++] = new Option("20MHz", "0", false, false);
	      form.elements["channelbound" + wlan_id].options[idx++] = new Option("20/40MHz", "1", false, false);	      
	      form.elements["channelbound" + wlan_id].length = idx;	      
	      if ( backup_chanbond >= 0)
		  	form.elements["channelbound" + wlan_id].selectedIndex = backup_chanbond;
		  else
		  	form.elements["channelbound" + wlan_id].selectedIndex = idx-1;
  	  } else {
  	  	  //수동
  	  	  backup_chanbond = form.elements["channelbound_manual" + wlan_id].selectedIndex;
  	      if ( backup_chanbond < 0) {
  	  	  	backup_chanbond = form.elements["channelbound" + wlan_id].selectedIndex;
  	  	  	if ( backup_chanbond > 0)
  	  	  		backup_chanbond = (backup_chanbond-1);
  	  	  }
  	      form.elements["channelbound_manual" + wlan_id].options[idx++] = new Option("20MHz", "0", false, false);
	      form.elements["channelbound_manual" + wlan_id].options[idx++] = new Option("20/40MHz", "1", false, false);	      
	      form.elements["channelbound_manual" + wlan_id].length = idx;	      
	      if ( backup_chanbond >= 0)
		  	form.elements["channelbound_manual" + wlan_id].selectedIndex = backup_chanbond;
		  else
		  	form.elements["channelbound_manual" + wlan_id].selectedIndex = idx;
	  }
  }

  if ( wlan_id == 1 && wlchan_setupmode != 0 ) {
  	document.getElementById('channel_bounding').style.display = 'none';
  	document.getElementById('channel_bounding_manual').style.display = '';
  } else {
  	document.getElementById('channel_bounding').style.display = '';
  	document.getElementById('channel_bounding_manual').style.display = 'none';
  }
}

// number check
function IsDigit(str) {
  var digits = "0123456789";
  var ch;

  if (str.length == 0)
    return false;

  for (var i = 0; i < str.length; i++) {
    ch = str.charAt(i);
    if (digits.indexOf(ch) == -1)
      return false;
  }
  return true;
}

function inet_aton(a) {
  var n;

  n = a.split(/\./);
  if (n.length != 4)
    return 0;

  return ((n[0] << 24) | (n[1] << 16) | (n[2] << 8) | n[3]);
}

function inet_ntoa(n) {
  var a;

  a = (n >> 24) & 255;
  a += "."
  a += (n >> 16) & 255;
  a += "."
  a += (n >> 8) & 255;
  a += "."
  a += n & 255;

  return a;
}

/* Form Action
 * -------------------------------------------------------------------------- */
function exist(obj) {
  return ((typeof(obj) != "undefined") ? true : false);
}

var colorEnabled = '#ffffff';
var colorEnabledText = '#000000';
var colorDisabled = '#e6e6e6';
var colorDisabledText = '#b2b29f';

function formDisable(e) {
  if (!exist(e))
    return;

  e.disabled = true;

  if (e.type != 'radio' &&
    e.type != 'checkbox' &&
    e.type != 'select-multiple'
    /* && e.type != 'select-one'*/
  ) {
    e.style.background = colorDisabled;
    e.style.color = colorDisabledText;
  }
}

function formEnable(e) {
  if (!exist(e))
    return;

  e.disabled = false;

  if (e.type != 'radio' &&
    e.type != 'checkbox' &&
    e.type != 'select-multiple'
    /* && e.type != 'select-one'*/
  ) {
    e.style.background = colorEnabled;
    e.style.color = colorEnabledText;
  }
}

function IsHtmlComment(str) {
  var comment;

  for (var i = 0; i < str.length; i++) {
    comment = str.charCodeAt(i);
    if (comment == 60) {
      comment = str.charCodeAt(i + 1);
      if (comment == 33) {
        comment = str.charCodeAt(i + 2);
        if (comment == 45) {
          comment = str.charCodeAt(i + 3);
          if (comment == 45)
            return true;
        }
      }
    }
  }
  return false;
}
