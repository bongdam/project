/*redirect form*/
function get_form(page, wlan_id){
        return 'wlan_redriect.php?redirect-url='+page+'&wlan_id='+wlan_id ;
}
/*add_menuItem(URL,title)*/
function add_menuItem(frameset,url,name)
{
	var str;
	document.write("<td class=\"topnavoff\" valign=\"middle\">");
	str="<a href=\""+url+"\" target=\""+frameset+"\" id=\""+name+"\" rel=\""+name+"\" onclick=\"return on_click_menu(this);\">"+name+"</a>";
	document.write(str);
	document.write("</td>");
}

function add_topMenuItem(url,menu_name)
{
  add_menuItem("sub_menu",url,menu_name);
}

function add_subMenuItem(url,menu_name)
{
	var str;
	document.write("<tr height=\"35\">");
	document.write("<td class=\"topnavoff\">");
	str="<a href=\""+url+"\" target=\"content\" id=\""+menu_name+"\" rel=\""+menu_name+"\" onclick=\"return on_click_menu(this);\">"+menu_name+"</a>";
	document.write(str);
	document.write("</td>");
	document.write("</tr>");
}
function init_submenu(submenuId)
{
	if(document.getElementById(submenuId))
	{
		if(document.getElementById(submenuId).click)
		{
			document.getElementById(submenuId).click();
		}
		else
		{
			var evt  = document.createEvent('MouseEvents');
			evt.initEvent('click',true,true);
			document.getElementById(submenuId).dispatchEvent(evt);
		}
	}
}
/*draw_topnav*/
function draw_topnav(wlan_num,ipv6, isAdmin)
{
	add_topMenuItem("skb_sub_menu_setup.php","홈");
	add_topMenuItem("skb_sub_menu_tcpip.php","유선 설정");
	add_topMenuItem(get_form("skb_sub_menu_wlan.php",0),"무선 설정");
	add_topMenuItem("skb_sub_menu_firewall.php","방화벽");
	if (parseInt(isAdmin,10) == 0) {
		add_topMenuItem("skb_sub_menu_qos.php","QoS");
	}
	add_topMenuItem("skb_sub_menu_mng.php","관리");
	add_topMenuItem("skb_sub_menu_logout.php","운용모드설정");
	init_submenu("Status");

}

function draw_subnav_head()
{
	document.write("<table id=\"topnav_container\" border=\"0\" cellspacing=\"1\" summary=\"\">");
	document.write("<tbody>");
	document.write("<tr height=\"34\">");
	document.write("<td class=\"topHeaderMenu\">");
	document.write("<div id=\"topHeaderId\"></div>");
	document.write("</td></tr>");
}

function draw_subnav_tail()
{
	document.write("<tr><td class=\"subMenuDummy\"></td></tr>");
	document.write("</tbody></table>");
}

function draw_subnav_setup()
{
  //add_subMenuItem("skb_wizard.php","Wizard");
  add_subMenuItem("skb_status.php","상태정보");
  //add_subMenuItem("skb_opmode.php","Operation Mode");
}
function draw_subnav_wlan(is8021xClient, isAdmin)
{
	add_subMenuItem("skb_wlbasic.php","기본 설정");
	add_subMenuItem("skb_wladvanced.php","고급 설정");
	add_subMenuItem("skb_wlsecurity.php","보안 설정");
	if (parseInt(isAdmin,10) == 0) {
		//add_subMenuItem("skb_wlsecurity_redirect.php","웹 리다이렉션 설정");
//		add_subMenuItem("skb_wlsecurity_disclient.php","연결 해제 설정");
	}
	add_subMenuItem("skb_wlactrl.php","접근 제어 설정");
	add_subMenuItem("skb_sta_protection.php","무선접속 제한 서비스");
 // add_subMenuItem("skb_wlwds.php","WDS Setting");
	add_subMenuItem("skb_wlsurvey.php","AP 검색");
	if (parseInt(isAdmin,10) == 0) {
		add_subMenuItem("skb_wlreset.php","무선 리셋");
//		add_subMenuItem("skb_daa.php","무선환경 검사");
  }
  //add_subMenuItem("skb_wlwps.php","WPS");
  //add_subMenuItem("skb_wlsch.php","Schedule");
	if(is8021xClient==1)
		add_subMenuItem("skb_rsCertInstall.php","802.1x Cert Install");
}

function draw_subnav_tcpip(isAdmin)
{
	add_subMenuItem("skb_tcpipwan.php","인터넷 설정");
//	add_subMenuItem("skb_ipv6tcpipwan.php","IPv6 설정");
	add_subMenuItem("skb_tcpiplan.php","로컬 랜 설정");
	add_subMenuItem("skb_tcpipport.php","포트 설정");
	//add_subMenuItem("skb_operate_mode.php","운용 모드 설정");
	if (parseInt(isAdmin,10) == 0) {
		add_subMenuItem("skb_vlan.php","VLAN 설정");
	}
}

function draw_subnav_ipv6()
{
	add_subMenuItem("skb_ipv6_wan.php","IPv6 Wan Setting");
	add_subMenuItem("skb_dhcp6s.php","IPv6 Lan Setting");
	add_subMenuItem("skb_radvd.php","Radvd");
	add_subMenuItem("skb_tunnel6.php","Tunnel (6 over 4)");

}
function draw_subnav_firewall(ipv6_enable, isAdmin)
{
	add_subMenuItem("skb_macfilter.php","MAC 필터링");
	add_subMenuItem("skb_portfw.php","포트 포워딩");
	add_subMenuItem("skb_static_mapping.php","Static Mapping");
	//add_subMenuItem("skb_urlfilter.php","URL Filtering");
	add_subMenuItem("skb_dmz.php","DMZ");
	if (parseInt(isAdmin,10) == 0) {
		add_subMenuItem("skb_dos.php","보안 설정(DOS)");
	}
	add_subMenuItem("skb_lanrestrict.php","랜 제한");
	add_subMenuItem("skb_bstorm.php","B Storm 제어");
}

function draw_subnav_qos(ipv6_enable)
{
/*	if(ipv6_enable)
	  	add_subMenuItem("skb_ip6_qos.php","IPv6_QoS");
	else
		add_subMenuItem("skb_ip_qos.php","QoSRule 설정");*/
	add_subMenuItem("skb_qosacl.php","Rule 설정");
	add_subMenuItem("skb_qosque.php","QUEUE 출력 설정");
//	add_subMenuItem("skb_qosremark.php","QoS Remark 설정");
}

function draw_subnav_mng(isDisplayCPU, isEnableBT,isDisplayTR069, isAdmin, nat_mode)
{
  add_subMenuItem("skb_status.php","상태정보");
  if (parseInt(isAdmin,10) == 0) {
  add_subMenuItem("skb_diagnostic.php","자가진단 기능");
  add_subMenuItem("skb_igmp.php","IGMP");
  add_subMenuItem("skb_holepunch.php","홀 펀치");
  }
  add_subMenuItem("skb_stats.php","트래픽 통계");
  if (nat_mode == 1) {
  add_subMenuItem("skb_ip_connection.php","커넥션 통계");
}
  add_subMenuItem("skb_ddns.php","DDNS");
  if(isDisplayCPU == 1)
  	add_subMenuItem("skb_cpuShow.php","CPU Utilizaiton");
  add_subMenuItem("skb_ntp.php","시간");
  //add_subMenuItem("skb_dos.php","Denial-of-Service");
  if(isDisplayTR069 == 1)
  	add_subMenuItem("skb_tr069config.php","TR-069 Config");
  add_subMenuItem("skb_syslog.php","시스템 Log");
  if (parseInt(isAdmin,10) == 0) {
  //add_subMenuItem("skb_ldap.php","LDAP CFG");
  add_subMenuItem("skb_auto_reboot.php","AUTO REBOOT");
  }
  add_subMenuItem("skb_password.php","비밀번호 설정");
  if (parseInt(isAdmin,10) == 0) {
  add_subMenuItem("skb_auto_upgrade.php","자동 업그레이드");
  }
  add_subMenuItem("skb_jumbo.php","점보 프레임");
  if (parseInt(isAdmin,10) == 0) {
  add_subMenuItem("skb_port_mirror.php","포트 미러링");
  add_subMenuItem("skb_snmp.php","SNMP");
  }
  if(isEnableBT == 1){
  	add_subMenuItem("skb_transmission.php","Transmission BT");
  }
//  if (parseInt(isAdmin,10) == 0) {
	add_subMenuItem("skb_usb.php","USB 관리");
//  }
  add_subMenuItem("skb_upload.php","펌웨어 업그레이드");
  add_subMenuItem("skb_saveconf.php","재부팅 / 초기화");
  add_subMenuItem("skb_logout.php?flag=3","로그아웃");
}

function draw_subnav_logout()
{
	add_subMenuItem("skb_operate_mode.php","운용모드설정");
}

function has_class(element, class_name)
{
        if (!element.className) {
                element.className = "";
                return false;
        }

        var regex = new RegExp("(^|\\s)\\s*" + class_name + "\\s*(\\s|$)");
        return regex.test(element.className);
}
/*add_class()*/
function add_class(element, class_name)
{
        if (has_class(element, class_name)) {
                return;
        }
        element.className += (element.className == "" ? "" : " ") + class_name;
}

/*remove_class()*/
function remove_class(element, class_name)
{
        if (!element.className) {
                element.className = "";
                return;
        }

        /*
         * This regex is similar to \bclassName\b, except that \b does not
         * treat certain legal CSS characters as "word characters": notably,
         * the . and - characters.
         */
        var regex = new RegExp("(^|\\s)\\s*" + class_name + "\\s*(\\s|$)");
        element.className = element.className.replace(regex, "$1$2");
}
/*on_click_menu(this)*/
function on_click_menu(element)
{
  var items = document.getElementsByTagName("a");
  for (var i = 0; i < items.length; i++) {
        var item = items[i];
        remove_class(item.parentNode, "topnavon");
        add_class(item.parentNode, "topnavoff");
  }
  remove_class(element.parentNode, "topnavoff");
  add_class(element.parentNode, "topnavon");
}
