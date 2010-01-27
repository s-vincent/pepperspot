<?php
# pepper - PepperSpot.info. A Wireless LAN Access Point Controller
# Copyright (C) 2003, 2004 Mondru AB.
# Copyright (C) 2006, 2009 Christophe BORELLY - IUT de Beziers (France)
#
# The contents of this file may be used under the terms of the GNU
# General Public License Version 2, provided that the above copyright
# notice and this permission notice is included in all copies or
# substantial portions of the software.

# Redirects from PepperSpot daemon:
#
# Redirection when not yet or already authenticated
#   notyet:  PepperSpot daemon redirects to login page.
#   already: PepperSpot daemon redirects to success status page.
#
# Response to login:
#   already: Attempt to login when already logged in.
#   failed:  Login failed
#   success: Login succeded
#
# logoff:  Response to a logout
###############################################################################
define('HS_DEBUG',false);
# Set HS_REDIR_TIMEOUT to a positive value if you want to slow down
# the execution of the login procedure (for debug purposes)
# In general, you can set HS_REDIR_TIMEOUT to 0 seconds
define('HS_REDIR_TIMEOUT',0);
# Set HS_HTTPS_TIMEOUT to a positive value if you want to redirect
# automaticaly users to https://<UAM URL>. This securises user/password
# exchange between client and UAM WEB server. In general, the URL of
# this script is set in uamserver's value of pepper.conf :
## uamserver https://uam.pepperspot.info/hsl.php
# Comment HS_HTTPS_TIMEOUT if you want to use the UAM server's default URL
# even if it is not secure !!!
define('HS_HTTPS_TIMEOUT',5);

# Shared secret used to encrypt password (PAP).
# Prevents dictionary attacks.
# You should change this to your own shared secret.
# It must be the same value of uamsecret in pepper.conf
# Comment this line (AND uamsecret in pepper.conf),
# if you want to use CHAP method.
define('HS_UAMSECRET','testing234');

# Set HS_LANG (lower case) for messages translations
# See hsl-msg-*.php files
define('HS_LANG','en');
###############################################################################
# If you want to use CAS authentication (http://www.jasig.org/cas)
# You must :
#   1- set USE_CAS=true
#   2- uncomment the HS_UAMSECRET
#   3- configure RADIUS to use the rlm_cas module
define('USE_CAS',false);
define('CAS_LIB_DIR','CAS-1.0.1');
define('CAS_SERVER','cas.pepperspot.info');
define('CAS_PORT',8443);
define('CAS_URL','');
# CAS_SERVICE must be the same as "service" in RADIUS raddb/modules/cas.conf
define('CAS_SERVICE','cas://PepperSpot');
# Check CAS server's certificate
#define('CAS_CACERT','/usr/local/apache2/conf/ca.crt');
# CAS_PGT_STORAGE must be set on Windows Systems
define('CAS_PGT_STORAGE','C:/Tmp');
# Set CAS_AUTO_SUBMIT_TIMEOUT if you want to enable automatic
# login form submission after the specified time in milliseconds
#define('CAS_AUTO_SUBMIT_TIMEOUT','1000');
# Set CAS_READONLY to true if you want to enable by default
# the readonly attribute in the login form
define('CAS_READONLY',false);
###############################################################################
# Constants
define('LF',"\n");
define('MD5_SIZE',16);
###############################################################################
# Style
define('SIZE',40);     // Size of username and password fields in auth-form
define('MAX_LEN',128); // Maximum size of username et password
define('WIDTH',(HS_DEBUG)?'600px':'400px');  // Popup's width
define('HEIGHT',(HS_DEBUG)?'400px':'200px'); // Popup's height
define('FORM_NAME','pepperSpotForm');
define('BACKGROUND_COLOR','#FAD155');
$tmp='background-color:#FDF2D1;border:thin solid black;';
$tmp.='margin:0 auto 0 auto;';
define('TABLE_STYLE',$tmp);
define('TD_STYLE','text-align:right;padding:1px;');
###############################################################################
# Variables
$action=cbGetValue($_REQUEST,'action');
$res=cbGetValue($_REQUEST,'res');
$uamip=cbGetValue($_REQUEST,'uamip');
$uamport=cbGetValue($_REQUEST,'uamport');
$baseURL=($uamip!=''&&$uamport!='')?'http://'.$uamip.':'.$uamport:'';
$userurl=cbGetValue($_REQUEST,'userurl');
$userurldecode=urldecode($userurl);
$redirurl=cbGetValue($_REQUEST,'redirurl');
$redirurldecode=urldecode($redirurl);
$timeleft=cbGetValue($_REQUEST,'timeleft');

$challenge=cbGetValue($_REQUEST,'challenge');
$username=cbGetValue($_REQUEST,'username'); // For debug
$password=cbGetValue($_REQUEST,'password'); // For debug

// DO NOT MOVE : Those variables are used in the include file bellow !
$secureURL='https://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
// Detects if current WEB server is IPv6 or not : to be used in the future ?
$HOST_IS_IPv6=preg_match('/^\[[^\[]+\]/',$_SERVER['HTTP_HOST']);
###############################################################################
# Messages translations
include_once('hsl-msg-'.HS_LANG.'.php');
###############################################################################
# Check config
if (USE_CAS&&!defined('HS_UAMSECRET'))
{
  echo('<h1>'.CAS_CONFIG_ERROR.'</h1>'.LF);
  echo('<p>'.CAS_CONFIG_ERROR_TEXT.'</p>'.LF);
  echo('<ul>'.LF);
  echo('<li>'.CAS_CONFIG_ERROR_MSG1.'</li>'.LF);
  echo('<li>'.CAS_CONFIG_ERROR_MSG2.'</li>'.LF);
  echo('</ul>'.LF);
  exit(1);
}
###############################################################################
# Start of login script
if ($action=='js') echoJavaScript();

if (defined('HS_HTTPS_TIMEOUT'))
{
  $HTTPS=strtoupper(cbGetValue($_SERVER,"HTTPS"));
  if ($HTTPS!='ON')
  {
    $REFRESH_NO_HTTPS=HS_HTTPS_TIMEOUT.';url='.$secureURL;
    echoHeader($TITLE_NO_HTTPS,$MSG_NO_HTTPS,false,$REFRESH_NO_HTTPS);
    $msg='<ReplyMessage>Login must use encrypted connection</ReplyMessage>';
    echoFooter(102,$msg);
  }
}
if (USE_CAS)
{
  require_once(CAS_LIB_DIR.'/CAS.php');
  if (HS_DEBUG) phpCAS::setDebug();
  phpCAS::proxy(CAS_VERSION_2_0,CAS_SERVER,CAS_PORT,CAS_URL);
  if (defined('CAS_CACERT')) phpCAS::setCasServerCACert(CAS_CACERT);
  else phpCAS::setNoCasServerValidation();
  if (isset($_SERVER['WINDIR'])) phpCAS::setPGTStorageFile('',CAS_PGT_STORAGE);
  if ($action=='logout')
  {
    //phpCAS::logout();
    phpCAS::logoutWithUrl($baseURL.'/prelogin');
    //phpCAS::logoutWithRedirectService($baseURL.'/prelogin');
    exit(0);
  }
  phpCAS::forceAuthentication();
}

if ($action==HS_CONNECT)
{
  calcValues();
  $url=$GLOBALS['baseURL'].'/logon?username='.$GLOBALS['username'];
  if (defined('HS_UAMSECRET')) // Use PAP
  {
    $url.='&password='.$GLOBALS['pappassword'];
  }
  else  // Use CHAP
  {
    $url.='&response='.$GLOBALS['response'];
  }
  $url.='&userurl='.$GLOBALS['userurl'];
  $refresh=HS_REDIR_TIMEOUT.';url='.$url;
  echoHeader($TITLE_CNX_START,$MSG_CNX_START,false,$refresh);
  if (HS_DEBUG) echoValues();
  echoFooter(201,'<LoginResultsURL>'.$url.'</LoginResultsURL>');
}

switch ($res)
{
  case 'success':$result=1;
    echoHeader($TITLE_SUCCESS,$MSG_SUCCESS);
    break;
  case 'failed':$result=2;
    echoHeader($TITLE_FAILED,$MSG_FAILED);
    echoForm();
    break;
  case 'logoff':$result=3;
    echoHeader($TITLE_LOGOFF,$MSG_LOGOFF);
    break;
  case 'already':$result=4;
    echoHeader($TITLE_ALREADY,$MSG_ALREADY);
    break;
  case 'notyet':$result=5;
    echoHeader($TITLE_NOTYET,$MSG_NOTYET);
    echoForm();
    break;
  case 'popup1':$result=11;
    echoHeader($TITLE_POPUP1,$MSG_POPUP1);
    break;
  case 'popup2':$result=12;
    echoHeader($TITLE_POPUP2,$MSG_POPUP2);
    break;
  case 'popup3':$result=13;
    echoHeader($TITLE_POPUP3,$MSG_POPUP3);
    break;
  # Otherwise it was not a form request
  # Send out an error message
  case 'smartclient':
  default:echoHeader($TITLE_DEFAULT,$MSG_DEFAULT,false);
}
echoFooter();
# End of login script
###############################################################################
///////////////////////////////////////////////////////////
# Compute values to send to pepper's daemon
///////////////////////////////////////////////////////////
function calcValues()
{
  // Hexa to binnary conversion
  $GLOBALS['binChal']=pack('H32',$GLOBALS['challenge']);
  if (defined('HS_UAMSECRET')) // Use PAP
  {
    $GLOBALS['len']=strlen($GLOBALS['password']);
    $GLOBALS['nbSeg']=(int)($GLOBALS['len']/MD5_SIZE+1);
    $GLOBALS['normLen']=$GLOBALS['nbSeg']*MD5_SIZE;
    // Set the size to a multiple of MD5_SIZE characters
    // and pad with 0 if needed
    $GLOBALS['binPass']=pack('a'.$GLOBALS['normLen'],$GLOBALS['password']);
    $GLOBALS['pappassword']='';
    $GLOBALS['binCipher'][0]=$GLOBALS['binChal'];
    for ($i=0;$i<$GLOBALS['nbSeg'];$i++)
    {
// Here we don't use exactely RADIUS method (RFC 2865 page 27 § 5.2)
// to be retro-compatible with old versions !
// hash(i)=MD5(cipher(i)||secret) avec cipher(0)=challenge
$GLOBALS['binHash'][$i]=pack('H*',md5($GLOBALS['binCipher'][$i].HS_UAMSECRET));
$GLOBALS['binPwd'][$i]=substr($GLOBALS['binPass'],$i*MD5_SIZE,MD5_SIZE);
// cipher(i+1)=hash(i) XOR pass(i)
$GLOBALS['binCipher'][$i+1]=$GLOBALS['binHash'][$i]^$GLOBALS['binPwd'][$i];
$GLOBALS['pappassword'].=bin2hex($GLOBALS['binCipher'][$i+1]);
    }
  }
  else // CHAP
  {
    $GLOBALS['response']=md5("\0".$GLOBALS['password'].$GLOBALS['binChal']);
  }
}
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
function cbGetValue($array,$name)
{
  if (isset($array[$name])) return $array[$name];
  return '';
}
///////////////////////////////////////////////////////////
# Function used in echoValues()
///////////////////////////////////////////////////////////
function echoData($msg,$val)
{
  printf('%18s : [%s] %d byte(s)'.LF,$msg,$val,strlen($val));
}
///////////////////////////////////////////////////////////
# Print computed values for debuging purposes
///////////////////////////////////////////////////////////
function echoValues()
{
  echo '<h3>VALUES :</h3>'.LF;
  echo '<pre style="background-color:silver;">'.LF;
  echoData('USER',$GLOBALS['username']);
  echoData('PASS',$GLOBALS['password']);
  echoData('CHAL',$GLOBALS['challenge']);
  if (defined('HS_UAMSECRET')) // Use PAP
  {
    echoData('LEN',$GLOBALS['len']);
    echoData('NSEG',$GLOBALS['nbSeg']);
    echoData('NLEN',$GLOBALS['normLen']);
    echoData('BPWD',bin2hex($GLOBALS['binPass']));
    for ($i=0;$i<$GLOBALS['nbSeg'];$i++)
    {
      echoData('CIPHER ('.$i.')',bin2hex($GLOBALS['binCipher'][$i]));
      echoData('HASH ('.$i.')',bin2hex($GLOBALS['binHash'][$i]));
      echoData('PWD ('.$i.')',bin2hex($GLOBALS['binPwd'][$i]));
    }
    echoData('CIPHER ('.$i.')',bin2hex($GLOBALS['binCipher'][$i]));
    echoData('PAP',$GLOBALS['pappassword']);
  }
  else // Use CHAP
  {
    echoData('RESP',$GLOBALS['response']);
  }
  echo '</pre>'.LF;
}
///////////////////////////////////////////////////////////
# First part of the HTML page
///////////////////////////////////////////////////////////
function echoHeader($title,$bodyText,$withJavascript=true,$refresh='')
{
  echo '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">'.LF;
  echo '<html>'.LF;
  echo '<head>'.LF;
  echo '  <title>'.$title.'</title>'.LF;
  echo '  <meta http-equiv="Cache-control" content="no-cache">'.LF;
  echo '  <meta http-equiv="Pragma" content="no-cache">'.LF;
  if ($refresh!='')
  {
    echo '  <meta http-equiv="refresh" content="'.$refresh.'">'.LF;
  }
  if ($withJavascript)
  {
    echo '  <script type="text/javascript" ';
    echo 'src="'.$_SERVER['PHP_SELF'].'?action=js';
    echo '&uamip='.$GLOBALS['uamip'].'&uamport='.$GLOBALS['uamport'].'">';
    echo '</script>'.LF;
  }
  echo '  <style type="text/css">'.LF;
  echo 'a:hover {background-color:yellow;}'.LF;
  echo '  </style>'.LF;
  echo '</head>'.LF;
  echo '<body';
  if ($withJavascript)
  {
    echo ' onload="javascript:doOnLoad('.$GLOBALS['result'];
    echo ',\''.$_SERVER['PHP_SELF'].'?res=popup2&uamip='.$GLOBALS['uamip'];
    echo '&uamport='.$GLOBALS['uamport'].'&userurl='.$GLOBALS['userurl'];
    echo '&redirurl='.$GLOBALS['redirurl'];
    echo '&timeleft='.$GLOBALS['timeleft'].'\'';
    echo ',\''.$GLOBALS['userurldecode'].'\'';
    echo ',\''.$GLOBALS['redirurldecode'].'\'';
    echo ',\''.$GLOBALS['timeleft'].'\');"';
    echo ' onblur="javascript:doOnBlur('.$GLOBALS['result'].');"';
  }
  echo ' style="background-color:'.BACKGROUND_COLOR.';">'.LF;
  echo '  <h1 style="text-align:center;">'.$title.'</h1>'.LF;
  echo '  <p style="text-align:center;">'.$bodyText.'</p>'.LF;
  if (HS_DEBUG)
  {
    echo '<h3>REQUEST :</h3>'.LF;
    echo '<pre style="background-color:silver;">'.LF;
    foreach ($_REQUEST AS $key=>$val) echoData($key,$val);
    echo '</pre>'.LF;
  }
}
///////////////////////////////////////////////////////////
# Last part of the HTML page
///////////////////////////////////////////////////////////
function echoFooter($responseCode='',$message='')
{
  if (USE_CAS)
  {
    if (isset($_SESSION))
    {
      $phpCAS=cbGetValue($_SESSION,'phpCAS');
      if (is_array($phpCAS))
      {
        $user=cbGetValue($phpCAS,'user');
        $casHref=$_SERVER['PHP_SELF'].'?action=logout';
        $casHref.='&uamip='.$GLOBALS['uamip'].'&uamport='.$GLOBALS['uamport'];
        // In case of popup, redirect to opener !!!
        if (preg_match('/popup/',$GLOBALS['res']))
        {
          $casHref='javascript:opener.location=\''.$casHref.'\';self.close();';
        }
        echo '<p>'.CAS_FOOTER_TITLE.' [<b>'.$user.'</b>]';
        echo ' (<a href="'.$casHref.'" title="'.CAS_FOOTER_LINK_TITLE.'">';
        echo CAS_FOOTER_LINK_MSG.'</a>)...</p>'.LF;
      }
      else echo '<p>'.CAS_FOOTER_MSG.'</p>'.LF;
    }
    //else echo '<p>'.CAS_FOOTER_MSG.'</p>'.LF;
  }
  echo '</body>'.LF;
  if ($responseCode!='')
  {
    echo '<!--'.LF;
    echo '<?xml version="1.0" encoding="UTF-8"?>'.LF;
    echo '<WISPAccessGatewayParam'.LF;
    echo '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'.LF;
    echo '  xsi:noNamespaceSchemaLocation=';
    echo '"http://www.acmewisp.com/WISPAccessGatewayParam.xsd">'.LF;
    echo '<AuthenticationReply>'.LF;
    echo '<MessageType>120</MessageType>'.LF;
    echo '<ResponseCode>'.$responseCode.'</ResponseCode>'.LF;
    echo $message.LF;
    echo '</AuthenticationReply>'.LF;
    echo '</WISPAccessGatewayParam>'.LF;
    echo '-->'.LF;
  }
  echo '</html>'.LF;
  exit(0);
}
///////////////////////////////////////////////////////////
# Login form
///////////////////////////////////////////////////////////
function echoForm()
{
  if (USE_CAS)
  {
    $pt=phpCAS::retrievePT(CAS_SERVICE,$err_code,$output);
    $GLOBALS['username']=phpCAS::getUser();
    $GLOBALS['password']=$pt;
  }
  $PHP_SELF=$_SERVER['PHP_SELF'];
  $challenge=$GLOBALS['challenge'];
  $uamip=$GLOBALS['uamip'];
  $uamport=$GLOBALS['uamport'];
  $userurl=$GLOBALS['userurl'];
  $username=$GLOBALS['username'];
  $password=$GLOBALS['password'];
  echo '  <form name="'.FORM_NAME.'" method="post" action="'.$PHP_SELF.'">'.LF;
  echo '  <input type="hidden" name="challenge" value="'.$challenge.'">'.LF;
  echo '  <input type="hidden" name="uamip" value="'.$uamip.'">'.LF;
  echo '  <input type="hidden" name="uamport" value="'.$uamport.'">'.LF;
  echo '  <input type="hidden" name="userurl" value="'.$userurl.'">'.LF;
  echo '  <table style="'.TABLE_STYLE.'">'.LF;
  echo '    <tbody>'.LF;
  echo '      <tr>'.LF;
  echo '        <th style="'.TD_STYLE.'">Username :</th>'.LF;
  echo '        <td><input type="text" name="username" value="'.$username.'"';
  echo ' size="'.SIZE.'" maxlength="'.MAX_LEN.'"';
  if (USE_CAS&&CAS_READONLY) echo ' readonly';
  echo '/></td>'.LF;
  echo '      </tr>'.LF;
  echo '      <tr>'.LF;
  echo '        <th style="'.TD_STYLE.'">Password :</td>'.LF;
  echo '        <td><input type="'.((USE_CAS)?'text':'password').'"';
  echo ' name="password" value="'.$password.'" size="'.SIZE.'"';
  echo ' maxlength="'.MAX_LEN.'"';
  if (USE_CAS&&CAS_READONLY) echo ' readonly';
  echo '/></td>'.LF;
  echo '      </tr>'.LF;
  echo '      <tr>'.LF;
  echo '        <td style="text-align:center;" colspan="2">';
  echo '<input type="submit" name="action" value="'.HS_CONNECT.'"';
  echo ' onclick="javascript:popUp(\''.$PHP_SELF.'?res=popup1';
  echo '&uamip='.$uamip.'&uamport='.$uamport.'\');"/>';
  if (USE_CAS&&CAS_READONLY)
  {
   echo '<input type="checkbox" title="'.CAS_READONLY_TITLE.'"';
   echo ' onclick="toggleReadOnly(\''.FORM_NAME.'\');"/> '.CAS_READONLY_MSG;
  }
  echo '</td>'.LF;
  echo '      </tr>'.LF;
  echo '    </tbody>'.LF;
  echo '  </table>'.LF;
  echo '  </form>'.LF;
  if (USE_CAS&&defined('CAS_AUTO_SUBMIT_TIMEOUT')&&CAS_AUTO_SUBMIT_TIMEOUT>=0)
  {
   echo '  <script type="text/javascript">'.LF;
   echo 'var form=document.forms["'.FORM_NAME.'"];'.LF;
   echo 'if (form&&form.password.value.length>0) ';
   echo '{setTimeout("form.action.click();",'.CAS_AUTO_SUBMIT_TIMEOUT.');}'.LF;
   echo '  </script>'.LF;
  }
}
///////////////////////////////////////////////////////////
# JavaScript
///////////////////////////////////////////////////////////
function echoJavascript()
{
  echo 'var blur=0;'.LF;
  echo 'var starttime=new Date();'.LF;
  echo 'var startclock=starttime.getTime();'.LF;
  echo 'var mytimeleft=0;'.LF;

  if (USE_CAS&&CAS_READONLY)
  {
  echo 'function toggleReadOnly(formName) {'.LF;
  echo '  var form=document.forms[formName];'.LF;
  echo '  if (form) {'.LF;
  echo '    var field=form.elements[\'username\'];'.LF;
  echo '    if (field) field.readOnly=!field.readOnly;'.LF;
  echo '    field=form.elements[\'password\'];'.LF;
  echo '    if (field) field.readOnly=!field.readOnly;'.LF;
  echo '  }'.LF;
  echo '}'.LF;
  }

  echo 'function doTime() {'.LF;
  echo '  window.setTimeout("doTime()",1000);'.LF;
  echo '  t=new Date();'.LF;
  echo '  time=Math.round((t.getTime()-starttime.getTime())/1000);'.LF;
  echo '  if (mytimeleft) {'.LF;
  echo '   time=mytimeleft-time;'.LF;
  echo '    if (time<=0) {'.LF;
  echo '      window.location="'.$_SERVER['PHP_SELF'].'?res=popup3';
  echo '&uamip='.$GLOBALS['uamip'].'&uamport='.$GLOBALS['uamport'].'";'.LF;
  echo '    }'.LF;
  echo '  }'.LF;
  echo '  if (time<0) time=0;'.LF;
  echo '  hours=(time-(time%3600))/3600;'.LF;
  echo '  time=time-(hours*3600);'.LF;
  echo '  mins=(time-(time%60))/60;'.LF;
  echo '  secs=time-(mins*60);'.LF;
  echo '  if (hours<10) hours="0"+hours;'.LF;
  echo '  if (mins<10) mins="0"+mins;'.LF;
  echo '  if (secs<10) secs="0"+secs;'.LF;
  echo '  title="Online time : "+hours+":"+mins+":"+secs;'.LF;
  echo '  if (mytimeleft) {'.LF;
  echo '    title="Remaining time : "+hours+":"+mins+":"+secs;'.LF;
  echo '  }'.LF;
  echo '  if(document.all || document.getElementById){'.LF;
  echo '     document.title=title;'.LF;
  echo '  }'.LF;
  echo '  else {'.LF;
  echo '    self.status=title;'.LF;
  echo '  }'.LF;
  echo '}'.LF;

  echo 'function popUp(URL) {'.LF;
  echo '  if (self.name!="pepperspot_popup") {'.LF;
  echo '    pepperspot_popup=window.open(URL,"pepperspot_popup"';
  echo ',"toolbar=0,scrollbars=0,location=0,statusbar=0,menubar=0,resizable=0';
  echo ',width='.WIDTH.',height='.HEIGHT.'");'.LF;
  echo '  }'.LF;
  echo '}'.LF;

  echo 'function doOnLoad(result,URL,userurl,redirurl,timeleft) {'.LF;
  echo '  if (timeleft) {'.LF;
  echo '    mytimeleft=timeleft;'.LF;
  echo '  }'.LF;
  echo '  if (result==1) {'.LF;
  echo '    if (self.name=="pepperspot_popup") doTime();'.LF;
  echo '    else popUp(URL);'.LF;
  echo '  }'.LF;
  echo '  if ((result==2)||result==5) {'.LF;
  echo '    self.focus();'.LF;
  echo '    document.'.FORM_NAME.'.username.focus();'.LF;
  echo '  }'.LF;
  echo '  if ((result==2)&&(self.name!="pepperspot_popup")) {'.LF;
  echo '    popUp("");'.LF;
  echo '    pepperspot_popup.close();'.LF;
  echo '  }'.LF;
  echo '  if ((result==12)&&(self.name=="pepperspot_popup")) {'.LF;
  echo '    doTime();'.LF;
  echo '    if (redirurl) {'.LF;
  echo '      opener.location=redirurl;'.LF;
  echo '    }'.LF;
  echo '    else if (opener.home) {'.LF;
  echo '      opener.home();'.LF;
  echo '    }'.LF;
  echo '    else {'.LF;
  echo '      opener.location="about:home";'.LF;
  echo '    }'.LF;
  echo '    self.focus();'.LF;
  echo '    blur=0;'.LF;
  echo '  }'.LF;
  echo '  if ((result==13)&&(self.name=="pepperspot_popup")) {'.LF;
  echo '    self.focus();'.LF;
  echo '    blur=1;'.LF;
  echo '  }'.LF;
  echo '}'.LF;

  echo 'function doOnBlur(result) {'.LF;
  echo '  if ((result==12)&&(self.name=="pepperspot_popup")) {'.LF;
  echo '    if (blur==0) {'.LF;
  echo '      blur=1;'.LF;
  echo '      self.focus();'.LF;
  echo '    }'.LF;
  echo '  }'.LF;
  echo '}'.LF;
  exit(0);
}
?>
