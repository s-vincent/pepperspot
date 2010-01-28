<?php
# pepper - PepperSpot.info. A Wireless LAN Access Point Controller
###############################################################################
# Messages translations
define('HS_NAME','PepperSpot'.(($HOST_IS_IPv6)?' (IPv6)':' (IPv4)'));

# Text displayed on submit button
define('HS_CONNECT','Connection');

define('CAS_CONFIG_ERROR','CAS configuration error !!!');
$tmp='If you want to use CAS authentication';
$tmp.=' (http://www.jasig.org/cas), you must set :';
define('CAS_CONFIG_ERROR_TEXT',$tmp);
$tmp='USE_CAS=true ['.(USE_CAS?'true':'false').']';
define('CAS_CONFIG_ERROR_MSG1',$tmp);
$tmp='Enter a secret in HS_UAMSECRET ['.@constant('HS_UAMSECRET').']';
define('CAS_CONFIG_ERROR_MSG',$tmp);
define('CAS_READONLY_TITLE','Allow updates');
define('CAS_READONLY_MSG',''); // Text following the checkbox
define('CAS_FOOTER_TITLE','CAS user :');
$tmp='Click here if you want to loggout completely from CAS';
define('CAS_FOOTER_LINK_TITLE',$tmp);
define('CAS_FOOTER_LINK_MSG','Déconnection from CAS');
define('CAS_FOOTER_MSG','You are not logged !!!');

$TITLE_CNX_START='Logging in to '.HS_NAME;
$MSG_CNX_START='Please wait';
if (HS_REDIR_TIMEOUT>0) $MSG_CNX_START.=' '.HS_REDIR_TIMEOUT.' seconds';
$MSG_CNX_START.=' before redirection...';

$TITLE_DEFAULT=HS_NAME.' Login Failed !!!';
$MSG_DEFAULT='Login must be performed through '.HS_NAME.' daemon !!!';
$MSG_DEFAULT.='<br/>Close your navigator and try again.';

$TITLE_SUCCESS='Logged in to '.HS_NAME;
$MSG_SUCCESS='Welcome on '.HS_NAME.'.<br/>';
$MSG_SUCCESS.='<a href="'.$baseURL.'/logoff" title="logout">';
$MSG_SUCCESS.='Click here if you want to <b>logout</b></a>.';

$TITLE_FAILED='Wrong identification for '.HS_NAME.' !!!';
$MSG_FAILED='Try again...';

$TITLE_LOGOFF='Logged out from '.HS_NAME;
$MSG_LOGOFF='You\'ve been logged out from '.HS_NAME.'.<br/>';
$MSG_LOGOFF.='<a href="'.$baseURL.'/prelogin" title="login">';
$MSG_LOGOFF.='Click here if you want to <b>login</b></a>.';

$TITLE_ALREADY='You\'re already logged in to '.HS_NAME;
$MSG_ALREADY='<a href="'.$baseURL.'/logoff" title="logout">';
$MSG_ALREADY.='Click here if you want to <b>logout</b></a>.';

$TITLE_NOTYET='Logging in to '.HS_NAME;
$MSG_NOTYET='Enter your IDs for the connection to '.HS_NAME.'...';

$TITLE_POPUP1='Trying to log in to '.HS_NAME;
$MSG_POPUP1=$MSG_CNX_START;
 
$TITLE_POPUP2='Logged in to '.HS_NAME;
$MSG_POPUP2='<a href="javascript:opener.location=\''.$baseURL.'/logoff\';';
$MSG_POPUP2.='self.close();" title="logout">';
$MSG_POPUP2.='Click here if you want to <b>logout</b></a>.';

$TITLE_POPUP3='You\'ve been logged out from '.HS_NAME;
$MSG_POPUP3='<a href="javascript:opener.location=\''.$baseURL.'/prelogin\';';
$MSG_POPUP3.='self.close();" title="login">';
$MSG_POPUP3.='Click here if you want to <b>login</b></a>.';

if (defined('HS_HTTPS_TIMEOUT'))
{
	$TITLE_NO_HTTPS=HS_NAME.' Login Failed !!!';
	$MSG_NO_HTTPS='Login must use an encrypted connection (HTTPS) !!!';
	$MSG_NO_HTTPS.='<br/>You\'ll be redirected in '.HS_HTTPS_TIMEOUT;
	$MSG_NO_HTTPS.=' seconds to the <a href="'.$secureURL.'"';
	$MSG_NO_HTTPS.=' title="Secured connection">secured site</a>...';
}
?>
