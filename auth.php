<?php

$user		= 'UserName';
$password	= 'Password';
$host		= 'ADDomainControllerIPorName';
$domain		= 'DomainName';
$basedn		= 'DC=google,DC=com';
$group		= 'internet_users';

$check_group	= "1"; # 1 - Yes, 0 - No

$ldap		= ldap_connect("ldap://$host.$domain") or die('Could not connect to LDAP server.');

ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

ldap_bind($ldap, "{$user}@{$domain}", $password) or die('Could not bind to AD.');

$userdn		= xldap_get_dn($ldap, $basedn, $user);

if (preg_match("/CN/", $userdn)){
    if ($check_group==1){
	$groupdn	= xldap_get_dn($ldap,$basedn,$group);

	$result		= xldap_user_group_check($ldap, $userdn, $groupdn, 1);

	if ($result==1){
	    print "Ok\n";
	}else{
	    $result	= xldap_user_group_check($ldap, $userdn, $groupdn, 16);
	    if ($result==1){
		print "Ok\n";
	    }else{
		print "Error member\n";
	    }
	}
    }else{
	print "Ok\n";
    }
}else{
    print "Error get DN\n";
}

ldap_unbind($ldap);

exit;

function xldap_get_dn($ldap, $basedn, $samaccountname) {
    $attributes = array('dn');
    $result = ldap_search($ldap, $basedn,"(samaccountname={$samaccountname})", $attributes);
    if ($result === FALSE)
    {
	return '';
    }
    $entries = ldap_get_entries($ldap, $result);
    if ($entries['count']>0){
	return $entries[0]['dn'];
    }else{
	return '';
    }
}

function xldap_user_group_check($ldap, $userdn, $groupdn, $recurs_count=16) {
    if ($recurs_count <=0 ){
	return FALSE;
    }
    $attributes = array('memberof');
    $result = ldap_read($ldap, $userdn, '(objectclass=*)', $attributes);
    if ($result === FALSE){
	return FALSE;
    }
    $entries = ldap_get_entries($ldap, $result);
    if ($entries['count'] <= 0){
	return FALSE;
    }
    if (empty($entries[0]['memberof'])){
	return FALSE;
    }else{
	for ($i = 0; $i < $entries[0]['memberof']['count']; $i++) {
	    if ($entries[0]['memberof'][$i] == $groupdn) {
		return TRUE;
	    }else{
		if ($recurs_count>1){
		    if (xldap_user_group_check($ldap, $entries[0]['memberof'][$i], $groupdn, $recurs_count-1)) {
			return TRUE;
		    }
		}
	    }
	}
    }
    return FALSE;
}

?>

