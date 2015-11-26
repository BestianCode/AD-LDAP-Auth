#!/usr/bin/python

import re
import ldap

user            = 'UserName'
password        = 'Password'
host            = 'ADDomainControllerIPorName'
domain          = 'DomainName'
basedn          = 'DC=google,DC=com'
group           = 'internet_users'

check_group     = 1 # 1 - Yes, 0 - No

def xldap_get_dn(xldap,xbasedn,xuser):
    xres = xldap.search_s(xbasedn,ldap.SCOPE_SUBTREE,"(sAMAccountName="+xuser+")",["dn"])
    for xdn,trash in xres:
        if re.search( '^CN\=.*', str(xdn)):
            return re.sub(r'\n', "", str(xdn))
    return 0

def xldap_user_group_check(xldap, xuserdn, xgroupdn, xrecurs_count):
    if xrecurs_count<=0:
        return 0
    xres = xldap.search_s(xuserdn,ldap.SCOPE_SUBTREE,"(objectclass=*)",["memberOf"])
    for trash,xmember in xres:
        xi=0
        if xmember:
            while xi<len(xmember['memberOf']):
                xmemof=xmember['memberOf'][xi]
                if xmemof==xgroupdn:
                    return 1;
                else:
                    if xrecurs_count>1:
                        xres = xldap_user_group_check(xldap, xmemof, xgroupdn, int(xrecurs_count-1))
                        if xres==1:
                            return 1
                xi=xi+1
    return 0

l = ldap.initialize("ldap://"+host+"."+domain)
l.simple_bind_s(user+"@"+domain, password)
l.set_option(ldap.OPT_REFERRALS, 0)

userdn = xldap_get_dn(l,basedn,user)

if re.search( '^CN\=.*', str(userdn)):
#    print "USER: ",userdn, "\n",
    if check_group==1:
        groupdn = xldap_get_dn(l,basedn,group);
#        print "GROUP:",groupdn,"\n",
        result  = xldap_user_group_check(l, userdn, groupdn,1);

        if result==1:
            print "Ok\n",
        else:
            result = xldap_user_group_check(l, userdn, groupdn, 16);
            if result==1:
                print "Ok\n",
            else:
                print "Error member\n",
    else:
        print "Ok\n",
else:
    print "Error get DN\n",

l.unbind()

