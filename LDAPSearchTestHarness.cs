using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


    class LDAPSearchTestHarness
    {
        static void Main(string[] args)
        {
            //.ctor
            var ldap = new LDAPSearch();
            var props = new List<LDAPSearch.DirectoryProperty>();
            props.Add(LDAPSearch.DirectoryProperty.SAMACCOUNTNAME);
            props.Add(LDAPSearch.DirectoryProperty.TITLE);
            props.Add(LDAPSearch.DirectoryProperty.MEMBEROF);

            //searches
            var r0 = ldap.Search(LDAPSearch.SearchTarget.USER, LDAPSearch.SearchBy.EMAIL, "milesmouse@dis.com", props);
            var r1 = ldap.Search(LDAPSearch.SearchTarget.GROUP, LDAPSearch.SearchBy.GROUPNAME, "GROUP_1", props);
            var r2 = ldap.Search(LDAPSearch.SearchTarget.COMPUTER, LDAPSearch.SearchBy.COMPUTERNAME, "COMPU-100100", props);
            var r3 = ldap.Search(LDAPSearch.SearchTarget.PRINTER, LDAPSearch.SearchBy.PRINTERNAME,"PRINTER_1",props);

            //return/check values
            string userTitle = ldap.GetValue(LDAPSearch.DirectoryProperty.TITLE, r0);
            bool isUserInGroup = ldap.GetValue(LDAPSearch.DirectoryProperty.MEMBEROF, r0, "SOMEGROUPNAME");
            string computerName = ldap.GetValue(LDAPSearch.DirectoryProperty.SAMACCOUNTNAME, r2);
            string printerName = ldap.GetValue(LDAPSearch.DirectoryProperty.SAMACCOUNTNAME, r3);
        }
    }
