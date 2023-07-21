using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.ComponentModel;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Threading.Tasks;
using System.Net.Security;

/// <summary>
/// LDAP Search Utility
/// </summary>
/// <remarks>
/// Programmer: Mike DiRenzo, mike_Direnzo@hotmail.com
/// Date: 1/26/2007
/// Purpose: A self contained search utility for querying ANY LDAP with a limited set of params.
/// uses serverless binding and rootdse: https://msdn.microsoft.com/en-us/library/ms677945(v=vs.85).aspx
///	For speed and simplicty, this constructor of the utility uses an anonymous security context.  
/// History: mucho improvements from its initial verison.
public class LDAPSearch
{
    /// <summary>
    /// LDAPSearch
    /// </summary>
    /// <remarks>
    /// USAGE:
    /// var toReturn = ldap.LDAPSearch([SEARCH TARGET], [SEARCH BY], ["SEARCH KEY"],[0..N PROPERTIES TO SEARCH FOR], [BEGIN RANGE], [END RANGE]);
    /// [SEARCH TARGET]: enum LDAPSearch.SearchTarget
    /// [SEARCH BY]: enum LDAPSearch.SearchBy<
    /// ["SEARCH KEY"]: This is the value of what is being searched for
    /// [0..N PROPERTIES TO SEARCH FOR]: a collection of LDAPSearch.DirectoryProperty enums
    /// [BEGIN RANGE]: Optional and can be omitted.
    /// [END RANGE]: Optional and can be omitted.
    /// Note: [BEGIN RANGE], [END RANGE] ranges are used when [SEARCH TARGET] = LDAPSearch.SearchTarget.GROUP and are optional
    /// </remarks>
    public LDAPSearch()
    {
        if (IsLDAPAvailable())
        {
            DirectoryEntry root = new DirectoryEntry("LDAP://RootDSE");
            root = new DirectoryEntry("LDAP://" + root.Properties["defaultNamingContext"][0]);
            this.DirectorySearcher = new DirectorySearcher(root);
        }
    }

    /// <summary>
    /// IsLDAPAvailable
    /// </summary>
    /// <returns>bool</returns>
    /// <remarks>Checks to see if there is a an LDAP to bind to vis-a-vis RootDSE.  If not an exception is thrown.</remarks>
    internal bool IsLDAPAvailable()
    {
        DirectoryEntry root = new DirectoryEntry("LDAP://RootDSE");
        TimeSpan timeOut = new TimeSpan(0, 0, 0, 1);
        try
        {
            LdapConnection ldapConnection = new LdapConnection(new LdapDirectoryIdentifier((root.Properties["dnsHostName"][0]).ToString()));

            ldapConnection.AuthType = AuthType.Anonymous;
            ldapConnection.AutoBind = false;
            ldapConnection.Timeout = timeOut;
            ldapConnection.Bind();
            ldapConnection.Dispose();
            return true;
        }
        catch (LdapException lex)
        {
            throw (lex);
        }
        catch (Exception ex) {
            throw ex;
        }

    }
    internal DirectorySearcher DirectorySearcher { get; set; }
    internal string[] DirectoryProperties { get; set; }

    public enum SearchBy
    {
        [Description("(mail={0})")]
        EMAIL,

        [Description("(samaccountname={0})")]
        AD_LOGIN_ID,

        [Description("(employeenumber={0})")]
        EID,

        [Description("(CN={0})")]
        CNNAME,

        [Description("(CN={0})")]
        GROUPNAME,

        [Description("(Name={0})")]
        PRINTERNAME,

        [Description("(Name={0})")]
        COMPUTERNAME
    }

    public enum SearchTarget
    {
        [Description("(objectCategory=user)")]
        USER,

        [Description("(objectCategory=group)")]
        GROUP,

        [Description("(objectCategory=printQueue)")]
        PRINTER,

        [Description("(objectCategory=computer)")]
        COMPUTER
    }

    /// <summary>
    /// DirectoryProperty
    /// </summary>
    /// <remarks>This is a limited set of attributes.  This can be expanded to suite more use cases.
    /// For a complete list of attributes:
    /// https://msdn.microsoft.com/en-us/library/ms675095.aspx
    /// </remarks>
    public enum DirectoryProperty
    {
        [Description("adspath")]
        ADSPATH,
        [Description("cn")]
        CN,
        [Description("displayname")]
        DISPLAYNAME,
        [Description("distinguishedname")]
        DISTINGUISHEDNAME,
        [Description("employeeid")]
        EMPLOYEEID,
        [Description("employeenumber")]
        EMPLOYEENUMBER,
        [Description("member")]
        MEMBER,
        [Description("member;range={0}-{1}")]
        MEMBERRANGE,
        [Description("memberof")]
        MEMBEROF,
        [Description("name")]
        NAME,
        [Description("objectcategory")]
        OBJECTCATEGORY,
        [Description("objectclass")]
        OBJECTCLASS,
        [Description("samaccountname")]
        SAMACCOUNTNAME,
        [Description("samaccounttype")]
        SAMACCOUNTTYPE,
        [Description("title")]
        TITLE,
        [Description("useraccountcontrol")]
        USERACCOUNTCONTROL
    }

    /// <summary>
    /// Search
    /// </summary>
    /// <param name="SearchTarget">SearchTarget</param>
    /// <param name="SearchBy">SearchBy</param>
    /// <param name="searchTarget">SearchTarget</param>
    /// <param name="returnDirectoryProperties"></param>
    /// <param name="beginRange"></param>
    /// <param name="endRange"></param>
    /// <returns>Dictionary&lt;int, List&lt;KeyValuePair&lt;string, List&lt;string&gt;&gt;&gt;&gt;</returns>
    /// <remarks>This is a stand alone and independent utility
    /// </remarks>
    public Dictionary<int, List<KeyValuePair<string, List<string>>>> Search(
        SearchTarget SearchTarget,
        SearchBy SearchBy,
        string searchTarget,
        List<DirectoryProperty> returnDirectoryProperties,
        int? beginRange = 0, //default LDAP range min specs for a GROUP query
        int? endRange = 1499) //default LDAP range max specs for a GROUP query
    {
        if (returnDirectoryProperties.Count == 0)
        {
            this.DirectorySearcher.LoadDirectoryProperties(typeof(DirectoryProperty));
        }
        else
        {
            this.DirectorySearcher.LoadDirectoryProperties(returnDirectoryProperties);
        }

        //Remove and reset the range property
        if (SearchTarget == LDAPSearch.SearchTarget.GROUP)
        {
            var rangeIDX = this.DirectorySearcher.PropertiesToLoad.Cast<string>().ToList().FindIndex(f => f.Contains("member;"));
            if (rangeIDX > 0)
            {
                this.DirectorySearcher.PropertiesToLoad.RemoveAt(rangeIDX);
            }
            this.DirectorySearcher.PropertiesToLoad.Add(string.Format(
                DirectoryProperty.MEMBERRANGE.GetDescription(),
                beginRange.Value,
                endRange.Value
            ));

        }

        this.DirectorySearcher.Filter = string.Format("(&{0}{1})",
                                                        SearchTarget.GetDescription(),
                                                        string.Format(SearchBy.GetDescription(),
                                                        searchTarget));

        var data = GetSearchResult();

        var toReturn = GetDirectoryPropertyCollection(data);
        return toReturn;
    }


    /// <summary>
    /// Retrieve
    /// </summary>
    /// <param name="prop"></param>
    /// <param name="ldapData"></param>
    /// <param name="findString"></param>
    /// <returns>bool</returns>
    /// <remarks>
    /// USAGE:
    /// var t = GetValue(LDAPSearch.DirectoryProperty.[PROPERTY], toReturn, "[VALUE]");
    /// </remarks>
    public bool GetValue(LDAPSearch.DirectoryProperty prop, Dictionary<int, List<KeyValuePair<string, List<string>>>> ldapData, string findString)
    {
        bool toReturn = false;

        foreach (KeyValuePair<int, List<KeyValuePair<string, List<string>>>> entry in ldapData)
        {
            toReturn = entry.Value.FirstOrDefault(v => v.Key.Equals(prop.GetDescription())).Value.Any(v => v.Contains(findString));
            break;
        }

        return toReturn;
    }

    /// <summary>
    /// Retrieve
    /// </summary>
    /// <param name="prop"></param>
    /// <param name="ldapData"></param>
    /// <returns>string</returns>
    /// <remarks>
    /// USAGE:
    /// var y = GetValue(LDAPSearch.DirectoryProperty.MAIL, toReturn);
    /// </remarks>
    public string GetValue(LDAPSearch.DirectoryProperty prop, Dictionary<int, List<KeyValuePair<string, List<string>>>> ldapData)
    {
        string toReturn = string.Empty;
        foreach (KeyValuePair<int, List<KeyValuePair<string, List<string>>>> entry in ldapData)
        {
            try
            {
                toReturn = entry.Value.FirstOrDefault(v => v.Key.Equals(prop.GetDescription())).Value.FirstOrDefault();
            }
            catch
            {
                toReturn = string.Empty;
            }
            break;

        }
        return toReturn;
    }

    #region private methods
    /// <summary>
    /// ReturnSearchResult
    /// </summary>
    /// <returns></returns>
    private SearchResultCollection GetSearchResult()
    {
        Func<SearchResultCollection> result = () => this.DirectorySearcher.FindAll();
        return result();
    }

    /// <summary>
    /// GetDirectoryPropertyCollection
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    private Dictionary<int, List<KeyValuePair<string, List<string>>>> GetDirectoryPropertyCollection(SearchResultCollection data)
    {
        var toReturn = new Dictionary<int, List<KeyValuePair<string, List<string>>>>();

        int z = 0;
        List<KeyValuePair<string, List<string>>> current = null;
        foreach (SearchResult res in data)
        {
            current = new List<KeyValuePair<string, List<string>>>();
            foreach (string key in res.Properties.PropertyNames)
            {

                foreach (Object prop in res.Properties[key])
                {
                    var propColl = new List<string>();
                    for (int i = 0; i < res.Properties[key].Count; i++)
                    {
                        propColl.Add(res.Properties[key][i].ToString());
                    }

                    current.Add(new KeyValuePair<string, List<string>>(key, propColl));
                    break;
                }
            }
            toReturn.Add(z, current);
            z++;
        }
        return toReturn;
    }
    #endregion
}

/// <summary>
/// EnumExtensions
/// </summary>
/// <remarks>
/// Programmer: Mike DiRenzo
/// Date: 7/26/2017
/// Source: Google Search
/// Purpose: A generic extension class for retrieving DESCRIPTION attribs from an ENUM.
/// Usage:
/// 
///    public enum SearchBy
///    {
///        [Description("(mail={0})")]
///        EMAIL
///    }
///    
///    var desc = SearchBy.AD_LOGIN_ID.GetDescription();  //desc will contain (mail={0})
/// </remarks>
public static class EnumExtensions
{
    /// <summary>
    /// GetAttribute<T>
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="value"></param>
    /// <returns>T</returns>
    /// <remarks>
    /// This extension method is broken out so you can use a similar pattern with 
    /// other MetaData elements in the future. This is your base method for each.
    /// </remarks>
    public static T GetAttribute<T>(this Enum value) where T : Attribute
    {
        var type = value.GetType();
        var memberInfo = type.GetMember(value.ToString());
        var attributes = memberInfo[0].GetCustomAttributes(typeof(T), false);
        return (T)attributes[0];
    }


    /// <summary>
    /// GetDescription
    /// </summary>
    /// <param name="value"></param>
    /// <returns>string</returns>
    /// <remarks>This method creates a specific call to the above method, requesting the Description MetaData attribute.</remarks>
    public static string GetDescription(this Enum value)
    {
        var attribute = value.GetAttribute<DescriptionAttribute>();
        return attribute == null ? value.ToString() : attribute.Description;
    }

}

/// <summary>
/// Extension class: DirectoryPropertyExtensions
/// Used by: LDAP search utility
/// Purpose: to hydrate the the DirectorySearcher object property collection
/// </summary>
public static class DirectoryPropertyExtensions
{
    public static string[] LoadDirectoryProperties(this DirectorySearcher dsProps, Type props)
    {

        string[] toReturn = new string[Enum.GetValues(props).Length];
        int i = 0;
        foreach (LDAPSearch.DirectoryProperty prop in Enum.GetValues(props))
        {
            toReturn[i++] = prop.GetDescription();
        }
        dsProps.PropertiesToLoad.AddRange(toReturn);
        return toReturn;
    }

    public static string[] LoadDirectoryProperties(this DirectorySearcher dsProps, List<LDAPSearch.DirectoryProperty> props)
    {
        string[] toReturn = new String[props.Count];
        int i = 0;
        props.ForEach(p =>
        {
            toReturn[i++] = p.GetDescription();
        });
        dsProps.PropertiesToLoad.AddRange(toReturn);
        return toReturn;
    }
}
