using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;

namespace ActiveDirectorySamples
{
    class Program
    {
        static void Main(string[] args)
        {
            bool isAtutheticated = Authenticate("", "", "");

            if (isAtutheticated)
                Console.WriteLine("Authenticated");
            else
                Console.WriteLine("Authentication failed");

            Console.ReadLine();
        }

        static DirectoryEntry GetDomainInfo()
        {

            Domain domain = Domain.GetCurrentDomain();
            DirectoryEntry de = domain.GetDirectoryEntry();
            return de;
        }

        static bool Authenticate(string username, string password, string domain)
        {
            string path = "";
            String domainAndUsername = domain + @"\" + username;

            try
            {

                using (DirectoryEntry entry = new DirectoryEntry(path, domainAndUsername, password))
                {
                    //Bind to the native AdsObject to force authentication.			
                    Object obj = entry.NativeObject;

                    using (DirectorySearcher search = new DirectorySearcher(entry))
                    {
                        search.Filter = "(SAMAccountName=" + username + ")";
                        search.PropertiesToLoad.Add("cn");
                        SearchResult result = search.FindOne();

                        entry.Close();

                        if (null == result)
                            return false;
                        else
                            return true;

                    }
                }                
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return false;
            }

        }

        static ResultPropertyCollection GetDomainProperties(DirectoryEntry domain)
        {
            string[] policyAttributes = new string[] {
                                                      "maxPwdAge", "minPwdAge", "minPwdLength",
                                                      "lockoutDuration", "lockOutObservationWindow",
                                                      "lockoutThreshold", "pwdProperties",
                                                      "pwdHistoryLength", "objectClass",
                                                      "distinguishedName"
                                                      };

            DirectorySearcher ds = new DirectorySearcher(domain, "(objectClass=domainDNS)", policyAttributes, SearchScope.Base);

            SearchResult result = ds.FindOne();

            //do some quick validation...							  
            if (result == null)
            {
                throw new ArgumentException(
                  "domainRoot is not a domainDNS object."
                  );
            }

            return result.Properties;

        }

        static TimeSpan GetPasswordDuration(DirectoryEntry domain)
        {
            ResultPropertyCollection properties = GetDomainProperties(domain);

            Console.WriteLine("");
            Console.WriteLine("DOMAIN PROPERTIES");
            Console.WriteLine("-----------------");

            foreach (System.Collections.DictionaryEntry item in properties)
            {
                Console.WriteLine(item.Key + ": " + ((ResultPropertyValueCollection)item.Value)[0].ToString());

            }

            Console.WriteLine("");

            string val = "maxPwdAge";

            if (properties.Contains(val))
            {
                long ticks = Math.Abs((Int64)properties[val][0]);
                return TimeSpan.FromTicks(ticks);
            }

            else
                return TimeSpan.MaxValue;

        }

        const int UF_ACCOUNTDISABLE = 0x0002;
        const int UF_PASSWD_NOTREQD = 0x0020;
        const int UF_PASSWD_CANT_CHANGE = 0x0040;
        const int UF_NORMAL_ACCOUNT = 0x0200;
        const int UF_DONT_EXPIRE_PASSWD = 0x10000;
        const int UF_SMARTCARD_REQUIRED = 0x40000;
        const int UF_PASSWORD_EXPIRED = 0x800000;


        static bool ShowProps(string username, string password, string domain)
        {

            string path = "";
            string filterAttribute = "";
            String domainAndUsername = domain + @"\" + username;

            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(path, domainAndUsername, password))
                {
                    //Bind to the native AdsObject to force authentication.			
                    Object obj = entry.NativeObject;

                    using (DirectorySearcher search = new DirectorySearcher(entry))
                    {
                        search.Filter = "(SAMAccountName=" + username + ")";
                        search.PropertiesToLoad.Add("cn");
                        SearchResult result = search.FindOne();

                        if (null == result)
                            return false;

                        //Update the new path to the user in the directory.
                        path = result.Path;
                        filterAttribute = (String)result.Properties["cn"][0];

                        DirectoryEntry de = result.GetDirectoryEntry();

                        foreach (PropertyValueCollection item in de.Properties)
                        {
                            Console.WriteLine(item.PropertyName + " " + item.Value);
                        }

                        int uac = (int)de.Properties["userAccountControl"].Value;

                        bool passwordNeverExpire = false;
                        bool accountDisabled = false;
                        bool normalAccount = false;
                        bool passwordExpired = false;

                        if ((uac & UF_DONT_EXPIRE_PASSWD) == UF_DONT_EXPIRE_PASSWD)
                            passwordNeverExpire = true;

                        if ((uac & UF_ACCOUNTDISABLE) == UF_ACCOUNTDISABLE)
                            accountDisabled = true;

                        if ((uac & UF_NORMAL_ACCOUNT) == UF_NORMAL_ACCOUNT)
                            normalAccount = true;

                        if ((uac & UF_PASSWORD_EXPIRED) == UF_PASSWORD_EXPIRED)
                            passwordExpired = true;


                        DirectorySearcher ds = new DirectorySearcher(de, String.Format("({0}=*)", "pwdLastSet"), new string[] { "pwdLastSet" }, SearchScope.Base);
                        SearchResult sr = ds.FindOne();
                        if (sr != null)
                        {
                            if (sr.Properties.Contains("pwdLastSet"))
                            {
                                long ticks = (Int64)sr.Properties["pwdLastSet"][0];

                                DateTime passwordLastSet;

                                if (ticks == 0)
                                    passwordLastSet = DateTime.MinValue;

                                //password has never been set
                                if (ticks == -1)
                                {
                                    throw new InvalidOperationException(
                                      "User does not have a password"
                                      );
                                }

                                //get when the user last set their password;
                                passwordLastSet = DateTime.FromFileTime(ticks);
                            }
                        }


                        TimeSpan t = GetPasswordDuration(GetDomainInfo());
                        Console.WriteLine("Domain max password age: " + t.ToString());

                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return false;
            }


        }

    }
}
