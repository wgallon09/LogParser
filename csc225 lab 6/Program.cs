/* William Gallon
 * November 6 2010
 * This program takes a unix server authentication log, and parses it to find the authentication failures and invalid login name failures, along with their IP addresses*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace logParser
{
    
    class Program
    {
        //declare constants to help make more sense of what is being read from the data array
        const int logname = 3;
        const int name = 5;
        const int ip = 7;
        const int rhost = 8;
        const int port = 9;

        static void Main(string[] args)
        {
            string input;
            string[] data;
            int rootFailCount = 0;
            StreamReader infile = new StreamReader("auth.log");
            StreamWriter authFails = new StreamWriter("authfail.txt");
            StreamWriter nameFails = new StreamWriter("namefail.txt");

            while (!infile.EndOfStream)
            {
                input = infile.ReadLine();
                data = input.Split(']'); //splits off the beginning of the log, leaving only the message
                input = data[1];  //drops the date, as it will not be needed for this log
                input = input.Trim(':'); //cleans up the remaining colon character from the beginning of the log message
                input = input.Trim(); //cleans up whitespace
                data = input.Split();  //splits the log information into usable pieces

                if (input.Contains("authentication failure;")) //counts number of failed logins, and outputs them to authfail.txt
                {
                    //counts number of failured logins with username "root"
                    if (input.Contains("logname=root"))
                    {
                        rootFailCount++;
                    }

                    //skips lines with no logname, as the log first outputs a line with no username on a failed login before outputting
                    //the line that contains the failed login info
                    if (data[logname] != "logname=")
                    {
                        authFails.WriteLine(data[logname] + " " + data[rhost]);
                    }
                }
                //counts number of attempted logins with invalid usernames, and outputs them to namefail.txt
                if (input.Contains("invalid user"))
                {
                    nameFails.WriteLine(data[name] + " " + data[ip] + ":" + data[port]);
                }
            }

            infile.Close();
            authFails.Close();
            nameFails.Close();
            Console.WriteLine("There were {0} failed login attempts from root.  For more info, please see\n\"authfail.txt\" and \"namefail.txt\".", rootFailCount);
        }
    }
}
