# WebLogic honeypot
Cymmetria Research, 2018.

https://www.cymmetria.com/

Written by: Omer Cohen (@omercnet)
Special thanks: Imri Goldberg (@lorgandon), Itamar Sher, Nadav Lev

Contact: research@cymmetria.com

WebLogic Honeypot is a low interaction honeypot to detect CVE-2017-10271 in the Oracle WebLogic Server component of Oracle Fusion Middleware. This is a Remote Code Execution vulnerability. The honeypots does a simple simulation of the WebLogic server and will allow attackers to use the vulnerability to attempt to execute code, and will report of such attempts.

It is released under the MIT license for the use of the community, pull requests are welcome!


# Usage

* Run without parameters to listen on default port (8080):

    >sudo apt -y install ufw
    > ufw default DENY
    >sudo ufw allow 8080
    >sudo ufw allow 80
    >sudo ufw allow 7001
    >Rules updated
    >sudo ufw enable
    >vi /etc/ufw/before.rules

        # Don't delete these required lines, otherwise there will be errors
        *nat
        :PREROUTING ACCEPT [0:0]
        -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 7001
        -A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-port 7001
        COMMIT

        *filter

    >reboot
    > bash startup.sh
    > python weblogic_server.py -p 7001

* Run with --help to see other command line parameters


See also
--------

https://cymmetria.com/blog/honeypots-for-oracle-vulnerabilities/

http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-10271

Please consider trying out the MazeRunner Community Edition, the free version of our cyber deception platform.
https://community.cymmetria.com/
