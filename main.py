from Config.cfg import *
from Config.Config import *
import sys
import os

try:
    import requests
    import socket
    import concurrent.futures
    from urllib.parse import urlparse, urljoin
    import ssl
    import urllib3
    from requests.exceptions import RequestException
    from bs4 import BeautifulSoup
    import re
except Exception as e:
    ErrorModule(e)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DARK_BLUE = "\033[34m" 
BLUE = "\033[94m"      
WHITE = "\033[97m"
RESET = "\033[0m"

BEFORE = f"{DARK_BLUE}[{WHITE}" 
AFTER = f"{DARK_BLUE}]{RESET}"
BEFORE_DARK_BLUE = f"{DARK_BLUE}[{WHITE}"
AFTER_DARK_BLUE = f"{DARK_BLUE}]{RESET}"

INFO = f"{DARK_BLUE}{RESET}"
INPUT = f"{DARK_BLUE}{RESET}"
WAIT = f"{DARK_BLUE}{RESET}"
ERROR = f"{DARK_BLUE}{RESET}"
ADD = f"{DARK_BLUE}{RESET}"
GEN_VALID = f"{DARK_BLUE}{RESET}"

def make_request(url, headers, timeout=10):
    """Função para fazer requisições"""
    try:
        response = requests.get(
            url, 
            headers=headers, 
            timeout=timeout, 
            verify=False
        )
        return response
    except Exception as e:
        return None

def WebsiteVulnerabilityScanner():
    try:
        user_agent = ChoiceUserAgent()
        headers = {"User-Agent": user_agent}

        def InterestingPath(url):
            paths = [
                "admin", "admin/", "admin/index.php", "admin/login.php", "admin/config.php",
                "backup", "backup/", "backup/db.sql", "backup/config.tar.gz", "backup/backup.sql",
                "private", "private/", "private/.env", "private/config.php", "private/secret.txt",
                "uploads", "uploads/", "uploads/file.txt", "uploads/image.jpg", "uploads/backup.zip",
                "api", "api/", "api/v1/", "api/v1/users", "api/v1/status",
                "logs", "logs/", "logs/error.log", "logs/access.log", "logs/debug.log",
                "cache", "cache/", "cache/temp/", "cache/session/", "cache/data/",
                "server-status", "server-status/", "server-status/index.html",
                "dashboard", "dashboard/", "dashboard/index.html", "dashboard/admin.php", "dashboard/settings.php"
            ]
            CheckPaths(url, paths, "Interesting Path")

        def SensitiveFile(url):
            files = [
                "etc/passwd", "etc/password", "etc/shadow", "etc/group", "etc/hosts", "etc/hostname",
                "var/log/auth.log", "var/log/syslog", "var/log/messages", "var/log/nginx/access.log",
                "root/.bash_history", "home/user/.bash_history", "www/html/wp-config.php", "proc/self/environ",
                "opt/lampp/phpmyadmin/config.inc.php", "boot/grub/menu.lst", "proc/net/tcp"
            ]
            CheckPaths(url, files, "Sensitive File")

        def Xss(url):
            payloads = [
                "<script>alert('XssFoundByRedTiger')</script>",
                "<img src=x onerror=alert('XssFoundByRedTiger')>",
                "<svg/onload=alert('XssFoundByRedTiger')>"
            ]
            indicators = ["<script>", "alert(", "onerror=", "<svg", "javascript:"]
            TestPayloads(url, payloads, indicators, "Xss")

        def Sql(url):
            payloads = [
                "'", '"', "''", "' OR '1'='1'", "' OR '1'='1' --", "' OR '1'='1' /*", "' OR 1=1 --", "/1000",
                "' OR 1=1 /*", "' OR 'a'='a", "' OR 'a'='a' --", "' OR 'a'='a' /*", "' OR ''='", "admin'--", "admin' /*",
                "' OR 1=1#", "' OR '1'='1' (", "') OR ('1'='1", "'; EXEC xp_cmdshell('dir'); --", "' UNION SELECT NULL, NULL, NULL --", 
                "' OR 1=1 --", "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*", "' OR '1'='1'--", "' OR 1=1#", "' OR 1=1/*", 
                "' OR 'a'='a'#", "' OR 'a'='a'/*", "' OR ''=''", "' OR '1'='1'--", "admin' --", "admin' #", "' OR 1=1--", "' OR 1=1/*", 
                "' OR 'a'='a'--", "' OR ''=''", "' OR 'x'='x'", "' OR 'x'='x'--", "' OR 'x'='x'/*", "' OR 1=1#", "' OR 1=1--", 
                "' OR 1=1/*", "' OR '1'='1'/*", "' OR '1'='1'--", "' OR '1'='1'#", "' OR '1'='1'/*"
            ]
            indicators =  [
                "SQL syntax", "SQL error", "MySQL", "mysql", "MySQLYou",
                "Unclosed quotation mark", "SQLSTATE", "syntax error", "ORA-", 
                "SQLite", "PostgreSQL", "Truncated incorrect", "Division by zero",
                "You have an error in your SQL syntax", "Incorrect syntax near", 
                "SQL command not properly ended", "sql", "Sql", "Warning", "Error"
            ]
            TestPayloads(url, payloads, indicators, "Sql")

        def CheckPaths(url, paths, vulnerability_name):
            try:
                if not str(url).endswith("/"):
                    url += "/"
                found = False
                for path in paths:
                    try:
                        response = make_request(url + path, headers)
                        if response and response.status_code == 200:
                            found = True
                            print(f"{BEFORE_DARK_BLUE + current_time_hour() + AFTER_DARK_BLUE} {GEN_VALID} Vulnerability: {WHITE}{vulnerability_name}{DARK_BLUE} Status: {WHITE}True{DARK_BLUE} Path Found: {WHITE}/{path}{DARK_BLUE}")
                    except:
                        continue
                if not found:
                    print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Vulnerability: {WHITE}{vulnerability_name}{DARK_BLUE} Status: {WHITE}False{DARK_BLUE}")
            except:
                print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Vulnerability: {WHITE}{vulnerability_name}{DARK_BLUE} Status: {WHITE}Error during testing{DARK_BLUE}")

        def TestPayloads(url, payloads, indicators, vulnerability_name):
            try:
                response_old = make_request(url, headers)
                if not response_old:
                    return
                    
                if not str(url).endswith("/"):
                    url += "/"
                found = False
                for payload in payloads:
                    try:
                        response = make_request(url + payload, headers)
                        if response and response.status_code == 200 and response.text.lower() != response_old.text.lower():
                            for indicator in indicators:
                                if indicator.lower() in response.text.lower():
                                    found = True
                                    print(f"{BEFORE_DARK_BLUE + current_time_hour() + AFTER_DARK_BLUE} {GEN_VALID} Vulnerability: {WHITE}{vulnerability_name}{DARK_BLUE} Status: {WHITE}True{DARK_BLUE} Provocation: {WHITE}{payload}{DARK_BLUE} Indicator: {WHITE}{indicator}")
                                    break
                    except:
                        continue
                if not found:
                    print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Vulnerability: {WHITE}{vulnerability_name}{DARK_BLUE} Status: {WHITE}False{DARK_BLUE}")
            except:
                print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Vulnerability: {WHITE}{vulnerability_name}{DARK_BLUE} Status: {WHITE}Error during testing{DARK_BLUE}")

        print(f"{BEFORE + current_time_hour() + AFTER} {INFO} Selected User-Agent: {WHITE}{user_agent}{RESET}")
        website_url = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Website Url -> {RESET}")
        Censored(website_url)

        print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Looking for a vulnerability...")
        if "https://" not in website_url and "http://" not in website_url:
            website_url = "https://" + website_url

        Sql(website_url)
        Xss(website_url)
        InterestingPath(website_url)
        SensitiveFile(website_url)
        Continue()
        Reset()

    except Exception as e:
        Error(e)

def WebsiteUrlScanner():
    try:
        all_links = []
        
        user_agent = ChoiceUserAgent()
        headers = {"User-Agent": user_agent}

        def IsValidExtension(url):
            return re.search(r'\.(html|xhtml|php|js|css)$', url) or not re.search(r'\.\w+$', url)

        def ExtractLinks(base_url, domain, tags):
            extracted_links = []
            for tag in tags:
                attr = tag.get('href') or tag.get('src') or tag.get('action')
                if attr:
                    full_url = urljoin(base_url, attr)
                    if full_url not in all_links and domain in full_url and IsValidExtension(full_url):
                        extracted_links.append(full_url)
                        all_links.append(full_url)
            return extracted_links

        def ExtractLinksFromScript(scripts, domain):
            extracted_links = []
            for script in scripts:
                if script.string:
                    urls_in_script = re.findall(r'(https?://[^\s<>"\'\)]+)', script.string)
                    for url in urls_in_script:
                        if url not in all_links and domain in url and IsValidExtension(url):
                            extracted_links.append(url)
                            all_links.append(url)
            return extracted_links

        def FindSecretUrls(website_url, domain):
            try:
                response = make_request(website_url, headers)
                if not response or response.status_code != 200:
                    print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Failed to access website. Status: {WHITE}{response.status_code if response else 'No response'}{RESET}")
                    return
                
                soup = BeautifulSoup(response.content, 'html.parser')
                tags = soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'button', 'form'])
                extracted_links = ExtractLinks(website_url, domain, tags)
                extracted_links += ExtractLinksFromScript(soup.find_all('script'), domain)
                
                if extracted_links:
                    for link in extracted_links:
                        print(f"{BEFORE + current_time_hour() + AFTER} {ADD} Url: {WHITE}{link}{RESET}")
                else:
                    print(f"{BEFORE + current_time_hour() + AFTER} {INFO} No additional URLs found on the main page.{RESET}")
                    
            except Exception as e:
                print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Error scanning URLs: {WHITE}{e}{RESET}")

        def FindAllSecretUrls(website_url, domain):
            print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Scanning all website URLs (this may take a while)...{RESET}")
            FindSecretUrls(website_url, domain)
            visited_links = set()
            links_to_visit = all_links.copy()
            
            for link in links_to_visit:
                if link not in visited_links:
                    try:
                        response = make_request(link, headers)
                        if response and response.status_code == 200:
                            FindSecretUrls(link, domain)
                            visited_links.add(link)
                    except:
                        pass

        print(f"{BEFORE + current_time_hour() + AFTER} {INFO} Selected User-Agent: {WHITE}{user_agent}{RESET}")
        website_url = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Website Url -> {RESET}")
        Censored(website_url)
        
        if "https://" not in website_url and "http://" not in website_url:
            website_url = "https://" + website_url
        
        try:
            domain = re.sub(r'^https?://', '', website_url).split('/')[0]
        except:
            print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Invalid URL format!{RESET}")
            Continue()
            return
        
        print(f"""
 {BEFORE}01{AFTER}{WHITE} Only Main Page{RESET}
 {BEFORE}02{AFTER}{WHITE} All Website (Deep Scan){RESET}
        """)
        choice = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Choice -> {RESET}")
        
        if choice in ['1', '01']:
            FindSecretUrls(website_url, domain)
        elif choice in ['2', '02']:
            FindAllSecretUrls(website_url, domain)
        else:
            print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Invalid choice!{RESET}")
        
        Continue()
        Reset()
        
    except Exception as e:
        Error(e)

def WebsiteInfoScanner():
    try:
        user_agent = ChoiceUserAgent()
        headers = {"User-Agent": user_agent}

        def WebsiteFoundUrl(url):
            website_url = f"https://{url}" if not urlparse(url).scheme else url
            print(f"{BEFORE + current_time_hour() + AFTER} {ADD} Website: {WHITE}{website_url}{RESET}")
            return website_url

        def WebsiteDomain(website_url):
            domain = urlparse(website_url).netloc
            print(f"{BEFORE + current_time_hour() + AFTER} {ADD} Domain: {WHITE}{domain}{RESET}")
            return domain

        def WebsiteIp(domain):
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                ip = "None"
            if ip != "None":
                print(f"{BEFORE + current_time_hour() + AFTER} {ADD} IP: {WHITE}{ip}{RESET}")
            return ip

        def IpType(ip):
            if ':' in ip:
                ip_type = "ipv6" 
            elif '.' in ip:
                ip_type = "ipv4"
            else:
                return
            print(f"{BEFORE + current_time_hour() + AFTER} {ADD} IP Type: {WHITE}{ip_type}{RESET}")

        def WebsiteSecure(website_url):
            secure_status = "True" if website_url.startswith('https://') else "False"
            print(f"{BEFORE + current_time_hour() + AFTER} {ADD} Secure: {WHITE}{secure_status}{RESET}")

        def WebsiteStatus(website_url):
            try:
                response = make_request(website_url, headers)
                status_code = response.status_code if response else 404
            except RequestException:
                status_code = 404
            print(f"{BEFORE + current_time_hour() + AFTER} {ADD} Status Code: {WHITE}{status_code}{RESET}")

        def IpInfo(ip):
            try:
                api = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers).json()
            except RequestException:
                api = {}
            for key in ['country', 'hostname', 'isp', 'org', 'asn']:
                if key in api:
                    print(f"{BEFORE + current_time_hour() + AFTER} {ADD} Host {key.capitalize()}: {WHITE}{api[key]}{RESET}")

        def IpDns(ip):
            try:
                dns = socket.gethostbyaddr(ip)[0]
            except:
                dns = "None"
            if dns != "None":
                print(f"{BEFORE + current_time_hour() + AFTER} {ADD} Host DNS: {WHITE}{dns}{RESET}")

        def WebsitePort(ip):
            ports = [21, 22, 23, 25, 53, 69, 80, 110, 123, 143, 194, 389, 443, 161, 3306, 5432, 6379, 1521, 3389]
            port_protocol_map = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
                80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 194: "IRC", 389: "LDAP",
                443: "HTTPS", 161: "SNMP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
                1521: "Oracle DB", 3389: "RDP"
            }

            def ScanPort(ip, port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        if sock.connect_ex((ip, port)) == 0:
                            print(f"{BEFORE + current_time_hour() + AFTER} {ADD} Port: {WHITE}{port}{RESET} Status: {DARK_BLUE}Open{RESET} Protocol: {WHITE}{port_protocol_map.get(port, 'Unknown')}{RESET}")
                except:
                    pass

            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda p: ScanPort(ip, p), ports)

        def HttpHeaders(website_url):
            try:
                response = make_request(website_url, headers)
                if response:
                    for header, value in response.headers.items():
                        print(f"{BEFORE + current_time_hour() + AFTER} {ADD} HTTP Header: {WHITE}{header}{RESET} Value: {WHITE}{value}{RESET}")
            except RequestException:
                pass

        def CheckSslCertificate(website_url):
            try:
                with ssl.create_default_context().wrap_socket(socket.socket(), server_hostname=urlparse(website_url).hostname) as sock:
                    sock.settimeout(5)
                    sock.connect((urlparse(website_url).hostname, 443))
                    cert = sock.getpeercert()
                for key, value in cert.items():
                    print(f"{BEFORE + current_time_hour() + AFTER} {ADD} SSL Certificate Key: {WHITE}{key}{RESET} Value: {WHITE}{value}{RESET}")
            except:
                pass

        def CheckSecurityHeaders(website_url):
            security_headers = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']
            try:
                response = make_request(website_url, headers)
                if response:
                    for header in security_headers:
                        status = "Present" if header in response.headers else "Missing"
                        color = DARK_BLUE if header in response.headers else DARK_BLUE
                        print(f"{BEFORE + current_time_hour() + AFTER} {ADD} Security Header: {WHITE}{header}{RESET} Status: {color}{status}{RESET}")
            except RequestException:
                pass

        def AnalyzeCookies(website_url):
            try:
                response = make_request(website_url, headers)
                if response:
                    for cookie in response.cookies:
                        secure = 'Secure' if cookie.secure else 'Not Secure'
                        httponly = 'HttpOnly' if hasattr(cookie, '_rest') and 'HttpOnly' in cookie._rest else 'Not HttpOnly'
                        secure_color = DARK_BLUE if cookie.secure else DARK_BLUE
                        httponly_color = DARK_BLUE if 'HttpOnly' in str(cookie._rest) else DARK_BLUE
                        print(f"{BEFORE + current_time_hour() + AFTER} {ADD} Cookie: {WHITE}{cookie.name}{RESET} Secure: {secure_color}{secure}{RESET} HttpOnly: {httponly_color}{httponly}{RESET}")
            except RequestException:
                pass

        def DetectTechnologies(website_url):
            try:
                response = make_request(website_url, headers)
                if response:
                    headers = response.headers
                    soup = BeautifulSoup(response.content, 'html.parser')
                    techs = []
                    if 'x-powered-by' in headers:
                        techs.append(f"X-Powered-By: {headers['x-powered-by']}")
                    if 'server' in headers:
                        techs.append(f"Server: {headers['server']}")
                    for script in soup.find_all('script', src=True):
                        if 'jquery' in script['src']:
                            techs.append("jQuery")
                        if 'bootstrap' in script['src']:
                            techs.append("Bootstrap")
                    for tech in techs:
                        print(f"{BEFORE + current_time_hour() + AFTER} {ADD} Detected Technology: {WHITE}{tech}{RESET}")
            except:
                pass

        print(f"{BEFORE + current_time_hour() + AFTER} {INFO} Selected User-Agent: {WHITE}{user_agent}{RESET}")
        url = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Website URL -> {RESET}")
        Censored(url)
        print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Scanning..{RESET}")

        website_url = WebsiteFoundUrl(url)
        domain = WebsiteDomain(website_url)
        ip = WebsiteIp(domain)
        IpType(ip)
        WebsiteSecure(website_url)
        WebsiteStatus(website_url)
        IpInfo(ip)
        IpDns(ip)
        WebsitePort(ip)
        HttpHeaders(website_url)
        CheckSslCertificate(website_url)
        CheckSecurityHeaders(website_url)
        AnalyzeCookies(website_url)
        DetectTechnologies(website_url)
        Continue()
        Reset()

    except Exception as e:
        Error(e)

def IpPortScanner():
    try:
        def PortScanner(ip):
            port_protocol_map = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
                80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 194: "IRC", 389: "LDAP",
                443: "HTTPS", 161: "SNMP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
                1521: "Oracle DB", 3389: "RDP"
            }

            def ScanPort(ip, port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(0.1)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            protocol = port_protocol_map.get(port, "Unknown")
                            print(f"{BEFORE + current_time_hour() + AFTER} {ADD} Port: {WHITE}{port}{RESET} Status: {DARK_BLUE}Open{RESET} Protocol: {WHITE}{protocol}{RESET}")
                except Exception:
                    pass

            common_ports = list(port_protocol_map.keys()) + [8080, 8443, 9000, 27017, 11211]
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                executor.map(lambda port: ScanPort(ip, port), common_ports)

        ip = input(f"\n{BEFORE + current_time_hour() + AFTER} {INPUT} Ip -> {RESET}")
        print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Scanning..")
        PortScanner(ip)
        Continue()
        Reset()
    except Exception as e:
        Error(e)

def MainPanel():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        
        banner = """                                                                                                                                                                                                                                                                 
                             %@+*@@.                             %@*+@%                        
                             @@ .@@                              @@..%@                        
                              #@@%                               :%@@%                        
                              .@@    @@%@@                @@%@@    @@                             
                             ..@@   %@..*@               :@*..@%...@@                              
               . .... .     ...@@    @@@@@              .-@@@@@....@@                  
              ....%@- .      .  @@#.. . .=@@:.        .:@@=... ..*@@           -@%:               
              ..%@*+@@-:::::.....=@@+.... .+@@:     .:@@*......=@@=           @@**@%.               
              ..@@::@@%%%%%%@#. ...*@@:......#@%....#@%......:@@#.....#@@%%%%%@@::@@                
              ...#@@#.. .....%@*.....#@@:.....@%....#@.....:%@#.....*@@...  ...#@@#..               
              ........ .......-@@+.....@@.....@%....#@.....@@.....=@@-. . . .....  ..               
                            ....*@+... %@.....@%  . #@.. ..@%....+@#...                             
                            ....+@+... %@.....@%  . #@.. . @%....+@*...                             
                 #@@%...        +@+....%@ ....@%....#@.....@%....+@*..      ...#@@#.                
                @@::%@-         +@+....#@#%@@@@@@@@@@@@@@%#@%....+@*..      .:@%::@@                
                #@%#@@-.        +@*#@@@@%-:........ .....:-%@@@@#*@*..     ..:@@#%@#.               
                  **:@@@......:@@@@*..... ....:%@@@@%:..........*@@@@.......@@@:**:               
                    ...%@@.:@@@%. . ...  . #@@@*...:*@@@#.... . ....%@@@-.@@%               
                   .....:@@@+....     ...#@@.. .........@@#..         .+@@@-               
                   ...#@@*..... .    ...@@-......::......:@@.         ....*@@%                
                   :@@%:.........    ..#@-....*@@@@@@*....-@#         ......:%@@-               
                -@@*...             ..@# ... %@+..  =@%. . .#@.....         ....*@@=               
               +@@.....             :@#.. .. @%.... .%@:... *@:....         ... ..@@*               
                 =@@*.. ....         .@#  ...%@=... =@%.. .#@.....     ........*@@=                
                   -@@#:.....         #@:....*@@%%@@*.. ..:@#          .....:#@@-              
                     #@@*...        ...@@-......::......:@@.          ...+@@%                
                     ..-@@@=. ..........%@@............%@%............-@@@-              
                       #@@:-@@@#...........#@@@+....+@@@%...........#@@@-.@@%.              
              ....+*.@@@......:@@@@*... . .. .-@@@@@@= .. ..... +@@@@:. ... @@@.**..                
              ..#@%#@@-     ....+@*%@@@@#::..............::#@@@@%*@*...    ..:@@#%@#.               
              ..@@:.%@-.     ...+@+....%@%@@@@@@@@@@@@@@@@%@%....+@*...    ..:@%..%@.               
              ...#@@%...    ....+@+....%@... .@%  . #@.... @%... +@*...    ....%@@#:.               
                          +@+....%@... .@%  . #@.... @%... +@*...                   
                             .. *@+....%@... .@%  . #@.. . @%... +@#...                    
                      .-@@+.....@@.....@%  . #@.....@@.....=@@-...                
              ...*@@#........%@*.....#@@:.....@%  . #@.....:@@#.....*@@. ......#@@#..               
              ..@@-:@@#####%@#.....*@@-......#@%... #@#.... .:@@*.....#@%#####@@::@@.               
              ..%@*+@@-::::::....=@@+.... .+@@:......:@@*......=@@=.....:::::-@@+*@%.               
              ...:%@=...........@@#......-@@:..... ....-@@=......#@@....... ...-@%:..               
                             ..@@. ..@@@@@+ ...          =@@@@@.. .@@.                              
                             ..@@...%@..*@-....         .:@*..@%...@@..                             
                             ..@@...+@@%@@:....         ..@@%@@+...@@.. .                           
                             :#@@#:...-+...             .         #@@%:                        
                            .@@..@@:                             @@..@@                        
                            .%@+*@%                              %@*+@%                         
                            ..-++-                                -++-                                                 
        """
       
        print(f"{DARK_BLUE}{banner}{RESET}")        
        
        print(f"""
{BEFORE}01{AFTER} {WHITE}Website Vulnerability Scanner{RESET}
{BEFORE}02{AFTER} {WHITE}Website URL Scanner{RESET}  
{BEFORE}03{AFTER} {WHITE}Website Info Scanner{RESET}
{BEFORE}04{AFTER} {WHITE}IP Port Scanner{RESET}
{BEFORE}00{AFTER} {WHITE}Exit{RESET}
        """)
        
        choice = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Choice -> {RESET}")
        
        if choice == '01' or choice == '1':
            WebsiteVulnerabilityScanner()
        elif choice == '02' or choice == '2':
            WebsiteUrlScanner()
        elif choice == '03' or choice == '3':
            WebsiteInfoScanner()
        elif choice == '04' or choice == '4':
            IpPortScanner()
        elif choice == '00' or choice == '0':
            print(f"\n{BEFORE + current_time_hour() + AFTER} {INFO} Thanks for using!")
            sys.exit()
        else:
            print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Invalid choice!")

if __name__ == "__main__":
    try:
        MainPanel()
    except KeyboardInterrupt:
        print(f"\n{BEFORE + current_time_hour() + AFTER} {ERROR} Interrupted by user!")
        sys.exit()
    except Exception as e:
        Error(e)