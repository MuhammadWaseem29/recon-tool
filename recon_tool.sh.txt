#!/bin/bash

. ./configuration.cfg

actualDir=$(pwd)

# Function to check and install tools if not present
install_tools() {
    tools=("whatweb" "python3" "git" "curl" "dirsearch" "nmap" "python3-venv" "python3-pip" "subfinder" "httpx" "nuclei" "arjun" "gau" "dalfox" "findomain" "mailspoof" "subjack" "corsy" "python3-shcheck" "python3-cloud_enum" "gitdorker" "hakrawler" "html2text" "anew" "python3-secretfinder")

    for tool in "${tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            echo "$tool not found. Installing..."
            if [ "$tool" == "python3" ]; then
                sudo apt-get install -y python3 python3-pip
            elif [ "$tool" == "python3-venv" ]; then
                sudo apt-get install -y python3-venv
            elif [ "$tool" == "subfinder" ]; then
                GO111MODULE=on go install -v github.com/subfinder/subfinder/cmd/subfinder@latest
            elif [ "$tool" == "httpx" ]; then
                GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
            elif [ "$tool" == "nuclei" ]; then
                GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
            elif [ "$tool" == "arjun" ]; then
                git clone https://github.com/s0md3v/Arjun.git
                cd Arjun
                pip3 install -r requirements.txt
                cd ..
            elif [ "$tool" == "gau" ]; then
                GO111MODULE=on go install -v github.com/lc/gau@latest
            elif [ "$tool" == "dalfox" ]; then
                GO111MODULE=on go install -v github.com/hahwul/dalfox/v2@latest
            elif [ "$tool" == "findomain" ]; then
                curl -s https://api.github.com/repos/findomain/findomain/releases/latest | grep "browser_download_url" | grep "linux" | cut -d '"' -f 4 | wget -i -
                tar -xvf findomain-linux*
                sudo mv findomain /usr/local/bin/
            elif [ "$tool" == "mailspoof" ]; then
                pip3 install mailspoof
            elif [ "$tool" == "subjack" ]; then
                go install github.com/haccer/subjack@latest
            elif [ "$tool" == "corsy" ]; then
                pip3 install corsy
            elif [ "$tool" == "python3-shcheck" ]; then
                pip3 install shcheck
            elif [ "$tool" == "python3-cloud_enum" ]; then
                git clone https://github.com/aboul3la/Sublist3r.git
                cd Sublist3r
                pip3 install -r requirements.txt
                cd ..
            elif [ "$tool" == "gitdorker" ]; then
                git clone https://github.com/obheda12/GitDorker.git
                cd GitDorker
                pip3 install -r requirements.txt
                cd ..
            elif [ "$tool" == "hakrawler" ]; then
                GO111MODULE=on go install -v github.com/hakluke/hakrawler@latest
            elif [ "$tool" == "html2text" ]; then
                pip3 install html2text
            elif [ "$tool" == "anew" ]; then
                GO111MODULE=on go install -v github.com/tomnomnom/anew@latest
            elif [ "$tool" == "python3-secretfinder" ]; then
                pip3 install SecretFinder
            else
                sudo apt-get install -y $tool
            fi
        fi
    done
}

# Install required tools
install_tools

##############################################
############### PASSIVE RECON ################
##############################################
passive_recon() {
    printf "${BOLD}${GREEN}[*] STARTING FOOTPRINTING${NORMAL}\n\n"
    printf "${BOLD}${GREEN}[*] TARGET URL:${YELLOW} $domain ${NORMAL}\n"
    ip_address=$(dig +short $domain)
    printf "${BOLD}${GREEN}[*] TARGET IP ADDRESS:${YELLOW} $ip_address ${NORMAL}\n\n"
    
    domain=$1
    domainName="https://"$domain
    company=$(echo $domain | awk -F[.] '{print $1}')
    
    cd targets
    
    if [ -d $domain ]; then rm -Rf $domain; fi
    mkdir $domain
    
    cd $domain
    
    if [ -d footprinting ]; then rm -Rf footprinting; fi
    mkdir footprinting
    
    cd footprinting
    
    printf "${GREEN}[+] Checking if the target is alive...${NORMAL}\n"
    if ping -c 1 -W 1 "$domain" &> /dev/null; 
    then
        printf "\n${BOLD}${YELLOW}$domain${NORMAL} is alive!${NORMAL}\n\n"
    else
        if [ $mode == "more" ]
        then
            printf "\n${BOLD}${YELLOW}$domain${RED} is not alive.${NORMAL}\n\n"
            return
        else
            printf "\n${BOLD}${YELLOW}$domain${RED} is not alive. Aborting passive reconnaissance${NORMAL}\n\n"
            exit 1
        fi    
    fi
    
    printf "${GREEN}[+] Whois Lookup${NORMAL}\n"
    printf "${NORMAL}${CYAN}Searching domain name details, contact details of domain owner, domain name servers, netRange, domain dates, expiry records, records last updated...${NORMAL}\n\n"
    whois $domain | grep 'Domain\|Registry\|Registrar\|Updated\|Creation\|Registrant\|Name Server\|DNSSEC:\|Status\|Whois Server\|Admin\|Tech' | grep -v 'the Data in VeriSign Global Registry' | tee whois.txt
    
    printf "\n${GREEN}[+] Nslookup ${NORMAL}\n"
    printf "${NORMAL}${CYAN}Searching DNS Queries...${NORMAL}\n\n"
    nslookup $domain | tee nslookup.txt
    
    printf "\n${GREEN}[+] Horizontal domain correlation/acquisitions ${NORMAL}\n"
    printf "${NORMAL}${CYAN}Searching horizontal domains...${NORMAL}\n\n"
    email=$(whois $domain | grep "Registrant Email" | egrep -ho "[[:graph:]]+@[[:graph:]]+")
    curl -s -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" "https://viewdns.info/reversewhois/?q=$email" | html2text | grep -Po "[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)" | tail -n +4  | head -n -1 
    
    printf "\n${GREEN}[+] ASN Lookup ${NORMAL}\n"
    printf "${NORMAL}${CYAN}Searching ASN number of a company that owns the domain...${NORMAL}\n\n"
    python3 ~/tools/Asnlookup/asnlookup.py -o $company | tee -a asn.txt
    
    printf "\n${GREEN}[+] WhatWeb ${NORMAL}\n"
    printf "${NORMAL}${CYAN}Searching platform, type of script, google analytics, web server platform, IP address, country, server headers, cookies...${NORMAL}\n\n"
    whatweb $domain | tee whatweb.txt
    
    printf "\n${GREEN}[+] SSL Checker ${NORMAL}\n"
    printf "${NORMAL}${CYAN}Collecting SSL/TLS information...${NORMAL}\n\n"
    python3 ~/tools/ssl-checker/ssl_checker.py -H $domainName | tee ssl.txt
    
    printf "\n${GREEN}[+] Aquatone ${NORMAL}\n"
    printf "${NORMAL}${CYAN}Taking screenshot...${NORMAL}\n\n"
    echo $domainName | aquatone -screenshot-timeout $aquatoneTimeout -out screenshot &> /dev/null
    
    printf "\n${GREEN}[+] TheHarvester ${NORMAL}\n"
    printf "${NORMAL}${CYAN}Searching emails, subdomains, hosts, employee names...${NORMAL}\n\n"
    python3 ~/tools/theHarvester/theHarvester.py -d $domain -b all -l 500 -f theharvester.html > theharvester.txt
    printf "${NORMAL}${CYAN}Users found: ${NORMAL}\n\n"
    cat theharvester.txt | awk '/Users/,/IPs/' | sed -e '1,2d' | head -n -2 | anew -q users.txt
    cat users.txt
    printf "${NORMAL}${CYAN}IP Address: ${NORMAL}\n\n"
    cat theharvester.txt | awk '/IP Address/,/Hostnames/' | sed -e '1,2d' | head -n -2 | anew -q ip.txt
    cat ip.txt
    
    printf "\n${GREEN}[+] Sublist3r ${NORMAL}\n"
    printf "${NORMAL}${CYAN}Collecting subdomains...${NORMAL}\n\n"
    python3 ~/tools/Sublist3r/sublist3r.py -d $domain -o sublist3r.txt
    cat sublist3r.txt | anew -q subdomains.txt
    
    printf "\n${GREEN}[+] Assetfinder ${NORMAL}\n"
    printf "${NORMAL}${CYAN}Collecting assets from a target domain...${NORMAL}\n\n"
    assetfinder --subs-only $domain | anew -q assetfinder.txt
    
    printf "\n${GREEN}[+] Subfinder ${NORMAL}\n"
    printf "${NORMAL}${CYAN}Finding subdomains...${NORMAL}\n\n"
    subfinder -d $domain -o subfinder.txt
    cat subfinder.txt | anew -q subdomains.txt
    
    printf "\n${GREEN}[+] Nmap ${NORMAL}\n"
    printf "${NORMAL}${CYAN}Scanning ports...${NORMAL}\n\n"
    nmap -sS -sC -sV -p- $domain -oN nmap.txt
    cat nmap.txt
    
    printf "\n${GREEN}[+] Screenshot ${NORMAL}\n"
    printf "${NORMAL}${CYAN}Taking screenshots...${NORMAL}\n\n"
    aquatone -url $domain -out screenshots
    
    cd ..
}

# Pass domain as argument
passive_recon $1
