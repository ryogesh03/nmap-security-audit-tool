import nmap

def simple_security_audit(target):
    nm = nmap.PortScanner()
    print(f"--- Starting Security Audit for: {target} ---")
    
    # Run the scan with vulnerability scripts
    nm.scan(target, arguments='-sV --script vuln')
    
    vulns_found = 0 # Initialize the counter here

    with open("audit_report.txt", "w") as f:
        f.write(f"Security Audit Report for {target}\n" + "="*40 + "\n")

        for host in nm.all_hosts():
            f.write(f"\nHost: {host} ({nm[host].hostname()})\n")
            
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port]['version']
                    
                    f.write(f"[!] Port {port}: {service} (Version: {version})\n")

                    # Only count it as a finding if it's actually a potential thret
                    if 'script' in nm[host][proto][port]:
                        for script_id, result in nm[host][proto][port]['script'].items():
                            # Only count fings that aren't "Couldn't find"
                            if "Couldn't find" not in result and "ERROR" not in result:
                                vulns_found += 1 
                            f.write(f"    --> {script_id}: {result}\n")

        # Now write the summary AFTER the loops are finished
        f.write("\n" + "="*40 + "\n")
        f.write("FINAL SECURITY SCORE\n")
        if vulns_found == 0:
            f.write("Status: LOW RISK - No vulnerabilities detected.\n")
        else:
            f.write(f"Status: MEDIUM/HIGH RISK - {vulns_found} findings detected.\n")

    print(f"--- Audit Complete. {vulns_found} findings saved to report. ---")

target_ip = input("Enter Target IP : ")
simple_security_audit(target_ip)