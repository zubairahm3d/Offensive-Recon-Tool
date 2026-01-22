import os
from datetime import datetime

def create_report(data, target, format_type="txt", filename=None):
        
    os.makedirs("reports", exist_ok=True)
    
    if not filename:
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")
        filename = f"reports/{target}_{timestamp}"
    
    if format_type == "txt" or format_type == "text":
        filename += ".txt"
        return create_txt_report(data, target, filename)
    
    else:  # html
        filename += ".html"
        return create_html_report(data, target, filename)

def create_txt_report(data, target, filepath):
    #text report
    with open(filepath, 'w') as f:
        f.write(f"{'='*50}\n")
        f.write(f"SCAN REPORT\n")
        f.write(f"{'='*50}\n")
        f.write(f"Target: {target}\n")
        f.write(f"Date: {datetime.now()}\n")
        
        if 'port_scan' in data:
            f.write(f"\n[PORT SCAN]\n")
            scan = data['port_scan']
            if 'error' in scan:
                f.write(f"Error: {scan['error']}\n")
            else:
                ports = scan.get('open_ports', [])
                if ports:
                    for p in ports:
                        f.write(f"  Port {p.get('port')}: {p.get('service', '?')}\n")
                else:
                    f.write(f"  No open ports\n")
        
        if 'dns_enum' in data:
            f.write(f"\n[DNS]\n")
            dns = data['dns_enum']
            if 'error' in dns:
                f.write(f"Error: {dns['error']}\n")
            else:
                records = dns.get('records', {})
                for rtype, values in records.items():
                    f.write(f"  {rtype}:\n")
                    for v in values:
                        f.write(f"    • {v}\n")
        
        if 'subdomain_enum' in data:
            f.write(f"\n[SUBDOMAINS]\n")
            sub = data['subdomain_enum']
            if 'error' in sub:
                f.write(f"Error: {sub['error']}\n")
            else:
                subs = sub.get('subdomains', [])
                for s in subs:
                    f.write(f"  • {s}\n")
        
        if 'whois_lookup' in data:
            f.write(f"\n[WHOIS]\n")
            whois = data['whois_lookup']
            if 'error' in whois:
                f.write(f"Error: {whois['error']}\n")
            else:
                info = whois.get('whois_data', '')
                if info:
                    f.write(f"  {info}\n")
        
        if 'banner_grab' in data:
            f.write(f"\n[BANNERS]\n")
            banner = data['banner_grab']
            if 'error' in banner:
                f.write(f"Error: {banner['error']}\n")
            else:
                banners = banner.get('banners', [])
                for b in banners:
                    f.write(f"  Port {b.get('port')}:\n")
                    banner_text = b.get('banner', '')
                    if banner_text:
                        f.write(f"    {banner_text[:100]}...\n")
        
        if 'tech_detect' in data:
            f.write(f"\n[TECHNOLOGIES]\n")
            tech = data['tech_detect']
            if 'error' in tech:
                f.write(f"Error: {tech['error']}\n")
            else:
                techs = tech.get('technologies', [])
                for t in techs:
                    f.write(f"  • {t}\n")
    
    print(f"[+] Text report: {filepath}")
    return filepath
    #HTML REPORT
def create_html_report(data, target, filepath):
    
    html = f"""<!DOCTYPE html>
<html>
<head>
<title>Recon Report - {target}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
.header {{ background: linear-gradient(to right, #0066cc, #0099ff); 
          color: white; padding: 20px; border-radius: 10px; }}
.card {{ background: #f8f9fa; padding: 15px; margin: 10px 0; 
        border-left: 4px solid #0066cc; border-radius: 5px; }}
.badge {{ background: #28a745; color: white; padding: 3px 8px; 
         border-radius: 10px; font-size: 0.9em; }}
.tech-item {{ background: #e9ecef; padding: 8px; margin: 5px 0; border-radius: 5px; }}
</style>
</head>
<body>

<div class="header">
<h1>Recon Report</h1>
<h3>Target: {target}</h3>
<p>Date: {datetime.now()}</p>
</div>

<h2> Findings</h2>
"""
    
    if 'port_scan' in data:
        scan = data['port_scan']
        html += f'<div class="card"><h3>PORT SCAN</h3>'
        if 'error' in scan:
            html += f'<p style="color:red;">Error: {scan["error"]}</p>'
        else:
            ports = scan.get('open_ports', [])
            if ports:
                html += '<ul>'
                for p in ports:
                    html += f'<li>Port {p.get("port")}: {p.get("service", "unknown")}</li>'
                html += '</ul>'
            else:
                html += '<p>No open ports</p>'
        html += '</div>'
    
    if 'dns_enum' in data:
        dns = data['dns_enum']
        html += f'<div class="card"><h3>DNS ENUMERATION</h3>'
        if 'error' in dns:
            html += f'<p style="color:red;">Error: {dns["error"]}</p>'
        else:
            records = dns.get('records', {})
            if records:
                html += '<ul>'
                for rtype, values in records.items():
                    for v in values:
                        html += f'<li><strong>{rtype}:</strong> {v}</li>'
                html += '</ul>'
            else:
                html += '<p>No DNS records</p>'
        html += '</div>'
    
    if 'subdomain_enum' in data:
        sub = data['subdomain_enum']
        html += f'<div class="card"><h3>SUBDOMAIN ENUMERATION</h3>'
        if 'error' in sub:
            html += f'<p style="color:red;">Error: {sub["error"]}</p>'
        else:
            subs = sub.get('subdomains', [])
            if subs:
                html += '<ul>'
                for s in subs:
                    html += f'<li>{s}</li>'
                html += '</ul>'
            else:
                html += '<p>No subdomains found</p>'
        html += '</div>'

    if 'whois_lookup' in data:
        whois = data['whois_lookup']
        html += f'<div class="card"><h3>WHOIS LOOKUP</h3>'
        if 'error' in whois:
            html += f'<p style="color:red;">Error: {whois["error"]}</p>'
        else:
            info = whois.get('whois_data', '')
            if info:
                html += f'<pre>{info}</pre>'
            else:
                html += '<p>No WHOIS data</p>'
        html += '</div>'
    
    if 'banner_grab' in data:
        banner = data['banner_grab']
        html += f'<div class="card"><h3>BANNER GRABBING</h3>'
        if 'error' in banner:
            html += f'<p style="color:red;">Error: {banner["error"]}</p>'
        else:
            banners = banner.get('banners', [])
            if banners:
                for b in banners:
                    banner_text = b.get('banner', '')
                    if banner_text:
                        html += f'<p><strong>Port {b.get("port")}:</strong> {banner_text[:200]}...</p>'
            else:
                html += '<p>No banners grabbed</p>'
        html += '</div>'
    
    if 'tech_detect' in data:
        tech = data['tech_detect']
        html += f'<div class="card"><h3>TECHNOLOGY DETECTION</h3>'
        if 'error' in tech:
            html += f'<p style="color:red;">Error: {tech["error"]}</p>'
        else:
            techs = tech.get('technologies', [])
            if techs:
                html += '<div class="tech-grid">'
                for t in techs:
                    html += f'<div class="tech-item">{t}</div>'
                html += '</div>'
            else:
                html += '<p>No technologies detected</p>'
    if 'crawler' in data:
        urls = data['crawler'].get("urls", [])
        html += f'<div class="card"><h3>CRAWLER RESULTS ({len(urls)})</h3>'
        if urls:
            html += '<div style="max-height: 300px; overflow-y: auto;"><ul>'
            for url in urls:
                html += f'<li><a href="{url}" target="_blank">{url}</a></li>'
            html += '</ul></div>'
        else:
            html += '<p>No URLs found</p>'
        html += '</div>'

    if 'extractor' in data:
        html += '<div class="card"><h3>EXTRACTOR RESULTS</h3>'
        ext_data = data['extractor']
        js_files = ext_data.get("js_files", [])
        params = ext_data.get("parameters", [])
        
        if js_files:
            html += f'<h4>JavaScript Files ({len(js_files)})</h4><ul>'
            for js in js_files:
                html += f'<li>{js}</li>'
            html += '</ul>'
        
        if params:
            html += f'<h4>Parameters ({len(params)})</h4><ul>'
            for param in params:
                html += f'<li>{param}</li>'
            html += '</ul>'
            
        if not js_files and not params:
            html += '<p>No data extracted</p>'
        html += '</div>'
        html += '</div>'
    
    html += f"""
<hr>
<p style="text-align: center; color: #666;">
Report Generated by Recon Tool | ITSOLERA Red Team Gamma
</p>
</body>
</html>"""
    
    with open(filepath, 'w') as f:
        f.write(html)
    
    print(f"[+] HTML report: {filepath}")
    return filepath
