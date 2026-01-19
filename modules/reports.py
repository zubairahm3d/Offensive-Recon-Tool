import os
from datetime import datetime

def create_report(data, target, format_type="txt", filename=None):
    
    os.makedirs("reports", exist_ok=True)
    
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"reports/{target}_{timestamp}"
    
    if format_type == "txt":
        filename += ".txt"
        return create_txt_report(data, target, filename)
    
    else:  # html
        filename += ".html"
        return create_html_report(data, target, filename)

def create_txt_report(data, target, filepath):
    #text report
    with open(filepath, 'w') as f:
        f.write(f"{'='*50}\n")
        f.write(f"SCAn REPORT\n")
        f.write(f"{'='*50}\n")
        f.write(f"Target: {target}\n")
        f.write(f"Date: {datetime.now()}\n")
        
        if data.get('port_scan'):
            f.write(f"\n[PORT SCAn]\n")
            ports = data['port_scan'].get('open_ports', [])
            if ports:
                for p in ports:
                    f.write(f"  Port {p.get('port')}: {p.get('service', '?')}\n")
            else:
                f.write(f"  No open ports\n")
        
        if data.get('dns_lookup'):
            f.write(f"\n[DNS]\n")
            records = data['dns_lookup'].get('records', {})
            for rtype, values in records.items():
                f.write(f"  {rtype}:\n")
                for v in values:
                    f.write(f"    • {v}\n")
        
        if data.get('subdomain'):
            f.write(f"\n[SUBDOMAINS]\n")
            subs = data['subdomain'].get('subdomains', [])
            if subs:
                for s in subs:
                    f.write(f"  • {s}\n")
            else:
                f.write(f"  No subdomains found\n")
        
        if data.get('whois_lookup'):
            f.write(f"\n[WHOIS]\n")
            info = data['whois_lookup'].get('whois_data', 'No data')
            f.write(f"  {info}\n")
        
        if data.get('banner_grab'):
            f.write(f"\n[BANNERS]\n")
            banners = data['banner_grab'].get('banners', [])
            if banners:
                for b in banners:
                    f.write(f"  Port {b.get('port')}:\n")
                    banner = b.get('banner', '')
                    if banner:
                        f.write(f"    {banner[:100]}...\n")
            else:
                f.write(f"  No banners grabbed\n")
        
        if data.get('tech_detect'):
            f.write(f"\n[TECHNOLOGIES]\n")
            techs = data['tech_detect'].get('technologies', [])
            if techs:
                for tech in techs:
                    f.write(f"  • {tech}\n")
            else:
                f.write(f"  No technologies detected\n")
    
    print(f"[+] Text report: {filepath}")
    return filepath
    #HTML report
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
    
    for module_name, module_data in data.items():
        html += f'<div class="card"><h3>{module_name.replace("_", " ").upper()}</h3>'
        
        if module_name == "port_scan":
            ports = module_data.get("open_ports", [])
            if ports:
                html += '<ul>'
                for p in ports:
                    html += f'<li>Port {p.get("port")}: {p.get("service", "unknown")}</li>'
                html += '</ul>'
            else:
                html += '<p>No open ports</p>'
        
        elif module_name == "dns_lookup":
            records = module_data.get("records", {})
            if records:
                html += '<ul>'
                for rtype, values in records.items():
                    for v in values:
                        html += f'<li><strong>{rtype}:</strong> {v}</li>'
                html += '</ul>'
            else:
                html += '<p>No DNS records</p>'
        
        elif module_name == "subdomain":
            subs = module_data.get("subdomains", [])
            if subs:
                html += '<ul>'
                for s in subs:
                    html += f'<li>{s}</li>'
                html += '</ul>'
            else:
                html += '<p>No subdomains found</p>'
        
        elif module_name == "whois_lookup":
            info = module_data.get("whois_data", "")
            if info:
                html += f'<pre>{info}</pre>'
            else:
                html += '<p>No WHOIS data</p>'
        
        elif module_name == "banner_grab":
            banners = module_data.get("banners", [])
            if banners:
                for b in banners:
                    banner_text = b.get("banner", "")
                    if banner_text:
                        html += f'<p><strong>Port {b.get("port")}:</strong> {banner_text[:200]}...</p>'
            else:
                html += '<p>No banners grabbed</p>'
        
        elif module_name == "tech_detect":
            techs = module_data.get("technologies", [])
            if techs:
                html += '<div class="tech-grid">'
                for tech in techs:
                    html += f'<div class="tech-item">{tech}</div>'
                html += '</div>'
            else:
                html += '<p>No technologies detected</p>'
        
        html += '</div>'
    
    html += f"""
<hr>
</body>
</html>"""
    
    with open(filepath, 'w') as f:
        f.write(html)
    
    print(f"[+] HTML report: {filepath}")
    return filepath