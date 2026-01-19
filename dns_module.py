# dns_module.py
from dns.resolver import Resolver, NoAnswer, NXDOMAIN, Timeout, NoNameservers
import concurrent.futures

class DNSModule:
    DEFAULT_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

    def __init__(self, nameserver=None):
        self.resolver = Resolver()
        if nameserver:
            self.resolver.nameservers = [nameserver]
        self.resolver.timeout = 4
        self.resolver.lifetime = 4

    def query(self, domain, rtype):
        results = []
        try:
            answers = self.resolver.resolve(domain, rtype)
            for r in answers:
                if rtype == 'MX':
                    results.append(f"{r.preference} {r.exchange}")
                elif rtype == 'TXT':
                    parts = [x.decode() if isinstance(x, bytes) else x for x in r.strings]
                    results.append(" ".join(parts))
                else:
                    results.append(str(r))
        except (NoAnswer, NXDOMAIN, NoNameservers, Timeout):
            pass
        except Exception:
            pass
        return results

    def run(self, domain, types=None):
        if types is None:
            types = self.DEFAULT_TYPES

        out = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as exe:
            future_map = {exe.submit(self.query, domain, t): t for t in types}
            for future in concurrent.futures.as_completed(future_map):
                rtype = future_map[future]
                res = future.result()
                if res:
                    out[rtype] = res
        return out


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 dns_module.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    dns = DNSModule()
    results = dns.run(domain)

    for rtype, vals in results.items():
        print(rtype + ":")
        for v in vals:
            print(" ", v)

