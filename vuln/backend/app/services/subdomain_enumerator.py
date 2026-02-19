import socket
import dns.resolver
import dns.exception
import requests
from typing import List, Set, Dict, Any
import time
import concurrent.futures
from urllib.parse import urlparse


class SubdomainEnumerator:
    """
    Subdomain enumeration service using DNS brute force and common subdomain lists.
    """

    # Common subdomains to try
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'app',
        'blog', 'shop', 'store', 'news', 'support', 'help', 'docs', 'wiki',
        'forum', 'community', 'portal', 'login', 'secure', 'ssl', 'webmail',
        'remote', 'vpn', 'cloud', 'cdn', 'static', 'assets', 'media', 'files',
        'download', 'upload', 'backup', 'db', 'database', 'sql', 'mysql', 'postgres',
        'mongo', 'redis', 'cache', 'session', 'auth', 'oauth', 'sso', 'ldap',
        'jenkins', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence', 'slack',
        'teams', 'zoom', 'meet', 'webex', 'gotomeeting', 'skype', 'discord',
        'chat', 'messenger', 'whatsapp', 'telegram', 'signal', 'matrix',
        'git', 'svn', 'hg', 'cvs', 'repo', 'repository', 'code', 'ci', 'cd',
        'build', 'deploy', 'staging', 'prod', 'production', 'live', 'demo',
        'sandbox', 'test', 'qa', 'uat', 'devops', 'monitoring', 'logs', 'metrics',
        'grafana', 'kibana', 'elasticsearch', 'prometheus', 'alertmanager',
        'zabbix', 'nagios', 'icinga', 'munin', 'cacti', 'smokeping',
        'vpn', 'rdp', 'ssh', 'ftp', 'sftp', 'smb', 'nfs', 'cifs',
        'mssql', 'oracle', 'db2', 'sybase', 'informix', 'teradata',
        'hadoop', 'spark', 'kafka', 'zookeeper', 'cassandra', 'couchdb',
        'rabbitmq', 'activemq', 'zeromq', 'mqtt', 'amqp',
        'kubernetes', 'k8s', 'docker', 'container', 'registry', 'harbor',
        'traefik', 'nginx', 'apache', 'iis', 'tomcat', 'jboss', 'wildfly',
        'weblogic', 'websphere', 'glassfish', 'jetty', 'gunicorn', 'uwsgi',
        'php', 'python', 'java', 'nodejs', 'ruby', 'go', 'rust', 'scala',
        'clojure', 'erlang', 'elixir', 'haskell', 'ocaml', 'fsharp',
        'mobile', 'ios', 'android', 'windows', 'mac', 'linux', 'unix',
        'api1', 'api2', 'api3', 'v1', 'v2', 'v3', 'beta', 'alpha', 'gamma',
        'internal', 'external', 'public', 'private', 'shared', 'corporate',
        'enterprise', 'business', 'customer', 'client', 'user', 'member',
        'partner', 'vendor', 'supplier', 'distributor', 'reseller',
        'ns1', 'ns2', 'ns3', 'dns1', 'dns2', 'mx1', 'mx2', 'smtp', 'imap', 'pop3'
    ]

    def __init__(self, timeout: float = 2.0, max_workers: int = 10):
        self.timeout = timeout
        self.max_workers = max_workers
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def enumerate_subdomains(self, domain: str, use_brute_force: bool = True) -> Dict[str, Any]:
        """
        Enumerate subdomains for a given domain.

        Args:
            domain: Base domain to enumerate (e.g., 'example.com')
            use_brute_force: Whether to use DNS brute force

        Returns:
            Dict containing discovered subdomains and metadata
        """
        domain = domain.lower().strip()
        if not domain:
            return {
                'status': 'error',
                'message': 'Domain is required',
                'subdomains': [],
                'total_found': 0
            }

        # Remove protocol if present
        if '://' in domain:
            domain = urlparse(domain).netloc

        discovered_subdomains = set()
        start_time = time.time()

        try:
            # Always check the base domain first
            if self._check_subdomain(domain):
                discovered_subdomains.add(domain)

            if use_brute_force:
                # Use DNS brute force with common subdomains
                brute_force_results = self._brute_force_subdomains(domain)
                discovered_subdomains.update(brute_force_results)

            # Try certificate transparency logs (basic implementation)
            ct_results = self._check_certificate_transparency(domain)
            discovered_subdomains.update(ct_results)

            # Sort results
            sorted_subdomains = sorted(list(discovered_subdomains))

            return {
                'status': 'success',
                'domain': domain,
                'subdomains': sorted_subdomains,
                'total_found': len(sorted_subdomains),
                'scan_time': round(time.time() - start_time, 2),
                'method': 'dns_brute_force'
            }

        except Exception as e:
            return {
                'status': 'error',
                'message': f'Enumeration failed: {str(e)}',
                'domain': domain,
                'subdomains': list(discovered_subdomains),
                'total_found': len(discovered_subdomains),
                'scan_time': round(time.time() - start_time, 2)
            }

    def _check_subdomain(self, subdomain: str) -> bool:
        """
        Check if a subdomain resolves to an IP address.
        """
        try:
            # Try to resolve A record
            answers = self.resolver.resolve(subdomain, 'A')
            return len(answers) > 0
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return False
        except Exception:
            return False

    def _brute_force_subdomains(self, domain: str) -> Set[str]:
        """
        Perform DNS brute force enumeration using common subdomains.
        """
        discovered = set()

        def check_single_subdomain(subdomain_prefix: str) -> str:
            full_domain = f"{subdomain_prefix}.{domain}"
            if self._check_subdomain(full_domain):
                return full_domain
            return None

        # Use thread pool for parallel checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {
                executor.submit(check_single_subdomain, prefix): prefix
                for prefix in self.COMMON_SUBDOMAINS
            }

            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    discovered.add(result)

        return discovered

    def _check_certificate_transparency(self, domain: str) -> Set[str]:
        """
        Check Certificate Transparency logs for subdomains.
        This is a basic implementation - in production, you'd use CT log APIs.
        """
        discovered = set()

        # For now, just try a few common patterns
        # In a real implementation, you'd query CT logs like crt.sh
        common_prefixes = ['www', 'mail', 'ftp', 'admin', 'api', 'app', 'dev', 'staging']

        for prefix in common_prefixes:
            full_domain = f"{prefix}.{domain}"
            if self._check_subdomain(full_domain):
                discovered.add(full_domain)

        return discovered


# Global instance
subdomain_enumerator = SubdomainEnumerator()