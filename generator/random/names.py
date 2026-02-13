"""
Name Generator

Generates realistic names for hosts, users, and organizations.
"""

import random
from typing import List, Optional, Tuple


class NameGenerator:
    """Generates realistic names for scenario elements."""

    # First names (common US names)
    FIRST_NAMES = [
        "James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph",
        "Thomas", "Charles", "Christopher", "Daniel", "Matthew", "Anthony", "Mark",
        "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan",
        "Jessica", "Sarah", "Karen", "Nancy", "Lisa", "Betty", "Margaret", "Sandra",
        "Emily", "Hannah", "Ashley", "Kaitlyn", "Madison", "Sophia", "Olivia", "Ava",
        "Alex", "Taylor", "Jordan", "Morgan", "Casey", "Riley", "Jamie", "Quinn",
    ]

    # Last names (common US surnames)
    LAST_NAMES = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
        "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
        "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
        "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
        "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill",
        "Flores", "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell",
    ]

    # Departments
    DEPARTMENTS = [
        "Engineering", "IT", "Finance", "HR", "Marketing", "Sales",
        "Operations", "Legal", "Support", "Research", "Security",
    ]

    # Host prefixes by role
    HOST_PREFIXES = {
        "workstation": ["WS", "PC", "DESKTOP", "LAPTOP", "WKS"],
        "domain_controller": ["DC", "ADC", "PDC"],
        "file_server": ["FS", "FILE", "NAS", "SRV-FILE"],
        "web_server": ["WEB", "WWW", "HTTP", "SRV-WEB"],
        "database_server": ["DB", "SQL", "MYSQL", "SRV-DB"],
        "mail_server": ["MAIL", "MX", "EXCH", "SMTP"],
        "backup_server": ["BACKUP", "BKP", "SRV-BKP"],
        "generic": ["SRV", "SERVER", "APP"],
    }

    # Domain suffixes
    DOMAIN_SUFFIXES = [
        "local", "corp", "internal", "lan", "ad", "domain",
    ]

    # Organization name parts
    ORG_PREFIXES = [
        "Acme", "Global", "United", "Pacific", "Atlantic", "Northern",
        "Southern", "Central", "Metro", "National", "Premier", "Elite",
        "Alpha", "Apex", "Summit", "Peak", "Vertex", "Prime",
    ]

    ORG_SUFFIXES = [
        "Industries", "Solutions", "Technologies", "Systems", "Services",
        "Group", "Corp", "Inc", "Holdings", "Partners", "Consulting",
        "Financial", "Healthcare", "Manufacturing", "Logistics", "Energy",
    ]

    # C2 domains (look legitimate)
    C2_DOMAIN_PARTS = [
        "update", "cdn", "api", "static", "content", "sync", "cloud",
        "service", "gateway", "analytics", "global", "secure", "data",
        "backup", "storage", "assets", "media", "images", "files",
    ]

    C2_TLDS = [
        "com", "net", "io", "org", "co", "tech", "cloud", "online",
    ]

    def __init__(self, seed: Optional[int] = None):
        """
        Initialize generator.

        Args:
            seed: Random seed for reproducibility
        """
        self.rng = random.Random(seed)

    def generate_username(self, style: str = "first.last") -> Tuple[str, str, str]:
        """
        Generate a username with display name.

        Args:
            style: Username style (first.last, flast, firstl)

        Returns:
            Tuple of (username, first_name, last_name)
        """
        first = self.rng.choice(self.FIRST_NAMES)
        last = self.rng.choice(self.LAST_NAMES)

        if style == "first.last":
            username = f"{first.lower()}.{last.lower()}"
        elif style == "flast":
            username = f"{first[0].lower()}{last.lower()}"
        elif style == "firstl":
            username = f"{first.lower()}{last[0].lower()}"
        else:
            username = f"{first.lower()}.{last.lower()}"

        return username, first, last

    def generate_admin_username(self) -> Tuple[str, str]:
        """
        Generate an admin username.

        Returns:
            Tuple of (username, display_name)
        """
        patterns = [
            lambda f, l: f"admin.{f.lower()}",
            lambda f, l: f"admin_{f[0].lower()}{l.lower()}",
            lambda f, l: f"{f.lower()}.admin",
            lambda f, l: f"svc_{f.lower()}",
            lambda f, l: f"adm-{f.lower()}",
        ]

        first = self.rng.choice(self.FIRST_NAMES)
        last = self.rng.choice(self.LAST_NAMES)
        pattern = self.rng.choice(patterns)

        username = pattern(first, last)
        display_name = f"{first} {last} (Admin)"

        return username, display_name

    def generate_service_account(self) -> Tuple[str, str]:
        """
        Generate a service account.

        Returns:
            Tuple of (username, description)
        """
        services = [
            ("svc_backup", "Backup Service Account"),
            ("svc_sql", "SQL Service Account"),
            ("svc_iis", "IIS Service Account"),
            ("svc_scheduler", "Task Scheduler Service"),
            ("svc_monitoring", "Monitoring Service Account"),
            ("svc_antivirus", "Antivirus Service Account"),
            ("svc_deploy", "Deployment Service Account"),
        ]

        return self.rng.choice(services)

    def generate_hostname(self, role: str = "workstation", number: int = 1) -> str:
        """
        Generate a hostname.

        Args:
            role: Host role (workstation, domain_controller, etc.)
            number: Host number for uniqueness

        Returns:
            Hostname string
        """
        prefixes = self.HOST_PREFIXES.get(role, self.HOST_PREFIXES["generic"])
        prefix = self.rng.choice(prefixes)

        # Add number padding
        num_str = str(number).zfill(2)

        return f"{prefix}{num_str}"

    def generate_domain(self) -> str:
        """
        Generate a domain name.

        Returns:
            Domain name (e.g., corp.local)
        """
        org = self.rng.choice(self.ORG_PREFIXES).lower()
        suffix = self.rng.choice(self.DOMAIN_SUFFIXES)

        return f"{org}.{suffix}"

    def generate_organization(self) -> str:
        """
        Generate an organization name.

        Returns:
            Organization name
        """
        prefix = self.rng.choice(self.ORG_PREFIXES)
        suffix = self.rng.choice(self.ORG_SUFFIXES)

        return f"{prefix} {suffix}"

    def generate_c2_domain(self) -> str:
        """
        Generate a realistic-looking C2 domain.

        Returns:
            C2 domain name
        """
        parts = self.rng.sample(self.C2_DOMAIN_PARTS, 2)
        tld = self.rng.choice(self.C2_TLDS)

        return f"{parts[0]}-{parts[1]}.{tld}"

    def generate_c2_ip(self) -> str:
        """
        Generate a C2 IP from documentation ranges.

        Returns:
            IP address from RFC 5737 ranges
        """
        # RFC 5737 documentation ranges
        ranges = [
            (192, 0, 2),      # TEST-NET-1
            (198, 51, 100),   # TEST-NET-2
            (203, 0, 113),    # TEST-NET-3
        ]

        base = self.rng.choice(ranges)
        last_octet = self.rng.randint(1, 254)

        return f"{base[0]}.{base[1]}.{base[2]}.{last_octet}"

    def generate_internal_ip(self, network: str = "10.0.0.0/24") -> str:
        """
        Generate an internal IP within a network.

        Args:
            network: CIDR notation network

        Returns:
            IP address within the network
        """
        # Simple parsing - just handle /24 networks for now
        base = network.split("/")[0]
        parts = base.split(".")
        last_octet = self.rng.randint(10, 254)

        return f"{parts[0]}.{parts[1]}.{parts[2]}.{last_octet}"

    def generate_department(self) -> str:
        """Generate a random department name."""
        return self.rng.choice(self.DEPARTMENTS)

    def generate_users(self, count: int, include_admins: int = 0) -> List[dict]:
        """
        Generate a list of users.

        Args:
            count: Number of users to generate
            include_admins: Number of admins to include

        Returns:
            List of user dictionaries
        """
        users = []
        used_usernames = set()

        # Generate regular users
        for _ in range(count - include_admins):
            username, first, last = self.generate_username()

            # Ensure unique
            while username in used_usernames:
                username, first, last = self.generate_username()

            used_usernames.add(username)

            users.append({
                "username": username,
                "display_name": f"{first} {last}",
                "groups": ["Domain Users", self.generate_department()],
                "is_admin": False,
                "email": f"{username}@corp.local",
            })

        # Generate admins
        for _ in range(include_admins):
            username, display_name = self.generate_admin_username()

            while username in used_usernames:
                username, display_name = self.generate_admin_username()

            used_usernames.add(username)

            users.append({
                "username": username,
                "display_name": display_name,
                "groups": ["Domain Users", "Domain Admins", "Administrators"],
                "is_admin": True,
                "email": f"{username}@corp.local",
            })

        return users

    def generate_hosts(self, count: int, include_dc: bool = True) -> List[dict]:
        """
        Generate a list of hosts.

        Args:
            count: Number of hosts to generate
            include_dc: Whether to include a domain controller

        Returns:
            List of host dictionaries
        """
        hosts = []
        used_names = set()
        agent_id = 1

        # Always start with a workstation
        hostname = self.generate_hostname("workstation", 1)
        used_names.add(hostname)
        hosts.append({
            "hostname": f"{hostname}.corp.local",
            "short_name": hostname,
            "ip": self.generate_internal_ip(),
            "os": "windows",
            "agent_id": str(agent_id).zfill(3),
            "agent_name": hostname,
            "role": "workstation",
            "users": [],
        })
        agent_id += 1

        # Add DC if requested
        if include_dc and count > 1:
            hostname = self.generate_hostname("domain_controller", 1)
            used_names.add(hostname)
            hosts.append({
                "hostname": f"{hostname}.corp.local",
                "short_name": hostname,
                "ip": self.generate_internal_ip(),
                "os": "windows",
                "agent_id": str(agent_id).zfill(3),
                "agent_name": hostname,
                "role": "domain_controller",
                "users": ["administrator"],
            })
            agent_id += 1

        # Fill remaining with various roles
        roles = ["file_server", "web_server", "workstation", "database_server", "generic"]
        role_counts = {r: 1 for r in roles}

        while len(hosts) < count:
            role = self.rng.choice(roles)
            role_counts[role] = role_counts.get(role, 0) + 1
            hostname = self.generate_hostname(role, role_counts[role])

            if hostname in used_names:
                continue

            used_names.add(hostname)
            hosts.append({
                "hostname": f"{hostname}.corp.local",
                "short_name": hostname,
                "ip": self.generate_internal_ip(),
                "os": "windows",
                "agent_id": str(agent_id).zfill(3),
                "agent_name": hostname,
                "role": role,
                "users": [],
            })
            agent_id += 1

        return hosts
