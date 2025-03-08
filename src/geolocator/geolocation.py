from requests import get as req_get
from collections import defaultdict
import json
import ipaddress
import platform

if platform.system() == "Windows":
    from src.database.database import Database
else:
    from database.database import Database

class GeoLocation:
    def __init__(self):
        self.sources_file = "sources.json"
        self.ip_location_map = defaultdict(set)
        self.detected_sources = []
        self.load_detected_sources()
        self.api_url = "https://ipinfo.io/"
        self.db = Database()

    def load_detected_sources(self):
        """Load detected sources from a file."""
        try:
            with open(self.sources_file, "r") as file:
                self.detected_sources = json.load(file)
        except FileNotFoundError:
            self.detected_sources = []

    def save_locations(self):
        """Save detected sources to a file."""
        with open(self.sources_file, "w") as file:
            json.dump(self.detected_sources, file, indent=4)

    def is_private_ip(self, ip: str) -> bool:
        """Check if the IP address is a local network address or broadcast address."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or \
                    ip_obj.is_loopback or \
                    ip_obj.is_multicast or \
                    ip == "255.255.255.255" or \
                    ip == "0.0.0.0"
        except ValueError:
            return False
    
    def get_location(self, ip: str) -> dict:
        """Get geographical location of an IP address using ipinfo.io."""
        ret_err = {
            "ip": ip,
            "city": None,
            "country": None,
            "lat": None,
            "lon": None
        }
        for dst in self.detected_sources:
            if dst['ip'] == ip:
                return dst
            
        if self.is_private_ip(ip):
            return ret_err

        url = f"{self.api_url}{ip}/json"
        try:
            response = req_get(url, timeout=2).json()
            if response and "loc" in response:
                loc = response.get("loc", "0.0,0.0").split(',')
                location = {
                    "ip": ip,
                    "city": response.get("city", "Unknown"),
                    "country": response.get("country", "Unknown"),
                    "lat": float(loc[0]),
                    "lon": float(loc[1])
                }
                self.detected_sources.append(location)
                self.save_locations()
                return location
        except Exception as e:
            print(f"Error retrieving data for {ip}: {e}")
        return ret_err

    def process_ips(self, src_ip: str, dst_ip: str) -> None:
        """Process source and destination IPs to determine location and update maps."""
        if any(dst_ip == dst['ip'] for dst in self.detected_sources):
            return

        if dst_ip not in self.ip_location_map:
            location = self.get_location(dst_ip)

            if location["city"] and location["country"]:
                self.ip_location_map[(
                    location["city"], 
                    location["country"], 
                    location["lat"], 
                    location["lon"]
                )].add(dst_ip)

                print(f"New source located: {dst_ip} in {location['city']}, {location['country']}")
                self.db.populate_connections(src_ip, dst_ip)


