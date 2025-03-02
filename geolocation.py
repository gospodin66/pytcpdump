from requests import get as req_get
from collections import defaultdict
import json

class GeoLocation:
    def __init__(self):
        self.ip_location_map = defaultdict(set)
        self.detected_sources = []
        self.load_detected_sources()

    def load_detected_sources(self):
        """Load detected sources from a file."""
        try:
            with open("sources.json", "r") as file:
                self.detected_sources = json.load(file)
        except FileNotFoundError:
            self.detected_sources = []

    def save_detected_sources(self):
        """Save detected sources to a file."""
        with open("sources.json", "w") as file:
            json.dump(self.detected_sources, file)

    def get_location(self, ip: str) -> tuple:
        """Get geographical location of an IP address using ip-api.com."""
        url = f"http://ip-api.com/json/{ip}"
        try:
            response = req_get(url, timeout=2).json()
            if response["status"] == "success":
                city = response.get("city", "Unknown")
                country = response.get("country", "Unknown")
                lat = response.get("lat", 0.0)
                lon = response.get("lon", 0.0)
                return city, country, lat, lon
        except Exception as e:
            print(f"Error retrieving data for {ip}: {e}")
        return None, None, None, None


    def process_ip(self, ip: str) -> None:
        """Process IP to determine location and update maps."""
        if any(ip == source['ip'] for source in self.detected_sources):
            return
        if ip not in self.ip_location_map:
            city, country, lat, lon = self.get_location(ip)
            if city and country:
                self.ip_location_map[(city, country, lat, lon)].add(ip)
                self.detected_sources.append({
                    'ip': ip,
                    'city': city,
                    'country': country,
                    'lat': lat,
                    'lon': lon
                })
                self.save_detected_sources()
                print(f"New source detected: {ip}")
                print("Current found locations:")
                for (city, country, lat, lon), ips in self.ip_location_map.items():
                    print(f"{city}, {country} ({lat}, {lon}): {', '.join(ips)}")
