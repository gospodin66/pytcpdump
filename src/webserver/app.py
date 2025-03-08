from flask import Flask, render_template_string, jsonify, send_from_directory
import json

import requests

import platform

if platform.system() == "Windows":
    from src.geolocator.geolocation import GeoLocation
    from src.database.database import Database
else:
    from geolocator.geolocation import GeoLocation
    from database.database import Database

app = Flask(__name__, static_folder='../../static')

with open('../../static/index.html', 'r') as file:
    HTML_TEMPLATE = file.read()

def get_host_ip():
    try:
        response = requests.get('https://checkip.amazonaws.com')
        response.raise_for_status()
        return response.text.strip()
    except requests.RequestException as e:
        print(f"Error retrieving host IP: {e}")
        return '127.0.0.1'
    
HOST_IP = get_host_ip()

db = Database()
db.insert_current_host_as_source(HOST_IP, 'Unknown', 'Unknown', 0.0, 0.0)
db.close()

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

@app.route('/update_map')
def update_map():
    with open('../sources.json', 'r') as file:
        sources = json.load(file)
    
    geo_location = GeoLocation()
    host_location = geo_location.get_location(HOST_IP)
    
    return jsonify({
        "status": "success", 
        "sources": sources, 
        "host_location": host_location
    })

@app.route('/add_dest', methods=['POST', 'GET'])
def populate_destinations():
    db = Database()
    db.insert_destinations_from_file('sources.json', HOST_IP)
    return jsonify({
            "status": "success", 
            "message": "Database successfully populated with new sources."
        })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
