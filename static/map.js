const globe = Globe()
    .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
    .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
    .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
    .pointOfView({ altitude: 2.5 })
    (document.getElementById('map-container'));

let markers = [];
let polylines = [];
let cityMap = {};
let initialLoad = true;

function updateMap() {
    $.getJSON('/update_map', function(data) {
        const newMarkers = [];
        const newPolylines = [];
        const newCityMap = {};

        const hostLocation = data.host_location;

        data.sources.forEach(function(src) {
            const cityKey = src.city + ', ' + src.country;
            if (!newCityMap[cityKey]) {
                newCityMap[cityKey] = [];
            }
            newCityMap[cityKey].push(src);
        });

        Object.keys(newCityMap).forEach(function(cityKey) {
            const cityData = newCityMap[cityKey][0];
            newMarkers.push({
                lat: cityData.lat,
                lng: cityData.lon,
                size: 0.03,
                color: 'orange', 
                label: `${cityData.city}, ${cityData.country}`,
                info: `${cityData.city}, ${cityData.country}<br><br>` +
                      newCityMap[cityKey].map(ipInfo => `IP: ${ipInfo.ip}<br>Lat: ${ipInfo.lat}<br>Lon: ${ipInfo.lon}`).join('<br><br>')
            });

            newCityMap[cityKey].forEach(function(src) {
                if (hostLocation && (src.lat !== hostLocation.lat || src.lon !== hostLocation.lon)) {
                    const arcExists = polylines.some(polyline => 
                        polyline.startLat === hostLocation.lat && 
                        polyline.startLng === hostLocation.lon && 
                        polyline.endLat === src.lat && 
                        polyline.endLng === src.lon
                    );
                    if (!arcExists) {
                        newPolylines.push({
                            startLat: hostLocation.lat,
                            startLng: hostLocation.lon,
                            endLat: src.lat,
                            endLng: src.lon,
                            color: 'orange'
                        });
                    }
                }
            });
        });

        markers = markers.concat(newMarkers);
        polylines = polylines.concat(newPolylines);

        globe.pointsData(markers)
            .pointAltitude('size')
            .pointColor('color')
            .labelsData(markers)
            .labelLat('lat')
            .labelLng('lng')
            .labelText('label')
            .labelSize(0.5)
            .labelColor(() => 'white')
            .arcsData(polylines)
            .arcStartLat('startLat')
            .arcStartLng('startLng')
            .arcEndLat('endLat')
            .arcEndLng('endLng')
            .arcColor(d => d.color)
            .arcDashLength(1)
            .arcDashGap(2)
            .arcDashInitialGap(() => Math.random() * 5)
            .arcDashAnimateTime(1000)
            .onPointClick(marker => {
                const infoDiv = document.createElement('div');
                infoDiv.innerHTML = marker.info;
                infoDiv.style.position = 'absolute';
                infoDiv.style.backgroundColor = 'rgba(0, 0, 0, 0.7)';
                infoDiv.style.color = 'white';
                infoDiv.style.padding = '10px';
                infoDiv.style.borderRadius = '5px';
                infoDiv.style.top = '10px';
                infoDiv.style.left = '10px';
                document.body.appendChild(infoDiv);
                setTimeout(() => document.body.removeChild(infoDiv), 10000);
            });

        if (initialLoad && hostLocation) {
            globe.pointOfView({ lat: hostLocation.lat, lng: hostLocation.lon, altitude: 1.2 }, 2000);
            initialLoad = false;
        }
    });
}

setInterval(updateMap, 30000);
updateMap(); // Initial load
