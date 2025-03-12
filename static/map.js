let globe;

(() => {
    document.addEventListener("DOMContentLoaded", function() {
        if (typeof window.Globe === 'undefined') {
            console.error("Globe library is not loaded");
            return;
        }
        globe = window.Globe()
            .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
            .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
            .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
            .pointOfView({ altitude: 1.2 })
            (document.getElementById('map-container'));
        console.log("Globe initialized:", globe);
    });

    let markers = [];
    let polylines = [];
    let initialLoad = true;

    function updateMap() {
        $.getJSON('/update_map', function(data) {
            console.log("Data received from /update_map:", data);
            const newMarkers = [];
            const newPolylines = [];
            const newCityMap = {};

            const hostLocation = data.host_location;

            if (!hostLocation || !hostLocation.lat || !hostLocation.lon) {
                console.error("Invalid host location:", hostLocation);
                return;
            }

            data.sources.forEach(function(src) {
                const cityKey = src.city + ', ' + src.country;
                if (!newCityMap[cityKey]) {
                    newCityMap[cityKey] = [];
                }
                newCityMap[cityKey].push(src);
            });

            Object.keys(newCityMap).forEach(function(cityKey) {
                const cityData = newCityMap[cityKey][0];
                if (!cityData.lat || !cityData.lon) {
                    console.error(`Invalid city data for ${cityKey}:`, cityData);
                    return;
                }
                newMarkers.push({
                    lat: cityData.lat,
                    lng: cityData.lon,
                    size: 0.03,
                    color: initialLoad ? 'orange' : 'red', 
                    label: `${cityData.city}, ${cityData.country}`,
                    info: `${cityData.city}, ${cityData.country}<br><br>` +
                          newCityMap[cityKey].map(ipInfo => `IP: ${ipInfo.ip}<br>Lat: ${ipInfo.lat}<br>Lon: ${ipInfo.lon}`).join('<br><br>')
                });

                newCityMap[cityKey].forEach(function(src) {
                    if (hostLocation && (src.lat !== hostLocation.lat || src.lon !== hostLocation.lon)) {
                        if (!polylines.some(polyline => 
                            polyline.startLat === hostLocation.lat && 
                            polyline.startLng === hostLocation.lon && 
                            polyline.endLat === src.lat && 
                            polyline.endLng === src.lon
                        )) {
                            newPolylines.push({
                                startLat: hostLocation.lat,
                                startLng: hostLocation.lon,
                                endLat: src.lat,
                                endLng: src.lon,
                                color: initialLoad ? 'orange' : 'red'
                            });
                        }
                    }
                });
            });

            newMarkers.forEach(marker => {
                if (!markers.some(existingMarker => existingMarker.lat === marker.lat && existingMarker.lng === marker.lng)) {
                    markers.push(marker);
                }
            });

            newPolylines.forEach(polyline => {
                if (!polylines.some(existingPolyline => 
                    existingPolyline.startLat === polyline.startLat && 
                    existingPolyline.startLng === polyline.startLng && 
                    existingPolyline.endLat === polyline.endLat && 
                    existingPolyline.endLng === polyline.endLng)) {
                    polylines.push(polyline);
                }
            });

            console.log("Markers:", markers);
            console.log("Polylines:", polylines);

            if (globe) {
                if (markers.length > 0) {
                    globe.pointsData([...markers]) // Ensure globe is updated with new markers
                        .pointAltitude('size')
                        .pointColor('color')
                        .labelsData([...markers]) // Ensure globe is updated with new labels
                        .labelLat('lat')
                        .labelLng('lng')
                        .labelText('label')
                        .labelSize(0.5)
                        .labelColor(() => 'white');
                }

                if (polylines.length > 0) {
                    globe.arcsData([...polylines]) // Ensure globe is updated with new polylines
                        .arcStartLat('startLat')
                        .arcStartLng('startLng')
                        .arcEndLat('endLat')
                        .arcEndLng('endLng')
                        .arcColor(d => d.color)
                        .arcDashLength(1)
                        .arcDashGap(2)
                        .arcDashInitialGap(() => Math.random() * 5)
                        .arcDashAnimateTime(1000);
                }

                globe.onPointClick(marker => {
                    if (!marker || !marker.info) {
                        console.error("Marker info is undefined:", marker);
                        return;
                    }
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

                if (hostLocation && hostLocation.lat !== undefined && hostLocation.lon !== undefined) {
                    if (initialLoad) {
                        globe.pointOfView({ lat: hostLocation.lat, lng: hostLocation.lon, altitude: 1.2 }, 2000);
                        initialLoad = false;
                    }
                } else {
                    console.error("Invalid host location", hostLocation);
                }
            } else {
                console.error("Globe is not defined");
            }

        }).fail(function(jqxhr, textStatus, error) {
            console.error("Request Failed: " + textStatus + ", " + error);
        });
    }

    setInterval(updateMap, 45 * 1000); // 45 seconds
    updateMap(); // Initial load

})();