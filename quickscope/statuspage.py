import json.decoder
from typing import Tuple, Dict, List
import html
from collections import defaultdict
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json
import logging
import math
import nclib


logger = logging.getLogger(__name__)

STATUS_HTML = """<!DOCTYPE html>
<html lang="en-US">
<head>
    <title>Shooter Status</title>
    <script>
        var current_tick = null;
        var current_service = 1;
        function showTickService(tick, service) {
            current_tick = tick;
            current_service = service;

            var cards = document.getElementsByClassName("card");
            for (var i = 0; i < cards.length; i++) {
                var card = cards[i];
                var card_tick = parseInt(card.dataset.tick);
                var card_service = card.dataset.service;
                if (card.dataset.role === "get") {
                    if (card_tick === tick && card_service === service) {
                        card.style.display = '';
                    } else {
                        card.style.display = 'none';
                    }
                } else if (card.dataset.role === "set-service") {
                    if (card_tick === tick) {
                        card.style.display = '';
                    } else {
                        card.style.display = 'none';
                    }

                    if (card_service === service) {
                        card.classList.add("selected")
                    } else {
                        card.classList.remove("selected")
                    }
                } else if (card.dataset.role === "set-tick") {
                    if (card_tick === tick) {
                        card.classList.add("selected")
                    } else {
                        card.classList.remove("selected")
                    }
                }
            }
        }

        window.onload = function () {
            var cards = document.getElementsByClassName("card");
            var last = null;
            var second_last = null;
            for (var i = 0; i < cards.length; i++) {
                var card = cards[i];
                if (card.dataset.role === "set-tick") {
                    let card_tick = parseInt(card.dataset.tick);
                    second_last = last;
                    last = card_tick;
                    card.onclick = function () {
                        console.log("tick", card_tick);
                        showTickService(card_tick, "ALL");
                    };
                } else if (card.dataset.role == "set-service") {
                    let card_service = card.dataset.service;
                    card.onclick = function () {
                        console.log("service", card_service);
                        if (current_service == card_service) {
                            showTickService(current_tick, "ALL");
                        } else {
                            showTickService(current_tick, card_service);
                        }
                    };
                }
            }
            if (second_last !== null) {
                showTickService(second_last, "ALL");
            } else if (last !== null) {
                showTickService(last, "ALL");
            }
        };
    </script>
    <style>
        html {
            background-color: #222222;
            color: white;
        }
        
        #title {
            font-size: 40px;
        }
        
        .card {
            display: inline-block;
            text-align: center;
            background-color: #222228;
            border-width: 1px;
            border-color: #666;
            border-style: solid;
            margin: 5px;
            padding-top: 10px;
        }
        
        .card.selected {
            border-color: orange;
        }
        
        .card-title {
            font-weight: bold;
        }
        
        .card.selectable:hover {
            background-color: #333336;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div id="title">Shooter Status</div>
    <div id="progress">
        %(progress)s
    </div>
    <div id="services">
        %(services)s
    </div>
    <div id="teams">
        %(teams)s
    </div>
    <div id="title">Error Log</div>
    <div id="errorlog">
        <pre><code>%(errorlog)s</code></pre>
    </div>
</body>
</html>
"""

CARD_HTML = """
<div class="card" data-tick="%(tick)s" data-service="%(service)s" data-role="%(role)s">
    <div class="card-title">%(title)s</div>
    %(chart)s
</div>
"""

from .common import ShooterStatus, ScriptStatus

@dataclass_json
@dataclass
class FlagsReport:
    total_flags: int = 0
    got_flags: int = 0

@dataclass_json
@dataclass
class TickReport:
    expected_shots: int = 0
    total_shots: int = 0
    flags_by_service: Dict[str, FlagsReport] = field(default_factory=lambda: defaultdict(FlagsReport))
    flags_by_team: Dict[str, FlagsReport] = field(default_factory=lambda: defaultdict(FlagsReport))
    flags_by_team_service: Dict[Tuple[str, str], FlagsReport] = field(default_factory=lambda: defaultdict(FlagsReport))

def statuspage(server, outfile):
    sock = nclib.Netcat(server)
    sock.sendln(b'getstatus')
    recved = sock.recvall()
    try:
        dicts = json.loads(recved.decode())
        data: ShooterStatus = ShooterStatus.from_dict(dicts)
    except json.decoder.JSONDecodeError:
        logger.exception('JSON decode error for status: %s', recved)
        return

    sock.close()

    scripts_by_service: defaultdict[str, List[Tuple[str, ScriptStatus]]] = defaultdict(list)
    for script_hash, script_info in data.script_info.items():
        scripts_by_service[script_info.service_name].append((script_hash, script_info))

    ticks: Dict[int, TickReport] = defaultdict(TickReport)
    for target, status in data.targets.items():
        report = ticks[status.tick_first_seen]
        # how many shots can we expect to be made because of this target?
        # how many scripts for this service are active during this tick?
        for script_hash, script_info in scripts_by_service[target.service.name]:
            if status.tick_first_seen <= script_info.tick_first_seen <= status.tick_last_seen or \
                    script_info.tick_first_seen <= status.tick_first_seen <= script_info.tick_last_seen:
                report.expected_shots += data.retry_timeout
                if status.retired:
                    report.total_shots += data.retry_timeout
                else:
                    try:
                        report.total_shots += status.script_status[script_hash].runs
                    except KeyError:
                        pass

        report.flags_by_team[target.team.name].total_flags += 1
        report.flags_by_team_service[(target.team.name, target.service.name)].total_flags += 1
        report.flags_by_service[target.service.name].total_flags += 1
        if status.retired:
            report.flags_by_team[target.team.name].got_flags += 1
            report.flags_by_team_service[(target.team.name, target.service.name)].got_flags += 1
            report.flags_by_service[target.service.name].got_flags += 1

    ticks_html = '\n'.join(CARD_HTML % dict(
        title=f'Tick {tick}',
        chart=build_pie([max(0, ticks[tick].expected_shots - ticks[tick].total_shots), ticks[tick].total_shots], ['yellow', 'blue']),
        tick=tick,
        service=0,
        role="set-tick",
    ) for tick in sorted(ticks))
    services_html = '\n'.join(CARD_HTML % dict(
        title=f'{html.escape(service)}',
        chart=build_pie([max(0, report.total_flags - report.got_flags), report.got_flags], ['red', 'green']),
        tick=tick,
        service=service,
        role="set-service",
    ) for tick, tick_data in ticks.items() for service, report in tick_data.flags_by_service.items()) + '\n'
    teams_html = '\n'.join(CARD_HTML % dict(
        title=f'{html.escape(team)} - {report.got_flags}/{report.total_flags}',
        chart=build_pie([max(0, report.total_flags - report.got_flags), report.got_flags], ['red', 'green']),
        tick=tick,
        service=service,
        role="get",
    ) for tick, tick_data in ticks.items() for (team, service), report in tick_data.flags_by_team_service.items()) + '\n'
    teams_html += '\n'.join(CARD_HTML % dict(
        title=f'{html.escape(team)} - {report.got_flags}/{report.total_flags}',
        chart=build_pie([max(0, report.total_flags - report.got_flags), report.got_flags], ['red', 'green']),
        tick=tick,
        service="ALL",
        role="get",
    ) for tick, tick_data in ticks.items() for team, report in tick_data.flags_by_team.items()) + '\n'

    with open(outfile, 'w', encoding='utf-8') as fp:
        fp.write(STATUS_HTML % dict(progress=ticks_html, services=services_html, teams=teams_html,
                                    errorlog=data.error_log))

def endpoint(pAngleInRadians, pRadius, pCentreOffsetX, pCentreOffsetY):
    """
    Calculate position of point on circle given an angle, a radius, and the location of the center of the circle
    Zero line points west.
    """
    lCosAngle = math.cos(pAngleInRadians)
    lSinAngle = math.sin(pAngleInRadians)
    lStartLineDestinationX =  pCentreOffsetX - (pRadius * lCosAngle)  # originally said lRadius
    lStartLineDestinationY =  pCentreOffsetY - (pRadius * lSinAngle)

    return (lStartLineDestinationX, lStartLineDestinationY)

# https://drumcoder.co.uk/blog/2010/nov/16/python-code-generate-svg-pie-chart/
def build_pie(slices, colors):
    if sum(slices) == 0:
        slices = [1]
        colors = ['white']

    OFFSET_X = 75
    OFFSET_Y = 75
    RADIUS = 65
    INNER_RADIUS = 30
    DEGREES_IN_CIRCLE = 360.0

    current_angle = 0
    total = sum(slices)
    path_elem = ""

    for gradient, slice in zip(colors, slices):
        degrees = (DEGREES_IN_CIRCLE / total) * slice

        if degrees <= 0:
            pass
        else:
            route = 0
            if degrees > 180:
                route = 1
            if degrees >= 360:
                degrees = 359.99

            start_inner_x, start_inner_y = endpoint(current_angle, INNER_RADIUS, OFFSET_X, OFFSET_Y)
            start_outer_x, start_outer_y = endpoint(current_angle, RADIUS, OFFSET_X, OFFSET_Y)
            radians = math.radians(degrees)
            current_angle += radians
            end_inner_x, end_inner_y = endpoint(current_angle, INNER_RADIUS, OFFSET_X, OFFSET_Y)
            end_outer_x, end_outer_y = endpoint(current_angle, RADIUS, OFFSET_X, OFFSET_Y)

            line_1 = "M%f,%f L%f,%f" % (start_inner_x, start_inner_y, start_outer_x, start_outer_y)
            arc_1 = "A%d,%d 0 %d,1 %f %f" % (RADIUS, RADIUS, route, end_outer_x, end_outer_y)
            line_2 = "L%f,%f" % (end_inner_x, end_inner_y)
            arc_2 = "A%d,%d 0 %d,0 %f %f" % (INNER_RADIUS, INNER_RADIUS, route, start_inner_x, start_inner_y)

            path = "%s %s %s %s Z" % (line_1, arc_1, line_2, arc_2)
            path_elem += "<path d='%s' style='fill:url(#%s);'/>" % (path, gradient)

    svg = """
    <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="150" height="150">
      <defs>
        <radialGradient id="green" r="65%%" cx="0" cy="0" spreadMethod="pad" gradientUnits="userSpaceOnUse">
          <stop offset="0%%"   stop-color="#00ee00" stop-opacity="1"/>
          <stop offset="100%%" stop-color="#006600" stop-opacity="1" />
        </radialGradient>
        <radialGradient id="red" r="65%%" cx="0" cy="0" spreadMethod="pad" gradientUnits="userSpaceOnUse">
          <stop offset="0%%"   stop-color="#ff0000" stop-opacity="1"/>
          <stop offset="100%%" stop-color="#880000" stop-opacity="1" />
        </radialGradient>
        <radialGradient id="yellow" r="65%%" cx="0" cy="0" spreadMethod="pad" gradientUnits="userSpaceOnUse">
          <stop offset="0%%"   stop-color="#ffcc00" stop-opacity="1"/>
          <stop offset="100%%" stop-color="#886600" stop-opacity="1" />
        </radialGradient>
        <radialGradient id="blue" r="65%%" cx="0" cy="0" spreadMethod="pad" gradientUnits="userSpaceOnUse">
          <stop offset="0%%"   stop-color="#55aaff" stop-opacity="1"/>
          <stop offset="100%%" stop-color="#0022cc" stop-opacity="1" />
        </radialGradient>
        <radialGradient id="blue" r="65%%" cx="0" cy="0" spreadMethod="pad" gradientUnits="userSpaceOnUse">
          <stop offset="0%%"   stop-color="#ffffff" stop-opacity="1"/>
          <stop offset="100%%" stop-color="#aaaaaa" stop-opacity="1" />
        </radialGradient>
      </defs>

      %s
    </svg>
    """ % (path_elem,)

    return svg
