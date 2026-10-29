"""Ryu app: consume IDS alerts and temporarily block suspicious IPv4 sources."""

import json
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

from response.policy import validate_alert


APP_INSTANCE_NAME = "ids_response_api"
DEFAULT_BLOCK_SECONDS = 60


def build_drop_match(parser, source_ip):
    """Build an OpenFlow 1.3 IPv4 source match."""
    return parser.OFPMatch(
        eth_type=0x0800,
        ipv4_src=source_ip,
    )


class IDSResponseApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(IDSResponseApp, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.block_seconds = DEFAULT_BLOCK_SECONDS
        self.blocked = {}

        wsgi = kwargs["wsgi"]
        wsgi.register(
            IDSResponseController,
            {APP_INSTANCE_NAME: self},
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Table-miss: send unknown packets to the controller.
        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]

        self._add_flow(
            datapath,
            0,
            match,
            actions,
            hard_timeout=0,
        )

        self.logger.info(
            "Registered OpenFlow switch dpid=%s",
            datapath.id,
        )

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, CONFIG_DISPATCHER],
    )
    def state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif datapath.id in self.datapaths:
            del self.datapaths[datapath.id]

    def _add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        hard_timeout=0,
        idle_timeout=0,
    ):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        instructions = []

        if actions:
            instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions,
                )
            ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout,
        )

        datapath.send_msg(mod)

    def block_source(self, source_ip, alert):
        now = time.time()
        expiry = now + self.block_seconds
        installed = 0

        for datapath in list(self.datapaths.values()):
            parser = datapath.ofproto_parser
            match = build_drop_match(parser, source_ip)

            # Empty action list means drop.
            # Higher priority than the table-miss rule.
            self._add_flow(
                datapath,
                50000,
                match,
                [],
                hard_timeout=self.block_seconds,
            )

            installed += 1

        self.blocked[source_ip] = {
            "expires_at_epoch": expiry,
            "alert_type": alert["type"],
            "severity": alert["severity"],
            "switches_updated": installed,
        }

        self.logger.warning(
            "IDS BLOCK source=%s type=%s severity=%s "
            "switches=%d duration=%ds",
            source_ip,
            alert["type"],
            alert["severity"],
            installed,
            self.block_seconds,
        )

        return installed


class IDSResponseController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(IDSResponseController, self).__init__(
            req, link, data, **config
        )
        self.app = data[APP_INSTANCE_NAME]

    @route("ids_alert", "/ids/alert", methods=["POST"])
    def ids_alert(self, req, **kwargs):
        try:
            payload = req.json
            alert = validate_alert(payload)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            error_result = {
                "ok": False,
                "error": str(exc),
            }

            return Response(
                status=400,
                content_type="application/json",
                charset="utf-8",
                body=json.dumps(error_result),
            )

        count = self.app.block_source(
            alert["source_ip"],
            alert,
        )

        result = {
            "ok": True,
            "action": "temporary_block",
            "source_ip": alert["source_ip"],
            "duration_seconds": self.app.block_seconds,
            "switches_updated": count,
            "alert_type": alert["type"],
        }

        return Response(
            status=200,
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result),
        )

    @route("ids_status", "/ids/status", methods=["GET"])
    def ids_status(self, req, **kwargs):
        result = {
            "ok": True,
            "connected_switches": len(self.app.datapaths),
            "block_duration_seconds": self.app.block_seconds,
            "blocked_sources": self.app.blocked,
        }

        return Response(
            status=200,
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result),
        )
