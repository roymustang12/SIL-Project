#!/usr/bin/env python3
"""Insecure baseline controller for A/B comparison.

This controller intentionally trusts any LLDP topology update and uses it for
inter-switch forwarding decisions. It has no LLDP authentication and no
host/switch port validation, so forged LLDP can poison forwarding.
"""

from __future__ import annotations

from collections import defaultdict
import os
import struct
from typing import Dict, Optional, Set, Tuple

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, packet
from ryu.lib.packet import ether_types
from ryu.ofproto import ofproto_v1_3


class InsecureBaselineRyu(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    LLDP_DST_MAC = "01:80:c2:00:00:0e"
    LLDP_INTERVAL = 600
    TLV_REMOTE_DPID_TYPE = 127
    TLV_CONTROLLER_TYPE = 0x0C
    TLV_DIRECTION_TYPE = 0x73

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths: Dict[int, object] = {}
        self.switch_port_desc: Dict[int, Dict[int, object]] = defaultdict(dict)

        # Host and L2 learning state.
        self.mac_to_port: Dict[int, Dict[str, int]] = defaultdict(dict)
        self.host_location: Dict[str, Tuple[int, int]] = {}

        # Topology from LLDP (INSECURE): (src_switch, dst_switch) -> src_out_port
        self.links_out: Dict[Tuple[int, int], int] = {}
        # Local ports considered switch-to-switch by LLDP observations.
        self.link_local_ports: Dict[int, Set[int]] = defaultdict(set)

        self.controller_tlv = os.urandom(8)
        self.lldp_thread = hub.spawn(self._lldp_loop)

        self.logger.info("Insecure baseline controller initialized")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self._install_table_miss(datapath)
        self._request_port_desc(datapath)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self._request_port_desc(datapath)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self.switch_port_desc.pop(datapath.id, None)

    def _install_table_miss(self, datapath) -> None:
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

    def _add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def _request_port_desc(self, datapath) -> None:
        req = datapath.ofproto_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    def _flush_switch_flows(self) -> None:
        # Recompute forwarding from fresh packet-ins after topology changes.
        for datapath in list(self.datapaths.values()):
            parser = datapath.ofproto_parser
            ofp = datapath.ofproto
            delete = parser.OFPFlowMod(
                datapath=datapath,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                match=parser.OFPMatch(),
            )
            datapath.send_msg(delete)
            self._install_table_miss(datapath)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_reply_handler(self, ev):
        datapath = ev.msg.datapath
        for desc in ev.msg.body:
            if self._is_reserved_port(datapath, desc.port_no):
                continue
            self.switch_port_desc[datapath.id][desc.port_no] = desc
            if self._is_port_live(datapath, desc):
                self._send_lldp(datapath, desc.port_no, desc.hw_addr)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        datapath = ev.msg.datapath
        desc = ev.msg.desc
        if self._is_reserved_port(datapath, desc.port_no):
            return
        self.switch_port_desc[datapath.id][desc.port_no] = desc

    def _is_reserved_port(self, datapath, port_no: int) -> bool:
        return port_no >= datapath.ofproto.OFPP_MAX

    def _is_port_live(self, datapath, desc) -> bool:
        ofp = datapath.ofproto
        is_down = bool(desc.state & ofp.OFPPS_LINK_DOWN) or bool(desc.config & ofp.OFPPC_PORT_DOWN)
        return not is_down

    # ---------- LLDP (insecure) ----------

    def _lldp_loop(self):
        while True:
            for dpid, datapath in list(self.datapaths.items()):
                for port_no, desc in list(self.switch_port_desc.get(dpid, {}).items()):
                    if self._is_reserved_port(datapath, port_no):
                        continue
                    if not self._is_port_live(datapath, desc):
                        continue
                    self._send_lldp(datapath, port_no, desc.hw_addr)
            hub.sleep(self.LLDP_INTERVAL)

    def _send_lldp(self, datapath, port_no: int, src_mac: str) -> None:
        data = self._build_lldp_frame(datapath.id, port_no, src_mac)
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(port_no)],
            data=data,
        )
        datapath.send_msg(out)

    def _build_lldp_frame(self, dpid: int, port_no: int, src_mac: str) -> bytes:
        dpid_bytes = dpid.to_bytes(8, byteorder="big")
        chassis_value = bytes([4]) + dpid_bytes[2:8]
        port_value = bytes([2]) + port_no.to_bytes(2, byteorder="big", signed=False)
        ttl_value = struct.pack("!H", 120)
        remote_dpid_value = b"\x00\x26\xe1\x00" + dpid_bytes

        payload = b"".join(
            [
                self._build_tlv(1, chassis_value),
                self._build_tlv(2, port_value),
                self._build_tlv(3, ttl_value),
                self._build_tlv(self.TLV_REMOTE_DPID_TYPE, remote_dpid_value),
                self._build_tlv(self.TLV_CONTROLLER_TYPE, self.controller_tlv),
                self._build_tlv(self.TLV_DIRECTION_TYPE, b"\x01"),
                b"\x00\x00",
            ]
        )

        return self._mac_to_bytes(self.LLDP_DST_MAC) + self._mac_to_bytes(src_mac) + struct.pack(
            "!H", ether_types.ETH_TYPE_LLDP
        ) + payload

    @staticmethod
    def _build_tlv(tlv_type: int, value: bytes) -> bytes:
        header = ((tlv_type & 0x7F) << 9) | (len(value) & 0x1FF)
        return struct.pack("!H", header) + value

    def _parse_lldp(self, frame: bytes) -> Optional[Tuple[int, int]]:
        if len(frame) < 14:
            return None
        if struct.unpack("!H", frame[12:14])[0] != ether_types.ETH_TYPE_LLDP:
            return None

        payload = frame[14:]
        idx = 0
        remote_dpid = None
        remote_port = None

        while idx + 2 <= len(payload):
            header = struct.unpack_from("!H", payload, idx)[0]
            idx += 2
            tlv_type = header >> 9
            tlv_len = header & 0x1FF
            if tlv_type == 0:
                break
            if idx + tlv_len > len(payload):
                return None
            value = payload[idx : idx + tlv_len]
            idx += tlv_len

            if tlv_type == 2 and tlv_len == 3 and value[0] == 2:
                remote_port = struct.unpack("!H", value[1:3])[0]
            elif tlv_type == self.TLV_REMOTE_DPID_TYPE and tlv_len == 12 and value[0:4] == b"\x00\x26\xe1\x00":
                remote_dpid = struct.unpack("!Q", value[4:12])[0]

        if remote_dpid is None or remote_port is None:
            return None
        return remote_dpid, remote_port

    # ---------- Packet-in ----------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto

        in_port = msg.match.get("in_port")
        if in_port is None:
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # INSECURE: trust any LLDP and update topology links.
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            parsed = self._parse_lldp(msg.data)
            if parsed is not None:
                remote_dpid, remote_port = parsed
                link_key = (remote_dpid, datapath.id)
                prev_out_port = self.links_out.get(link_key)
                was_switch_port = in_port in self.link_local_ports[datapath.id]

                self.links_out[link_key] = remote_port
                self.link_local_ports[datapath.id].add(in_port)

                if prev_out_port != remote_port or not was_switch_port:
                    self._flush_switch_flows()

                self.logger.warning(
                    "[INSECURE] Learned link %s:%s -> %s:%s from LLDP packet-in on local port %s",
                    remote_dpid,
                    remote_port,
                    datapath.id,
                    in_port,
                    in_port,
                )
            return

        src = eth.src.lower()
        dst = eth.dst.lower()

        # Learn host location only on ports not marked as inter-switch links.
        if in_port not in self.link_local_ports.get(datapath.id, set()):
            self.mac_to_port[datapath.id][src] = in_port
            self.host_location[src] = (datapath.id, in_port)

        out_port = self._resolve_out_port(datapath.id, in_port, dst)
        if out_port is None:
            return
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            self._add_flow(datapath, 10, match, actions)

        data = None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def _resolve_out_port(self, src_dpid: int, in_port: int, dst_mac: str) -> Optional[int]:
        # Unknown destination: flood.
        if dst_mac not in self.host_location:
            return self.datapaths[src_dpid].ofproto.OFPP_FLOOD

        dst_dpid, dst_port = self.host_location[dst_mac]

        # Same switch destination.
        if dst_dpid == src_dpid:
            return dst_port

        # Inter-switch forwarding via LLDP-discovered links.
        out_port = self.links_out.get((src_dpid, dst_dpid))
        if out_port is None:
            return self.datapaths[src_dpid].ofproto.OFPP_FLOOD

        # Naive behavior: drop self-looping next-hop decisions.
        if out_port == in_port:
            return None

        return out_port

    @staticmethod
    def _mac_to_bytes(mac_str) -> bytes:
        if isinstance(mac_str, bytes):
            return mac_str
        return bytes(int(part, 16) for part in mac_str.split(":"))
