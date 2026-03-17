"""Ryu implementation of TopoGuard-style topology update security.

This app ports the key behavior from the Floodlight TopoGuard prototype:
- Port role tracking (ANY / HOST / SWITCH)
- Host move checks with optional liveness probing on old location
- LLDP forgery defense via controller-generated HMAC TLV verification

The app also includes basic L2 learning-switch forwarding so it can run as a
standalone controller with Mininet.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
import hmac
import hashlib
import os
import struct
from typing import Dict, List, Optional

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, icmp, ipv4, packet
from ryu.lib.packet import ether_types
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_3


class DeviceType(Enum):
    SWITCH = "switch"
    HOST = "host"
    ANY = "any"


@dataclass(frozen=True)
class PortKey:
    dpid: int
    port: int


@dataclass
class HostEntity:
    mac: str
    ip: str


@dataclass
class PortProperty:
    device_type: DeviceType = DeviceType.ANY
    hosts: Dict[str, bool] = field(default_factory=dict)

    def set_port_host(self) -> None:
        self.device_type = DeviceType.HOST

    def set_port_switch(self) -> None:
        self.device_type = DeviceType.SWITCH

    def set_port_any(self) -> None:
        self.device_type = DeviceType.ANY

    def add_host(self, mac: str) -> None:
        self.hosts[mac] = False

    def enable_host_shutdown(self, mac: str) -> None:
        self.hosts[mac] = True

    def disable_host_shutdown(self, mac: str) -> None:
        self.hosts[mac] = False

    def receive_port_shutdown(self) -> None:
        self.hosts.clear()
        self.set_port_any()

    def receive_port_down(self) -> None:
        for mac in list(self.hosts.keys()):
            self.hosts[mac] = True


class TopoGuardRyu(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # TopoGuard defaults used in the Floodlight prototype.
    CONTROLLER_IP = "10.0.1.100"
    PROBE_SRC_MAC = "aa:aa:aa:aa:aa:aa"
    LLDP_DST_MAC = "01:80:c2:00:00:0e"
    LLDP_INTERVAL = 2

    TLV_DIRECTION_TYPE = 0x73
    TLV_DIRECTION_FORWARD = b"\x01"
    TLV_REMOTE_DPID_TYPE = 127
    TLV_CONTROLLER_TYPE = 0x0C
    TLV_MAC_TYPE = 0x0D

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths: Dict[int, object] = {}
        self.mac_to_port: Dict[int, Dict[str, int]] = defaultdict(dict)

        # TopoGuard state.
        self.port_state: Dict[PortKey, PortProperty] = {}
        self.switch_port_desc: Dict[int, Dict[int, object]] = defaultdict(dict)
        self.topoguard_mac_port: Dict[str, PortKey] = {}
        self.probed_ports: Dict[PortKey, List[HostEntity]] = defaultdict(list)

        # LLDP-HMAC state.
        self.controller_tlv = os.urandom(8)
        self.hmac_key = os.urandom(32)
        self.mac_map: Dict[int, Dict[int, bytes]] = defaultdict(dict)

        self.lldp_thread = hub.spawn(self._lldp_loop)
        self.logger.info("TopoGuard Ryu app initialized")

    # ---------- OpenFlow lifecycle ----------

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

            stale_keys = [pk for pk in self.port_state if pk.dpid == datapath.id]
            for pk in stale_keys:
                self.port_state.pop(pk, None)

    def _install_table_miss(self, datapath) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
            )
        datapath.send_msg(mod)

    def _request_port_desc(self, datapath) -> None:
        parser = datapath.ofproto_parser
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    def _flush_switch_flows(self) -> None:
        # Recompute forwarding from fresh packet-ins after valid topology updates.
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
            self.port_state.setdefault(PortKey(datapath.id, desc.port_no), PortProperty())
            # Send LLDP immediately at discovery time to classify switch-to-switch
            # ports before regular host traffic can trigger false host-move alerts.
            if self._is_port_live(datapath, desc):
                self._send_lldp(datapath, desc.port_no, desc.hw_addr)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        desc = msg.desc

        if self._is_reserved_port(datapath, desc.port_no):
            return

        pk = PortKey(datapath.id, desc.port_no)

        if msg.reason == datapath.ofproto.OFPPR_DELETE:
            self._handle_port_down(pk)
            self.switch_port_desc[datapath.id].pop(desc.port_no, None)
            return

        self.switch_port_desc[datapath.id][desc.port_no] = desc
        self.port_state.setdefault(pk, PortProperty())

        if not self._is_port_live(datapath, desc):
            self._handle_port_down(pk)

    def _is_reserved_port(self, datapath, port_no: int) -> bool:
        return port_no >= datapath.ofproto.OFPP_MAX

    def _is_port_live(self, datapath, desc) -> bool:
        ofp = datapath.ofproto
        is_down = bool(desc.state & ofp.OFPPS_LINK_DOWN) or bool(desc.config & ofp.OFPPC_PORT_DOWN)
        return not is_down

    def _handle_port_down(self, pk: PortKey) -> None:
        pp = self.port_state.setdefault(pk, PortProperty())
        pp.receive_port_down()

    def _reclassify_as_switch_port(self, pk: PortKey, pp: PortProperty) -> None:
        # Drop any host bindings that were learned on this port before it was
        # identified as a trunk/switch port.
        stale_macs = [mac for mac, loc in self.topoguard_mac_port.items() if loc == pk]
        for mac in stale_macs:
            self.topoguard_mac_port.pop(mac, None)
        pp.hosts.clear()
        pp.set_port_switch()

    # ---------- LLDP + HMAC ----------

    def _lldp_loop(self):
        while True:
            for dpid, datapath in list(self.datapaths.items()):
                descs = self.switch_port_desc.get(dpid, {})
                for port_no, desc in list(descs.items()):
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

        actions = [parser.OFPActionOutput(port_no)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def _build_lldp_frame(self, dpid: int, port_no: int, src_mac: str) -> bytes:
        dpid_bytes = dpid.to_bytes(8, byteorder="big")

        chassis_value = bytes([4]) + dpid_bytes[2:8]
        port_value = bytes([2]) + port_no.to_bytes(2, byteorder="big", signed=False)
        ttl_value = struct.pack("!H", 0x0078)
        remote_dpid_value = b"\x00\x26\xe1\x00" + dpid_bytes
        mac_tlv_value = self._generate_mac_tlv_value(dpid, port_no)

        payload = b"".join(
            [
                self._build_tlv(1, chassis_value),
                self._build_tlv(2, port_value),
                self._build_tlv(3, ttl_value),
                self._build_tlv(self.TLV_REMOTE_DPID_TYPE, remote_dpid_value),
                self._build_tlv(self.TLV_CONTROLLER_TYPE, self.controller_tlv),
                self._build_tlv(self.TLV_DIRECTION_TYPE, self.TLV_DIRECTION_FORWARD),
                self._build_tlv(self.TLV_MAC_TYPE, mac_tlv_value),
                b"\x00\x00",  # End TLV
            ]
        )

        dst = self._mac_to_bytes(self.LLDP_DST_MAC)
        src = self._mac_to_bytes(src_mac)
        ether_header = dst + src + struct.pack("!H", ether_types.ETH_TYPE_LLDP)
        return ether_header + payload

    def _build_tlv(self, tlv_type: int, value: bytes) -> bytes:
        header = ((tlv_type & 0x7F) << 9) | (len(value) & 0x1FF)
        return struct.pack("!H", header) + value

    def _generate_mac_tlv_value(self, dpid: int, port_no: int) -> bytes:
        existing = self.mac_map.get(dpid, {}).get(port_no)
        if existing is not None:
            return existing

        msg = f"{dpid}{port_no}".encode("utf-8")
        digest = hmac.new(self.hmac_key, msg, hashlib.sha256).digest()
        self.mac_map[dpid][port_no] = digest
        return digest

    def _parse_lldp_fields(self, frame: bytes) -> Optional[dict]:
        if len(frame) < 14:
            return None

        eth_type = struct.unpack("!H", frame[12:14])[0]
        if eth_type != ether_types.ETH_TYPE_LLDP:
            return None

        payload = frame[14:]
        idx = 0

        remote_port = None
        remote_dpid = None
        controller_id = None
        mac_tlv = None

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
            elif (
                tlv_type == self.TLV_REMOTE_DPID_TYPE
                and tlv_len == 12
                and value[0:4] == b"\x00\x26\xe1\x00"
            ):
                remote_dpid = struct.unpack("!Q", value[4:12])[0]
            elif tlv_type == self.TLV_CONTROLLER_TYPE and tlv_len == 8:
                controller_id = value
            elif tlv_type == self.TLV_MAC_TYPE:
                mac_tlv = value

        return {
            "remote_port": remote_port,
            "remote_dpid": remote_dpid,
            "controller_id": controller_id,
            "mac_tlv": mac_tlv,
        }

    def _verify_lldp(self, frame: bytes) -> bool:
        fields = self._parse_lldp_fields(frame)
        if not fields:
            self.logger.warning("Violation: malformed LLDP frame")
            return False

        if fields["mac_tlv"] is None:
            self.logger.warning("Violation: receive falsified LLDP (missing MAC TLV)")
            return False

        remote_dpid = fields["remote_dpid"]
        remote_port = fields["remote_port"]
        if remote_dpid is None or remote_port is None:
            return False
        if remote_dpid not in self.datapaths:
            return False

        if fields["controller_id"] != self.controller_tlv:
            # Not generated by this controller instance.
            return False

        expected = self._generate_mac_tlv_value(remote_dpid, remote_port)
        if not hmac.compare_digest(expected, fields["mac_tlv"]):
            self.logger.warning("Violation: receive falsified LLDP (MAC mismatch)")
            return False

        return True

    # ---------- Packet processing ----------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match.get("in_port")
        if in_port is None:
            return

        pk = PortKey(datapath.id, in_port)
        pp = self.port_state.setdefault(pk, PortProperty())

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        src_mac = eth.src.lower()
        dst_mac = eth.dst.lower()

        # LLDP is treated as topology-security traffic; never feed it to L2 forwarding.
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            verified = self._verify_lldp(msg.data)
            if verified:
                was_switch_port = pp.device_type == DeviceType.SWITCH
                self._reclassify_as_switch_port(pk, pp)
                if not was_switch_port:
                    self._flush_switch_flows()
            elif pp.device_type == DeviceType.HOST:
                self.logger.warning(
                    "Violation: Receive LLDP packet from HOST port: sw=%s port=%s",
                    datapath.id,
                    in_port,
                )
            return

        # Floodlight code ignores broadcast for probing logic.
        if not self._is_broadcast(dst_mac):
            if self._handle_probe_reply(pkt, pk, src_mac):
                return

        self._handle_host_traffic(pkt, pk, src_mac, pp)

        # Basic L2 forwarding (standalone mode).
        dpid = datapath.id
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self._add_flow(datapath, 10, match, actions, msg.buffer_id)
                return
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

    def _is_broadcast(self, mac_addr: str) -> bool:
        return mac_addr == "ff:ff:ff:ff:ff:ff"

    def _handle_host_traffic(self, pkt: packet.Packet, pk: PortKey, src_mac: str, pp: PortProperty) -> None:
        # Transit traffic on inter-switch ports must never be interpreted as
        # first-hop host traffic.
        if pp.device_type == DeviceType.SWITCH:
            return

        previous = self.topoguard_mac_port.get(src_mac)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if previous is None:
            self.topoguard_mac_port[src_mac] = pk
            pp.add_host(src_mac)
            pp.set_port_any()
            return

        if previous == pk:
            if pp.device_type == DeviceType.SWITCH:
                self.logger.warning(
                    "Violation: Receive first-hop host packet from SWITCH port: sw=%s port=%s",
                    pk.dpid,
                    pk.port,
                )
            elif pp.device_type == DeviceType.ANY:
                pp.set_port_host()
                pp.disable_host_shutdown(src_mac)
            return

        # Host moved to a different first-hop port.
        previous_pp = self.port_state.get(previous)
        if previous_pp and previous_pp.device_type == DeviceType.SWITCH:
            # Previous location was a trunk port, so treat old mapping as stale.
            self.topoguard_mac_port[src_mac] = pk
            pp.add_host(src_mac)
            pp.set_port_host()
            return

        if previous_pp and src_mac in previous_pp.hosts and not previous_pp.hosts[src_mac]:
            self.logger.warning(
                "Violation: Host Move from switch %s port %s without Port ShutDown",
                previous.dpid,
                previous.port,
            )

        if ip_pkt is not None:
            if self._send_host_probe(ip_pkt.src, src_mac, previous):
                self.probed_ports[previous].append(HostEntity(mac=src_mac, ip=ip_pkt.src))

        self.topoguard_mac_port[src_mac] = pk
        pp.add_host(src_mac)
        pp.set_port_host()

    def _send_host_probe(self, ip_addr: str, mac_addr: str, out_port: PortKey) -> bool:
        datapath = self.datapaths.get(out_port.dpid)
        if datapath is None:
            return False

        if out_port.port not in self.switch_port_desc.get(out_port.dpid, {}):
            return False

        parser = datapath.ofproto_parser
        ofp = datapath.ofproto

        probe_pkt = packet.Packet()
        probe_pkt.add_protocol(
            ethernet.ethernet(
                dst=mac_addr,
                src=self.PROBE_SRC_MAC,
                ethertype=ether_types.ETH_TYPE_IP,
            )
        )
        probe_pkt.add_protocol(
            ipv4.ipv4(
                src=self.CONTROLLER_IP,
                dst=ip_addr,
                proto=inet.IPPROTO_ICMP,
                ttl=64,
            )
        )
        probe_pkt.add_protocol(
            icmp.icmp(type_=icmp.ICMP_ECHO_REQUEST, code=0, csum=0, data=icmp.echo(id_=1, seq=1, data=b"tg"))
        )
        probe_pkt.serialize()

        actions = [parser.OFPActionOutput(out_port.port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=actions,
            data=probe_pkt.data,
        )
        datapath.send_msg(out)
        return True

    def _handle_probe_reply(self, pkt: packet.Packet, pk: PortKey, src_mac: str) -> bool:
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if ip_pkt is None or icmp_pkt is None:
            return False

        if icmp_pkt.type != icmp.ICMP_ECHO_REPLY:
            return False

        entities = self.probed_ports.get(pk)
        if not entities:
            return False

        for he in list(entities):
            if he.ip == ip_pkt.src and he.mac == src_mac and ip_pkt.dst == self.CONTROLLER_IP:
                self.logger.warning(
                    "Violation: Host Move from switch %s port %s is still reachable",
                    pk.dpid,
                    pk.port,
                )
                entities.remove(he)
                if not entities:
                    self.probed_ports.pop(pk, None)
                return True

        return False

    @staticmethod
    def _mac_to_bytes(mac_str) -> bytes:
        if isinstance(mac_str, bytes):
            if len(mac_str) == 6:
                return mac_str
            raise ValueError("Invalid binary MAC length")
        return bytes(int(part, 16) for part in mac_str.split(":"))
