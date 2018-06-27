from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv6
from ryu.lib import mac
from ryu.lib.packet import ether_types

import requests
import json
import time
import sys

from threading import Timer
from datetime import datetime

import os

files = open(os.getenv("HOME")+ "/teste.txt", "r")
time1,time2 = files.readline().split(":")
print time1
print time2

class MySwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MySwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}
        self.sw = {}
       

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.

        self.logger.info("SWITCH CONFIGURANDO: %s",datapath.id)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions,False)
        #Configurando QOS Fila
        if datapath.id==1:
            self.logger.info("CONFIGURATION")
            payload = "tcp:127.0.0.1:6632"
            url= "http://localhost:8080/v1.0/conf/switches/0000000000000001/ovsdb_addr"
            r = requests.put(url,data=json.dumps(payload))

            time.sleep(1)

            url = "http://localhost:8080/qos/queue/0000000000000001"
            payload = {"type": "linux-htb","max_rate":"240000","queues": [{"min_rate":"0","max_rate":"240000"}, {"min_rate": "160000"}]}
            r = requests.post(url,data=json.dumps(payload))

        elif datapath.id==2:
            self.logger.info("CONFIGURATION!")
            payload = "tcp:127.0.0.1:6632"
            url= "http://localhost:8080/v1.0/conf/switches/0000000000000002/ovsdb_addr"
            r = requests.put(url,data=json.dumps(payload))

            time.sleep(1)

            url = "http://localhost:8080/qos/queue/0000000000000002"
            payload = {"type": "linux-htb","max_rate":"240000","queues": [{"min_rate":"0","max_rate":"240000"}, {"min_rate": "160000"}]}
            r = requests.post(url,data=json.dumps(payload))
        elif datapath.id==3:
            self.logger.info("CONFIGURATION OK!")
            payload = "tcp:127.0.0.1:6632"
            url= "http://localhost:8080/v1.0/conf/switches/0000000000000003/ovsdb_addr"
            r = requests.put(url,data=json.dumps(payload)) 

            time.sleep(1)
             #configurando a banda
            url = "http://localhost:8080/qos/queue/0000000000000003"
            payload = {"type": "linux-htb","max_rate":"240000","queues": [{"min_rate":"0","max_rate":"240000"}, {"min_rate": "160000"}]}
            r = requests.post(url,data=json.dumps(payload))
            
    def add_flow(self, datapath, priority, match, actions, select):
        #self.logger.info("Apredendo nova Regra!")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if select:
            #Regra e valida durante 400 segundos
            mod = parser.OFPFlowMod(datapath=datapath, 
                                    priority=priority, match=match,hard_timeout=400,
                                    instructions=inst,table_id=1)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,table_id=1)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']


        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions,True)
            return None

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = src  # ARP learning

        self.mac_to_port.setdefault(dpid, {})
        '''
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        '''
        # Learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            if self.arp_handler(msg):
                return None
            else:
                out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            #descarta o pacote se permissao 0 e direciona para o fluxo se diferente
            permissao = self.permission(dpid,in_port,src,dst)
            if permissao == 0:
                actions = []
            else:
                actions = [parser.OFPActionOutput(permissao)]

            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions,True)
            return
          
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def arp_handler(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth:
            eth_dst = eth.dst
            eth_src = eth.src

        # Break the loop for avoiding ARP broadcast storm
        if eth_dst == mac.BROADCAST_STR and arp_pkt:
            arp_dst_ip = arp_pkt.dst_ip

            if (datapath.id, eth_src, arp_dst_ip) in self.sw:
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    datapath.send_packet_out(in_port=in_port, actions=[])
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        # Try to reply arp request
        if arp_pkt:
            hwtype = arp_pkt.hwtype
            proto = arp_pkt.proto
            hlen = arp_pkt.hlen
            plen = arp_pkt.plen
            opcode = arp_pkt.opcode
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip

            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:
                    actions = [parser.OFPActionOutput(in_port)]
                    ARP_Reply = packet.Packet()

                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    ARP_Reply.serialize()

                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    return True
        return False
    #Gerenciador de fluxo
    def permission(self,dpid,in_port,src,dst):
        #Regras estaticas
        self.logger.debug("Definindo Regras estatica")
        self.logger.debug("porta: %s , src: %s , dst: %s",in_port,src,dst)
        #para o switch1
        if dpid == 1:
                #regras switch1 C1-C2 - Send - Receive
                if (in_port == 1 and src == '00:00:00:00:00:01' and dst == '00:00:00:00:00:03') :
                    self.logger.debug("Fluxo Permitido Switch1 Client1-Client2")
                    return 3
                elif (in_port == 8 and src == '00:00:00:00:00:03' and dst == '00:00:00:00:00:01'):
                    self.logger.debug("Fluxo Permitido Switch1 Client2-Client1")
                    return 1
                
                #regras switch1 C1-C3 - Send - Receive
                if (in_port == 1  and src == '00:00:00:00:00:01' and dst == '00:00:00:00:00:05') :
                    self.logger.debug("Fluxo Permitido Switch1 Client1-Client3")
                    return 3
                elif ( in_port==8 and src == '00:00:00:00:00:05' and dst == '00:00:00:00:00:01'):
                    self.logger.debug("Fluxo Permitido Switch1 Client3-Client1")
                    return 1
                
                
                #regras FLUXO INTERMEDIARIO - switch1 C3-C2 - Send - Receive
                if (in_port== 8 and src == '00:00:00:00:00:05' and dst == '00:00:00:00:00:03') :
                    self.logger.debug("Fluxo INTERMEDIARIO -  Permitido Switch1 Client2-Client3")
                    return 3
                
                #Server3-Server - Recebe
                if (in_port == 7 and src == '00:00:00:00:00:06' and dst == '00:00:00:00:00:02') :
                    self.logger.debug("Fluxo Permitido Switch1 Server3-Server1")
                    return 8

                # Server1-Server2 - Envia
                if (in_port == 3  and src == '00:00:00:00:00:02' and dst == '00:00:00:00:00:04') :
                    self.logger.debug("Fluxo Permitido Switch1 Server1-Server3")
                    return 2

        #para o switch2        
        elif dpid == 2:
                #regras switch2 C2-C1 - Send - Receive
                if (in_port == 1 and src == '00:00:00:00:00:03' and dst == '00:00:00:00:00:01') :
                    self.logger.debug("Fluxo Permitido Switch2 Client2-Client1")
                    return 5
                elif (in_port == 4 and src == '00:00:00:00:00:01' and dst == '00:00:00:00:00:03'):
                    self.logger.debug("Fluxo Permitido Switch2 Client1-Client2")
                    return 1
                
                #regras switch2 C2-C3 - Send - Receive
                if (in_port == 1 and src == '00:00:00:00:00:03' and dst == '00:00:00:00:00:05') :
                    self.logger.debug("Fluxo Permitido Switch2 Client2-Client3")
                    return 5
                elif (in_port == 4 and src == '00:00:00:00:00:05' and dst == '00:00:00:00:00:03'):
                    self.logger.debug("Fluxo Permitido Switch2 Client3-Client2")
                    return 1
                
                
                #regras FLUXO INTERMEDIARIO - switch1 C1-C3 - Send - Receive
                if (in_port == 4 and src == '00:00:00:00:00:01' and dst == '00:00:00:00:00:05') :
                    self.logger.debug("Fluxo INTERMEDIARIO -  Permitido Switch2 Client1-Client3")
                    return 5
                

                #Regra Server1-Server2 - Recebe
                if (in_port==4 and src == '00:00:00:00:00:02' and dst == '00:00:00:00:00:04') :
                    self.logger.debug("Fluxo Permitido Switch2 Server1-Server2")
                    return 2
                
                #Regra Server2-Server3 - Envia
                if (in_port==2 and src == '00:00:00:00:00:04' and dst == '00:00:00:00:00:06') :
                    self.logger.debug("Fluxo Permitido Switch2 Server2-Server3")
                    return 5

        #para o switch3     
        elif dpid == 3:
                #regras switch3 C3-C1 - Send - Receive   
                if (in_port==1 and src == '00:00:00:00:00:05' and dst == '00:00:00:00:00:01') :
                    self.logger.debug("Fluxo Permitido Switch3 Client3-Client1")
                    return 7
                elif (in_port==6 and src == '00:00:00:00:00:01' and dst == '00:00:00:00:00:05'):
                    self.logger.debug("Fluxo Permitido Switch3 Client1-Client3")
                    return 1

                #regras switch3 C3-C2 - Send - Receive
                if (in_port==1 and src == '00:00:00:00:00:05' and dst == '00:00:00:00:00:03') :
                    self.logger.debug("Fluxo Permitido Switch3 Client3-Client2")
                    return 7
                elif (in_port==6 and src == '00:00:00:00:00:03' and dst == '00:00:00:00:00:05'):
                    self.logger.debug("Fluxo Permitido Switch3 Client2-Client3")
                    return 1
                
                #Regra Server2-Server3 - Recebe
                if (in_port == 6 and src == '00:00:00:00:00:04' and dst == '00:00:00:00:00:06') :
                    self.logger.debug("Fluxo Permitido Switch3 Server2-Server3")
                    return 2

                #Regra Server3-Server1 - Envia
                if (in_port == 2 and src == '00:00:00:00:00:06' and dst == '00:00:00:00:00:02') :
                    self.logger.debug("Fluxo Permitido Switch3 Server3-Server1")
                    return 7
                
                #regras switch2 C2-C1 -Intermediario- Send - Receive
                if (in_port == 6 and src == '00:00:00:00:00:03' and dst == '00:00:00:00:00:01'):
                    self.logger.debug("Fluxo INTERMEDIARIO - Permitido Switch3 Client2-Client1")
                    return 7

        self.logger.debug("Fluxo sem permissao,descarte de pacotes: porta: %s , src: %s , dst: %s",in_port,src,dst)
        return 0


#verifica se esta dentro da hora especial
def reservaBanda(time1,time2):
    horaAtual = datetime.now().strftime('%H')
    horaAtualInt = int(horaAtual) 
    time1Int = int(time1)
    time2Int = int(time2)
    print("Hora Atual:")
    print(horaAtualInt)
    if time1Int<horaAtualInt and horaAtualInt<time2Int:
        return True
    else: 
        return False

#aloca banda baseada na hora
def alocaBanda():
    while(True):
        if(reservaBanda(time1,time2)):
            print ('Alocada Banda Especial Para os Servidores')
            url = "http://localhost:8080/qos/rules/0000000000000001"
            payload = {"priority": "1",
                    "match": {"nw_src":"10.0.0.2","nw_dst": "10.0.0.4","nw_proto": "TCP","nw_proto": "UDP"}, 
                    "actions":{"queue": "1"} }
            r = requests.post(url,data=json.dumps(payload))
            print(r)
            
        
            url = "http://localhost:8080/qos/rules/0000000000000002"
            payload = {"priority": "1",
                    "match": {"nw_src":"10.0.0.4","nw_dst": "10.0.0.6","nw_proto": "TCP","nw_proto": "UDP"}, 
                    "actions":{"queue": "1"} }
            r = requests.post(url,data=json.dumps(payload))
            print(r)

          
            
            url = "http://localhost:8080/qos/rules/0000000000000003"
            payload = {"priority": "1",
                    "match": {"nw_src":"10.0.0.6","nw_dst": "10.0.0.2","nw_proto": "TCP","nw_proto": "UDP"}, 
                    "actions":{"queue": "1"} }
            r = requests.post(url,data=json.dumps(payload))
            print(r)

        
        #faca essas configuracoes
        else:
            print ('Banda Normal')
            url = "http://localhost:8080/qos/rules/0000000000000001"
            payload = {"priority": "1",
                    "match": {"nw_src":"10.0.0.2","nw_dst": "10.0.0.4","nw_proto": "TCP","nw_proto": "UDP"}, 
                    "actions":{"queue": "0"} }
            r = requests.post(url,data=json.dumps(payload))
            print(r)

          
            
            url = "http://localhost:8080/qos/rules/0000000000000002"
            payload = {"priority": "1",
                    "match": {"nw_src":"10.0.0.4","nw_dst": "10.0.0.6","nw_proto": "TCP","nw_proto": "UDP"}, 
                    "actions":{"queue": "0"} }
            r = requests.post(url,data=json.dumps(payload))
            print(r)

          
            
            url = "http://localhost:8080/qos/rules/0000000000000003"
            payload = {"priority": "1",
                    "match": {"nw_src":"10.0.0.6","nw_dst": "10.0.0.2","nw_proto": "TCP","nw_proto": "UDP"}, 
                    "actions":{"queue": "0"} }
            r = requests.post(url,data=json.dumps(payload))
            print(r)

          
        #faca essas configuracoes,atualizar a cada 60 segundos a regra
        time.sleep(60)
      
#executa daqui a 20 segundos,listening
t = Timer(20.0, alocaBanda)
t.start() 
