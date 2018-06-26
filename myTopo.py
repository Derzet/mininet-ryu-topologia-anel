#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
from mininet.link import TCIntf
from mininet.util import custom

import requests
import json


def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    controler0=net.addController(name='controler0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    switch1 = net.addSwitch('switch1',cls=OVSKernelSwitch,  protocols='OpenFlow13', mac='00:00:00:00:10:00')
    switch2 = net.addSwitch('switch2',cls=OVSKernelSwitch, protocols='OpenFlow13', mac='00:00:00:00:20:00' )
    switch3 = net.addSwitch('switch3',cls=OVSKernelSwitch,  protocols='OpenFlow13', mac='00:00:00:00:30:00' )
    

    info( '*** Add hosts\n')
   
    client1 = net.addHost('client1', cls=Host, ip='10.0.0.1',mac='00:00:00:00:00:01')
    server1 = net.addHost('server1', cls=Host, ip='10.0.0.2',mac='00:00:00:00:00:02') 
      
    client2 = net.addHost('client2', cls=Host, ip='10.0.0.3',mac='00:00:00:00:00:03')
    server2 = net.addHost('server2', cls=Host, ip='10.0.0.4',mac='00:00:00:00:00:04')
    
    client3 = net.addHost('client3', cls=Host, ip='10.0.0.5',mac='00:00:00:00:00:05')
    server3 = net.addHost('server3', cls=Host, ip='10.0.0.6',mac='00:00:00:00:00:06')
    
  
    info( '*** Add links\n')
    

    
    #client
    net.addLink(switch1,client1,1,1024)

    net.addLink(switch2,client2,1,1024)
         
    net.addLink(switch3,client3,1,1024)
    
    #serves
    net.addLink(switch1,server1,2,1024)

    net.addLink(switch2,server2,2,1024)
    
    net.addLink(switch3,server3,2,1024)
    
    #switches

    net.addLink(switch1,switch2,3,4)
    
    net.addLink(switch2,switch3,5,6)
    
    net.addLink(switch3,switch1,7,8) 
    
    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    
    net.get('switch1').start([controler0])
    net.get('switch2').start([controler0]) 
    net.get('switch3').start([controler0])
    
    switch1.cmd("ovs-vsctl set-manager ptcp:6632")  
    switch2.cmd("ovs-vsctl set-manager ptcp:6632") 
    switch3.cmd("ovs-vsctl set-manager ptcp:6632")  

    info( '*** Post configure switches and hosts\n')
    #client1.cmd("iperf -s -p 1024")
    #enable All
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

