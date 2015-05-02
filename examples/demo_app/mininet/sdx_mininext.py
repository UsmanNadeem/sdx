#!/usr/bin/python

# Author: Arpit Gupta (glex.qsd@gmail.com)

"Create SDX topology with 4 Quagga edge routers"

import inspect, os, sys, atexit
# Import topo from Mininext
from mininext.topo import Topo
# Import quagga service from examples
from mininext.services.quagga import QuaggaService
# Other Mininext specific imports
from mininext.net import MiniNExT as Mininext
from mininext.cli import CLI
import mininext.util
# Imports from Mininet
import mininet.util
mininet.util.isShellBuiltin = mininext.util.isShellBuiltin
sys.modules['mininet.util'] = mininet.util

from mininet.node import OVSSwitch, Controller

from mininet.util import dumpNodeConnections
from mininet.node import RemoteController
from mininet.node import Node
from mininet.link import Link
from mininet.log import setLogLevel, info
from collections import namedtuple
#from mininet.term import makeTerm, cleanUpScreens
QuaggaHost = namedtuple("QuaggaHost", "name ip mac port")
net = None


class QuaggaTopo( Topo ):
    "Quagga topology example."

    def __init__( self ):

        "Initialize topology"
        Topo.__init__( self )

        "Directory where this file / script is located"
        scriptdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))) # script directory
        "Initialize a service helper for Quagga with default options"
        quaggaSvc = QuaggaService(autoStop=False)

        "Path configurations for mounts"
        quaggaBaseConfigPath=scriptdir + '/quaggacfgs/'

        "List of Quagga host configs"
        quaggaHosts = []
        quaggaHosts.append(QuaggaHost(name = 'a1', ip = '172.0.0.1/16', mac = '08:00:27:89:3b:9f', port = 1))
        quaggaHosts.append(QuaggaHost(name = 'b1', ip = '172.0.0.2/16', mac = '08:00:27:92:18:1f', port = 2))
        quaggaHosts.append(QuaggaHost(name = 'c1', ip = '172.0.0.3/16', mac = '08:00:27:54:56:ea', port = 3))
        quaggaHosts.append(QuaggaHost(name = 'c2', ip = '172.0.0.4/16', mac = '08:00:27:bd:f8:b2', port = 4))

        "Add switch for IXP fabric"
        ixpfabric = self.addSwitch( 's1' )
        " Adding other host not connected directly to the IXP "
	sw = self.addSwitch( 's2' )
        otherhost = self.addHost(name = "host", ip = "140.0.0.4/24", mac = '08:00:27:bd:f8:92', privateLogDir=True, privateRunDir=True, inMountNamespace=True, inPIDNamespace=True)

        "Setup each legacy router, add a link between it and the IXP fabric"
        for host in quaggaHosts:
            "Set Quagga service configuration for this node"
            quaggaSvcConfig = \
            { 'quaggaConfigPath' : scriptdir + '/quaggacfgs/' + host.name }
            quaggaContainer = self.addHost( name=host.name,
                                            ip=host.ip,
					    mac=host.mac,
                                            privateLogDir=True,
                                            privateRunDir=True,
                                            inMountNamespace=True,
                                            inPIDNamespace=True)
            self.addNodeService(node=host.name, service=quaggaSvc,
                                nodeConfig=quaggaSvcConfig)
	    "Attach the quaggaContainer to the IXP Fabric Switch"
            self.addLink( quaggaContainer, ixpfabric , port2=host.port)
       
	" Add root node for ExaBGP. ExaBGP acts as route server for SDX. "
	root = self.addHost('exabgp', ip = '172.0.255.254/16', inNamespace = False)
	self.addLink(root, ixpfabric, port2 = 5)
	
	" Adding other host not connected directly to the IXP "
        self.addLink( 'b1', sw)
        self.addLink( 'c1', sw)
        self.addLink( otherhost, sw)


def addInterfacesForSDXNetwork( net ):
    
        
    hosts=net.hosts
    print "Configuring participating ASs\n\n"

    for host in hosts:
	print "Host name: ", host.name
	#if host.name=='a1':
		#host.cmd('sudo ifconfig lo:1 100.0.0.1 netmask 255.255.255.0 up')
	if host.name=='b1':
		host.cmd('sudo ifconfig b1-eth1 140.0.0.2/24 up')
		host.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
		host.cmd('iptables -t nat -A POSTROUTING -s 172.0.0.0/24 -j SNAT --to-source 140.0.0.2')
	if host.name=='c1':
		host.cmd('sudo ifconfig c1-eth1 140.0.0.3/24 up')
		host.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
		host.cmd('iptables -t nat -A POSTROUTING -s 172.0.0.0/24 -j SNAT --to-source 140.0.0.3')
	#if host.name=='c2':
		#host.cmd('sudo ifconfig lo:143 140.0.0.3 netmask 255.255.255.0 
	if host.name=='host':
		host.cmd('route add -net default gw 140.0.0.2')
		#host.cmd('route add -net default dev host-eth0')
	if host.name == "exabgp":
		host.cmd( 'route add -net 172.0.0.0/16 dev exabgp-eth0')

def startNetwork():
    info( '** Creating Quagga network topology\n' )
    topo = QuaggaTopo()
    global net
    net = Mininext(topo=topo, switch=OVSSwitch, build = False )
    #net = Mininext(topo=topo, controller=lambda name: RemoteController( name, ip='127.0.0.1' ),listenPort=6633)
    " Add controller for additional switches "
    c1 = net.addController( 'c1', controller=RemoteController, ip='127.0.0.1', port=6633)
    c2 = net.addController( 'c2', port=6634 )
    
    # sh ovs-vsctl show OVSSwitch
            
    info( '** Starting the network\n' )
    net.start()
    
    c1.start()
    c2.start()
    for switch in net.switches:
        if switch.name == 's1':
                switch.start( [c1, c2] )
        if switch.name == 's2':
                switch.start( [c2, c1] )
                
    
    info( '** psaux dumps on all hosts\n' )
    for lr in net.hosts:
        if lr.name != 'exabgp':
	    lr.cmdPrint("ps aux")
    
    info( '**Adding Network Interfaces for SDX Setup\n' )    
    addInterfacesForSDXNetwork(net)
    
    info( '** Running CLI\n' )
    CLI( net )

def stopNetwork():
    if net is not None:
        info( '** Tearing down Quagga network\n' )
        net.stop()

if __name__ == '__main__':
    # Force cleanup on exit by registering a cleanup function
    atexit.register(stopNetwork)

    # Tell mininet to print useful information
    setLogLevel('info')
    startNetwork()
