# Final Skeleton
# a
# Hints/Reminders from Lab 3:
#
# To check the source and destination of an IP packet, you can use
# the header information... For example:
#
# ip_header = packet.find('ipv4')
#
# if ip_header.srcip == "1.1.1.1":
#   print "Packet is from 1.1.1.1"
#
# Important Note: the "is" comparison DOES NOT work for IP address
# comparisons in this way. You must use ==.
# 
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the 
# switch should send the packets out:
#
#    msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet)
#    msg.idle_timeout = 30
#    msg.hard_timeout = 30
#
#    msg.actions.append(of.ofp_action_output(port = <PORT>))
#    msg.data = packet_in
#    self.connection.send(msg)
#
# To drop packets, simply omit the action.
#

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()
valid={}
class Final (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)
    
   #  Drop all Packets that aren't defined
   #  msg = of.ofp_flow_mod()
   #  match = of.ofp_match()
   #  msg.match = match
   #  msg.hard_timeout = 0
   #  msg.soft_timeout = 0
   #  msg.priority = 1
     

  # flood packet method 
  def send(self,event,dst_port):
    msg = of.ofp_packet_out(in_port=event.ofp.in_port)
    if event.ofp.buffer_id is not None and event.ofp.buffer_id != -1:
       msg.buffer_id = event.ofp.buffer_id
    else:
       return
    msg.actions.append(of.ofp_action_output(port = dst_port))
    event.connection.send(msg)
   
  def installFlow (self,nw_src,nw_dst,tp_src,tp_dst,dl_type,nw_proto):
    msg = of.ofp_flow_mod()
    match = of.ofp_match()
    match.nw_src = nw_src
    match.nw_dst = nw_dst
    match.tp_src = tp_src
    match.tp_dst = tp_dst
    match.nw_proto = nw_proto
    match.dl_type = dl_type
    msg.match = match
    msg.hard_timeout = 0
    msg.idle_timeout = 100
    msg.priority = 2
    action = of.ofp_action_output(port = of.OFPP_NORMAL)
    msg.actions.append(action)
    self.connection.send(msg)

  def resend (self,packet,tp_dst):
    msg = of.ofp_packet_out()    
    msg.data = packet
    out_port = of.OFPP_NORMAL
    action = of.ofp_action_output(port = tp_dst)
    msg.actions.append(action)
    self.connection.send(msg)

  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    # This is where you'll put your code. The following modifications have 
    # been made from Lab 3:
    #   - port_on_switch: represents the port that the packet was received on.
    #   - switch_id represents the id of the switch that received the packet.
    #      (for example, s1 would have switch_id == 1, s2 would have switch_id == 2, etc...)
    # You should use these to determine where a packet came from. To figure out where a packet 
    # is going, you can use the IP header information.
    ipv4 = packet.find('ipv4')
    if ipv4 != None:
       ip_packet = packet.payload
       if ip_packet.protocol == ip_packet.TCP_PROTOCOL:
         tcp_packet = ip_packet.payload
         if (switch_id != 4):
           self.installFlow(ip_packet.srcip,ip_packet.dstip,tcp_packet.srcport,tcp_packet.dstport,0x800,6)
           self.installFlow(ip_packet.dstip,ip_packet.srcip,tcp_packet.dstport,tcp_packet.srcport,0x800,6)
           Final.resend (self,packet,1)  
         if (switch_id == 4): 
           self.installFlow(ip_packet.srcip,ip_packet.dstip,tcp_packet.srcport,tcp_packet.dstport,0x800,6)
           self.installFlow(ip_packet.dstip,ip_packet.srcip,tcp_packet.dstport,tcp_packet.srcport,0x800,6)
           if (ip_packet.dstip == '10.1.1.10'):
             Final.resend (self,packet,1)
           if (ip_packet.dstip == '10.2.2.20'):
             Final.resend (self,packet,2)
           if (ip_packet.dstip == '10.3.3.30'):
             Final.resend (self,packet,3)
           if (ip_packet.dstip == '10.4.4.40'):
             Final.resend (self,packet,4)
           if (ip_packet.dstip == '10.5.5.50'):
             Final.resend (self,packet,5)


       if ip_packet.protocol == ip_packet.UDP_PROTOCOL:
         udp_packet = ip_packet.payload
         if (switch_id != 4):
           self.installFlow(ip_packet.srcip,ip_packet.dstip,udp_packet.srcport,udp_packet.dstport,0x800,16)
           self.installFlow(ip_packet.dstip,ip_packet.srcip,udp_packet.dstport,udp_packet.srcport,0x800,16)
           Final.resend (self,packet,1)  
         if (switch_id == 4): 
           self.installFlow(ip_packet.srcip,ip_packet.dstip,udp_packet.srcport,udp_packet.dstport,0x800,16)
           self.installFlow(ip_packet.dstip,ip_packet.srcip,udp_packet.dstport,udp_packet.srcport,0x800,16)
           if (ip_packet.dstip == '10.1.1.10'):
             Final.resend (self,packet,1)
           if (ip_packet.dstip == '10.2.2.20'):
             Final.resend (self,packet,2)
           if (ip_packet.dstip == '10.3.3.30'):
             Final.resend (self,packet,3)
           if (ip_packet.dstip == '10.4.4.40'):
             Final.resend (self,packet,4)
           if (ip_packet.dstip == '10.5.5.50'):
             Final.resend (self,packet,5)


       if ip_packet.protocol == ip_packet.ICMP_PROTOCOL:
         icmp_packet = ip_packet.payload 
         if valid [ip_packet.srcip] != True :
           print ip_packet.srcip
           print "NOT VALID!" 

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    packet_in = event.ofp # The actual ofp_packet_in message.
    ipv4 = packet.find('ipv4')
    arpp = packet.find('arp')
    icmpp = packet.find('icmp')
    valid[10.1.1.10]=True
    valid[10.2.2.20]=True
    valid[10.3.3.30]=True
    valid[10.4.4.40]=True
    valid[10.5.5.50]=True
    if ipv4 != None:
      self.do_final(packet, packet_in, event.port, event.dpid)
        # FILTERS for ICMP are done in do_final.
      if (icmpp != None):
        self.send(event,of.OFPP_FLOOD)
    else:
      self.send(event,of.OFPP_ALL)
def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
