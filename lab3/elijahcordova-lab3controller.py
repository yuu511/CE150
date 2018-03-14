# Lab 3 Skeleton
#
# Based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()
valid = {}
firewallOk = {}

class Firewall (object):
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
  
  # send packet
  def send(self,event,dst_port=of.OFPP_ALL):
    msg = of.ofp_packet_out(in_port=event.ofp.in_port)
    if event.ofp.buffer_id is not None and event.ofp.buffer_id != -1:
       msg.buffer_id = event.ofp.buffer_id
    else
       return
    msg.actions.append(of.ofp_action_output(port = dst_port))
    event.connection.send(msg)


  def do_firewall (self, packet, packet_in):
    # The code in here will be executed for every packet.
    print ""

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)
    tcpp = event.parsed.find('tcp')
    arpp = event.parsed.find('arp')
    if tcpp is None and arpp is None:
      print "NTA"
      return 
    # build flow both ways
    valid[(event.connection,packet.src)] = event.port
    destination = valid.get((event.connection,packet.dst))
    if destination is None:
      self.send(event, of.OFPP_ALL)
    else:
      msg = of.ofp_flow_mod()
      msg.idle_timeout = 1000
      msg.hard_timeout = 3000     
      if tcpp is not None: 
        msg.match.dl_type = 0x800
        msg.match.nw_proto = 6
        print "T"
      elif arpp is not None:  
        msg.match.dl_type = 0x806
        msg.match.nw_proto = None
        print "A" 
      msg.match.dl_src = packet.src
      msg.match.dl_dst = packet.dst
      msg.actions.append(of.ofp_action_output(port = destination))
      event.connection.send(msg) 

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
