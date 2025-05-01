from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
from forwarding.l2_learning import LearningSwitch
import subprocess
import shlex
import datetime
import click_wrapper

log = core.getLogger()


class controller (object):
    # Here you should save a reference to each element:
    devices = dict()

    # Here you should save a reference to the place you saw the first time a specific source mac
    firstSeenAt = dict()

    def __init__(self):

        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        
        """
        This function is called everytime a new device starts in the network.
        You need to determine what is the new device and run the correct application based on that.
        
        Note that for normal switches you should use l2_learning module that already is available in pox as an external module.
        """

        # In this phase, you will need to run your network functions on the controller. Here is just an example how you can do it:
        # click = click_wrapper.start_click("../nfv/forwarder.click", "", "/tmp/forwarder.stdout", "/tmp/forwarder.stderr")

        # You might need a record of switches that are already connected to the controller. 
        # Please keep them in "devices".
        # For instance: self.devices[len(self.devices)] = mySwitch
        id = event.dpid
        if(id<=3):
            # This is a normal learning switch
            # You should run the l2_learning module
            log.info(f"Starting Learning Switch for switch {id}")
            self.devices[id] = LearningSwitch(event.connection, False)
        elif(id==4):
            # This is the NAPT switch
            log.info("Starting NAPT")
            # Click script
            self.devices[id] = click_wrapper.start_click("/opt/pox/ext/napt.click", "", "/tmp/napt.stdout", "/tmp/napt.stderr")
        elif(id==5):
            # This is the IDS switch
            log.info("Starting IDS")
            # IDS Click script
            self.devices[id] = click_wrapper.start_click("/opt/pox/ext/ids.click", "", "/tmp/ids.stdout", "/tmp/ids.stderr")
        elif(id==6):
            # This is the Load Balancer switch
            log.info("Starting Load Balancer")
            # load-balancer Click script
            self.devices[id] = click_wrapper.start_click("/opt/pox/ext/lb1.click", "", "/tmp/lb1.stdout", "/tmp/lb1.stderr")
        else:
            # Error
            log.error("Unknown device connected to the controller")

        return

    # This should be called by each element in your application when a new source MAC is seen

    def updatefirstSeenAt(self, mac, where):
       
        """
        This function updates your first seen dictionary with the given input.
        It should be called by each element in your application when a new source MAC is seen
        """
       
        # self.firstSeenAt[mac] = (where, datetime.datetime.now().isoformat())
        if mac not in self.firstSeenAt:
            # first time we ever see this MAC—record where and when
            log.info(f"New MAC {mac} seen at {where} (firstSeenAt)")
            self.firstSeenAt[mac] = (where, now)
        else:
            old_where, old_time = self.firstSeenAt[mac]
            if where != old_where:
                # host moved: log a warning so we can detect mobility/anomalies
                log.warning(f"MAC {mac} moved from {old_where} to {where}; first seen at {old_time}")
            else:
                # same location as before—no change in first-seen
                log.debug(f"MAC {mac} still at {where}; first seen at {old_time}")



def launch(configuration=""):
    core.registerNew(controller)
