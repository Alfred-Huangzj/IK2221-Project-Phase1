#!/usr/bin/python3

import os
import subprocess
import time
import signal
from pox.core import core
log = core.getLogger()

# Register signal handlers to gracefully stop Click processes
signal.signal(signal.SIGINT, lambda sig, frame: handle_kill(sig, frame))
signal.signal(signal.SIGTERM, lambda sig, frame: handle_kill(sig, frame))

"""
This is an helper wrapper to run Click on top of POX
This will be used in the NFV part of the project
"""


click_pids = []

def start_click(configuration, parameters, stdout="/tmp/click.out", stderr="/tmp/click.err"):
    """
    Launch a Click process with the specified configuration file and parameters.
    Standard output and error are appended to the given files.
    Returns the Popen object.
    """
    # Build the command invocation
    cmd = ["sudo", "click", configuration] + (parameters.split() if parameters else [])
    # Open the log files for appending
    out_fd = open(stdout, 'a')
    err_fd = open(stderr, 'a')
    log.info(f"Launching Click: {' '.join(cmd)}, stdout->{stdout}, stderr->{stderr}")
    # Start process in its own session to facilitate cleanup
    p = subprocess.Popen(cmd, stdout=out_fd, stderr=err_fd, preexec_fn=os.setsid)
    click_pids.append(p.pid)
    log.info(f"Click launched with PID {p.pid}")
    return p


def handle_kill(sig, frame):
    """
    Signal handler to terminate all started Click processes.
    """
    log.info(f"Received signal {sig}, terminating Click processes...")
    for pid in list(click_pids):
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            log.info(f"Sent SIGTERM to Click PID {pid}")
        except ProcessLookupError:
            log.warning(f"Click PID {pid} not found")
    # Allow some time for cleanup
    time.sleep(0.5)
    os._exit(0)

def killall_click():
    """
    Forcefully terminate any remaining Click processes.
    """
    log.info("Killing all Click processes via killall")
    subprocess.call(["sudo", "killall", "-SIGTERM", "click"], shell=False)
