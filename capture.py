"""
capture.py
David Rice
Version 1.0
A demo program to show the Cisco URWB telemetry library in action
"""

from scapy.all import *
from scapy.layers.inet import UDP
from pycurwb import *
import typer

app = typer.Typer()     #initialize typer app

def decode_urwb_packet(packet):
    """
    If URWBTelemetry layer found, show the packet
    """
    if URWBTelemetry in packet:
        packet[URWBTelemetry].show()

@app.command("capture")
def capture(
    interface: str = typer.Option(default=..., help = "Windows interface name"),
    port: int = typer.Option(default=30000, help = "UDP receipt port for telemetry data")
):
    try:
        bind_layers(UDP, URWBTelemetry, dport=port)     #Causes scapy to automatically decode the UDP payload for packets received on UDP port "port" as URWBTelemetry Packet's
        sniff(iface=interface, filter=f"udp port {port}", prn=decode_urwb_packet)       #sniff packets with capture filture of "udp port 'port'" from "interface" and send them to "decode_urwb_packet" function for handling
    except KeyboardInterrupt:  #stop capture on keyboard interrupt
        print('\nStopped packet capture')

if __name__ == "__main__":
    app()
