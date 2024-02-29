from scapy.all import *
from scapy.layers.inet import IP, TCP
import logging

logging.basicConfig(level=logging.INFO)

TARGET_IP = "127.0.0.1"
START_PORT = 20
END_PORT = 1024
TIMEOUT = 0.5


def syn_scan(target_ip_new, port):
    """
    Sends a SYN packet to a target IP address and port. Determines if the port
    is open based on the response received.

    param target_ip_new: The target IP address as a string.
    param port: The target port as an integer.
    """
    ip = IP(dst=target_ip_new)
    syn = TCP(dport=port, flags='S')
    resp = sr1(ip/syn, timeout=TIMEOUT, verbose=0)

    if resp is None:
        logging.debug(f"Port {port} closed (no response).")
    elif TCP in resp and resp[TCP].flags & 0x04:
        logging.debug(f"Port {port} closed (RST flag).")
    elif TCP in resp and resp[TCP].flags & 0x12:
        logging.info(f"Port {port} is open.")
        print(f"Port {port} is open.")
    else:
        logging.debug(f"Port {port} status is uncertain or filtered.")


def main():
    """
    Runs a SYN scan on a range of ports from START_PORT to END_PORT on
    the TARGET_IP. It logs and prints the status of open ports.
    """
    open_ports = []
    for port in range(START_PORT, END_PORT + 1):
        open_ports.append(port) if syn_scan(TARGET_IP, port) else None

    if not open_ports:
        logging.info("No available ports open.")
        print("No available ports open.")


if __name__ == "__main__":
    """
    Ensure the input constants are valid, then runs the main function to
    start the port scan.
    """
    assert isinstance(TARGET_IP, str), "TARGET_IP must be a string."
    assert isinstance(START_PORT, int), "START_PORT must be an integer."
    assert isinstance(END_PORT, int), "END_PORT must be an integer."
    assert START_PORT > 0, "START_PORT must be greater than 0."
    assert END_PORT >= START_PORT, "END_PORT must be greater than or equal to START_PORT."
    assert isinstance(TIMEOUT, (int, float)), "TIMEOUT must be an integer or float."
    main()
