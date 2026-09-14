import socket
import sys
import time

# Deliberately attempts an outbound connection during "offline" analysis,
# to test BlueLine's network-activity monitoring. Connects to a
# loopback port that a real attacker-controlled fixture would substitute
# with something real; here it's just used to prove detection works.
def main():
    sys.stdin.buffer.read()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 54329))
        time.sleep(0.2)
        s.close()
    except OSError:
        pass  # no listener needed for the *attempt* itself in some test runs
    print("done")

if __name__ == "__main__":
    main()
