#!/usr/bin/env python3
"""Headless controller client for pcble2gamepad's Classic HID backend.

Speaks the backend's JSON socket protocol directly (replaces the GUI).
Socket: /run/pcble2gamepad/<uid>/pro.sock
Methods: input {buttons:[3], sticks:[4]}, release, stop, reconnect, status.
The backend auto-neutrals 500 ms after the last frame; press() re-sends
a held frame every 100 ms until release.
"""
import json, socket, sys, time, threading

SOCKET = '/run/pcble2gamepad/1000/pro.sock'
NEUTRAL = [2159, 1916, 2070, 2013]

BITS = {
    'A': (0, 0x08), 'B': (0, 0x04), 'X': (0, 0x02), 'Y': (0, 0x01),
    'R': (0, 0x40), 'ZR': (0, 0x80),
    'Minus': (1, 0x01), 'Plus': (1, 0x02), 'RStick': (1, 0x04),
    'LStick': (1, 0x08), 'Home': (1, 0x10), 'Capture': (1, 0x20),
    'D-down': (2, 0x01), 'D-up': (2, 0x02), 'D-right': (2, 0x04),
    'D-left': (2, 0x08), 'L': (2, 0x40), 'ZL': (2, 0x80),
}

class Pro:
    def __init__(self, sock_path=SOCKET):
        self.sock_path = sock_path
        self.buttons = [0, 0, 0]
        self.sticks = list(NEUTRAL)
        self.lock = threading.Lock()
        self.stop_flag = threading.Event()

    def _send(self, request):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(self.sock_path)
        s.sendall((json.dumps(request) + '\n').encode())
        buf = b''
        while not buf.endswith(b'\n'):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf.decode() or '{}')

    def _frame(self):
        return {'version': 1, 'method': 'input',
                'buttons': list(self.buttons), 'sticks': list(self.sticks)}

    def status(self):
        return self._send({'version': 1, 'method': 'status'})

    def _hold_loop(self, duration):
        end = time.time() + duration / 1000.0
        while time.time() < end and not self.stop_flag.is_set():
            self._send(self._frame())
            time.sleep(0.08)

    def press(self, action, duration=100):
        byte, bit = BITS[action]
        with self.lock:
            self.buttons[byte] |= bit
        self._hold_loop(duration)
        with self.lock:
            self.buttons[byte] &= ~bit
        self._send(self._frame())

    def release(self):
        with self.lock:
            self.buttons = [0, 0, 0]
            self.sticks = list(NEUTRAL)
        self._send({'version': 1, 'method': 'release'})

    def stick(self, index, value, duration=100):
        """index 0..3 = LX, LY, RX, RY; value -1..1"""
        center = NEUTRAL[index]
        positive = [1466, 1583, 1414, 1510][index]
        negative = [1517, 1465, 1522, 1531][index]
        with self.lock:
            self.sticks[index] = int(center + value * (positive if value >= 0 else negative))
        self._hold_loop(duration)
        with self.lock:
            self.sticks[index] = center
        self._send(self._frame())

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'status'
    p = Pro()
    if cmd == 'status':
        print(json.dumps(p.status(), indent=1))
    elif cmd == 'press':
        p.press(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 100)
        print('pressed', sys.argv[2])
    elif cmd == 'release':
        p.release(); print('released')
