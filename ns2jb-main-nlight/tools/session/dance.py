#!/usr/bin/env python3
"""Reliable console driver for the pcble2gamepad Classic HID backend.

Single FIFO writer with a lock, verified button byte map (from
input_compose(): byte0=face/R/ZR, byte1=system, byte2=dpad/L/ZL),
atomic press+release, backend lifecycle via run-classic.sh.

Console-side backend stdin protocol (run-classic.sh, non-desktop):
  buttons HEX HEX HEX   - set button bytes (held until release)
  sticks LX LY RX RY    - set stick values
  release               - neutral frame
  status | quit
"""
import subprocess, sys, time, os, fcntl

FIFO = '/tmp/proctl.fifo'
CONSOLE_MAC = 'AC:FA:E4:D5:5A:2B'
ADAPTER = 'hci0'

BUTTONS = {
    'A': (0, 0x08), 'B': (0, 0x04), 'X': (0, 0x02), 'Y': (0, 0x01),
    'R': (0, 0x40), 'ZR': (0, 0x80),
    'Minus': (1, 0x01), 'Plus': (1, 0x02), 'RStick': (1, 0x04),
    'LStick': (1, 0x08), 'Home': (1, 0x10), 'Capture': (1, 0x20),
    'D-down': (2, 0x01), 'D-up': (2, 0x02), 'D-right': (2, 0x04),
    'D-left': (2, 0x08), 'L': (2, 0x40), 'ZL': (2, 0x80),
}


def fifo_write(line):
    """Atomic single-line command to the backend stdin FIFO."""
    fd = os.open(FIFO, os.O_WRONLY | os.O_NONBLOCK)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, (line + '\n').encode())
    finally:
        os.close(fd)


def press(action, hold_ms=180):
    byte, bit = BUTTONS[action]
    fifo_write(f'buttons {bit} 0 0' if byte == 0 else
               f'buttons 0 {bit} 0' if byte == 1 else
               f'buttons 0 0 {bit}')
    time.sleep(hold_ms / 1000.0)
    fifo_write('release')
    time.sleep(0.12)


def hold_frames(action, seconds):
    """Hold a button for a duration (re-sends to defeat auto-neutral)."""
    byte, bit = BUTTONS[action]
    line = (f'buttons {bit} 0 0' if byte == 0 else
            f'buttons 0 {bit} 0' if byte == 1 else
            f'buttons 0 0 {bit}')
    end = time.time() + seconds
    while time.time() < end:
        fifo_write(line)
        time.sleep(0.25)
    fifo_write('release')


def stick(index, value, hold_ms=250):
    center = [2159, 1916, 2070, 2013][index]
    pos = [1466, 1583, 1414, 1510][index]
    neg = [1517, 1465, 1522, 1531][index]
    v = int(center + value * (pos if value >= 0 else neg))
    s = [2159, 1916, 2070, 2013]
    s[index] = v
    fifo_write(f'sticks {s[0]} {s[1]} {s[2]} {s[3]}')
    time.sleep(hold_ms / 1000.0)
    fifo_write('release')
    time.sleep(0.12)


def backend_alive():
    out = subprocess.run(['pgrep', '-f', 'pcble2gamepad-controller-backend'],
                         capture_output=True, text=True)
    return out.returncode == 0


def backend_restart():
    """Restart the backend in reconnect mode with a fresh FIFO."""
    subprocess.run(['sudo', '-n', 'pkill', '-9', '-f', 'run-classic'],
                   capture_output=True)
    subprocess.run(['sudo', '-n', 'pkill', '-9', '-f',
                    'pcble2gamepad-controller-backend'], capture_output=True)
    time.sleep(3)
    subprocess.run(['bash', '-c',
                    f'rm -f {FIFO} && mkfifo {FIFO} && '
                    f'(sleep infinity > {FIFO} &) && '
                    f'sudo -n /usr/local/libexec/pcble2gamepad/run-classic.sh '
                    f'{ADAPTER} --reconnect {CONSOLE_MAC} --profile pro '
                    f'< {FIFO} > /tmp/pro-backend-auto.log 2>&1 &'],
                   capture_output=True)
    time.sleep(8)


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'help'
    if cmd == 'backend-restart':
        backend_restart(); print('backend restarted')
    elif cmd == 'backend-status':
        print('alive' if backend_alive() else 'dead')
    elif cmd == 'press':
        press(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 180)
        print('pressed', sys.argv[2])
    elif cmd == 'hold':
        hold_frames(sys.argv[2], float(sys.argv[3]))
        print('held', sys.argv[2])
    elif cmd == 'help':
        print(__doc__)
