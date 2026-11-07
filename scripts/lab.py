"""Generate the reference PCAP or replay the same case on Ubuntu loopback."""
import argparse
import io
import socket
import struct
import threading
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT = socket.inet_aton("192.0.2.10")
SERVER = socket.inet_aton("192.0.2.20")
PORT = 8080


def archive():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as output:
        output.writestr(zipfile.ZipInfo("inventory.txt"), "LAB ONLY\nasset=demo-01\n")
    return buffer.getvalue()


def transaction(method, path, status, body, content_type="text/plain", form=b"", headers=""):
    request = f"{method} {path} HTTP/1.1\r\nHost: portal.test:8080\r\nConnection: close\r\n"
    if form:
        request += f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(form)}\r\n"
    response = (
        f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n{headers}\r\n"
    )
    return (request + "\r\n").encode() + form, response.encode() + body


def case():
    return [
        transaction("GET", "/health", "200 OK", b"ok\n"),
        *[
            transaction("POST", "/login", "401 Unauthorized", b"denied\n",
                        form=f"user=lab-analyst&password=fake-wrong-{attempt}".encode(),
                        headers='WWW-Authenticate: Basic realm="lab"\r\n')
            for attempt in range(1, 4)
        ],
        transaction("POST", "/login", "200 OK", b"demo login accepted\n",
                    form=b"user=lab-analyst&password=fake-correct",
                    headers="Set-Cookie: lab_session=demo; HttpOnly\r\n"),
        transaction("GET", "/exports/inventory.zip", "200 OK", archive(), "application/zip",
                    headers='Content-Disposition: attachment; filename="inventory.zip"\r\n'),
        transaction("GET", "/exports/payroll.zip", "404 Not Found", b"missing\n"),
    ]


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def frame(number, reverse, client_port, seq, ack, flags, data):
    client_mac = bytes.fromhex("020000000010")
    server_mac = bytes.fromhex("020000000020")
    src, dst, sport, dport = CLIENT, SERVER, client_port, PORT
    src_mac, dst_mac = client_mac, server_mac
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
        src_mac, dst_mac = dst_mac, src_mac
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(data))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + data)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(data), number, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return (dst_mac + src_mac + b"\x08\x00" + ip + tcp + data).ljust(60, b"\0")


def reference():
    with (ROOT / "captures/reference.pcap").open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, (request, response) in enumerate(case()):
            client = 10000 + index * 1000
            server = 90000 + index * 1000
            c_end = client + 1 + len(request)
            s_end = server + 1 + len(response)
            segments = [
                (False, client, 0, 0x02, b""),
                (True, server, client + 1, 0x12, b""),
                (False, client + 1, server + 1, 0x10, b""),
                (False, client + 1, server + 1, 0x18, request),
                (True, server + 1, c_end, 0x18, response),
                (False, c_end, s_end, 0x10, b""),
                (True, s_end, c_end, 0x11, b""),
                (False, c_end, s_end + 1, 0x11, b""),
                (True, s_end + 1, c_end + 1, 0x10, b""),
            ]
            for offset, segment in enumerate(segments):
                reverse, seq, ack, flags, data = segment
                packet = frame(index * 9 + offset + 1, reverse, 49152 + index, seq, ack, flags, data)
                capture.write(struct.pack("<IIII", 1794045600 + index * 2, offset * 10000,
                                          len(packet), len(packet)))
                capture.write(packet)
    (ROOT / "evidence/reference-inventory.zip").write_bytes(archive())


def replay():
    with socket.socket() as listener:
        listener.settimeout(5)
        listener.bind(("127.0.0.1", PORT))
        listener.listen()
        for request, response in case():
            result = []

            def client():
                with socket.create_connection(("127.0.0.1", PORT), timeout=5) as connection:
                    connection.sendall(request)
                    result.append(connection.makefile("rb").read())

            worker = threading.Thread(target=client)
            worker.start()
            with listener.accept()[0] as connection:
                connection.settimeout(5)
                received = bytearray()
                while len(received) < len(request):
                    chunk = connection.recv(len(request) - len(received))
                    if not chunk:
                        raise RuntimeError("Client closed before sending the full request")
                    received.extend(chunk)
                if received != request:
                    raise RuntimeError("Unexpected lab request")
                connection.sendall(response)
            worker.join()
            if result != [response]:
                raise RuntimeError("Unexpected lab response")
            print(request.split(b"\r\n")[0].decode(), "->", response.split(b"\r\n")[0].decode())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["reference", "replay"])
    args = parser.parse_args()
    if args.mode == "reference":
        reference()
    else:
        replay()
