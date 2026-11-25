#!/usr/bin/env python3
"""TCP to STDIO bridge for PepperSpray MCP server in Docker"""
import socket
import subprocess
import threading
import os
import sys

BRIDGE_PORT = int(os.environ.get('MCP_BRIDGE_PORT', 5000))
PEPPERSPRAY_SERVER = os.environ.get('PEPPERSPRAY_SERVER', 'http://localhost:8888')

def handle_client(client_socket, client_addr):
    """Forward TCP connection to MCP stdio"""
    print(f"[+] Handling connection from {client_addr[0]}:{client_addr[1]}")

    try:
        mcp_process = subprocess.Popen(
            ['python3', 'pepperspray_mcp.py', '--server', PEPPERSPRAY_SERVER],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0
        )

        def forward_to_mcp():
            """Forward data from TCP socket to MCP process stdin"""
            try:
                while True:
                    data = client_socket.recv(8192)
                    if not data:
                        break
                    mcp_process.stdin.write(data)
                    mcp_process.stdin.flush()
            except Exception as e:
                print(f"[-] Error forwarding to MCP: {e}", file=sys.stderr)
            finally:
                try:
                    mcp_process.stdin.close()
                except:
                    pass

        def forward_from_mcp():
            """Forward data from MCP process stdout to TCP socket"""
            try:
                while True:
                    data = mcp_process.stdout.read(8192)
                    if not data:
                        break
                    client_socket.sendall(data)
            except Exception as e:
                print(f"[-] Error forwarding from MCP: {e}", file=sys.stderr)
            finally:
                try:
                    client_socket.close()
                except:
                    pass

        def forward_stderr_from_mcp():
            """Forward data from MCP process stderr to bridge stderr"""
            try:
                # Use read(1) or small chunks to avoid missing data, or iter with readline
                while True:
                    data = mcp_process.stderr.read(4096)
                    if not data:
                        break
                    sys.stderr.buffer.write(data)
                    sys.stderr.buffer.flush()
            except Exception as e:
                print(f"[-] Error forwarding stderr from MCP: {e}", file=sys.stderr)

        # Start forwarding threads
        t1 = threading.Thread(target=forward_to_mcp, daemon=True)
        t2 = threading.Thread(target=forward_from_mcp, daemon=True)
        t3 = threading.Thread(target=forward_stderr_from_mcp, daemon=True)
        t1.start()
        t2.start()
        t3.start()

        # Wait for both communication threads to complete
        t1.join()
        t2.join()
        # t3 is daemon and will exit with the process

        # Cleanup
        mcp_process.wait()
        print(f"[-] Connection from {client_addr[0]}:{client_addr[1]} closed")

    except Exception as e:
        print(f"[-] Error handling client: {e}", file=sys.stderr)
    finally:
        try:
            client_socket.close()
        except:
            pass

def main():
    """Start TCP server and listen for MCP connections"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', BRIDGE_PORT))
    server.listen(10)

    print(f"[+] TCP-STDIO Bridge listening on 0.0.0.0:{BRIDGE_PORT}")
    print(f"[+] Forwarding to PepperSpray server: {PEPPERSPRAY_SERVER}")
    print("[+] Ready for MCP connections")

    try:
        while True:
            client, addr = server.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(client, addr),
                daemon=True
            )
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[-] Shutting down bridge...")
    except Exception as e:
        print(f"[-] Server error: {e}", file=sys.stderr)
    finally:
        server.close()

if __name__ == '__main__':
    main()
