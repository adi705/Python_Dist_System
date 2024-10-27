#!/usr/bin/env python3
import argparse
import json
import re
import signal
import socket
import socketserver
import threading
import os  # Import os to work with file paths

from hashlib import sha1
from http.server import BaseHTTPRequestHandler,HTTPServer

# Initialize the object store and a lock for thread-safe access
object_store = {}
object_store_lock = threading.Lock()

# Initialize the Chord ring and relevant constants
ring = []
M = 10   # Number of bits for the hash
RING_SIZE = pow(2,M) # Total size of the ring

# Dynamically set the NODEFILE path based on the script's directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # Get the directory of the current script
NODEFILE = os.path.join(SCRIPT_DIR, 'nodes.txt')  # Construct the path to nodes.txt
#NODEFILE = 'apo042/src/nodes.txt' # File containing node addresses




class NodeHttpHandler(BaseHTTPRequestHandler):
   # Handle HTTP requests for the Chord node
    def send_whole_response(self, code, content, content_type="text/plain"):
    # Helper method to send a complete HTTP response
        if isinstance(content, str):
            
            content = content.encode("utf-8")
            if not content_type:
                content_type = "text/plain"
            if content_type.startswith("text/"):
                content_type += "; charset=utf-8"
        elif isinstance(content, bytes):
            
            if not content_type:
                content_type = "application/octet-stream"
        elif isinstance(content, object):
            
            content = json.dumps(content, indent=2)
            content += "\n"
            content = content.encode("utf-8")
            content_type = "application/json"

        self.send_response(code)
        self.send_header('Content-type', content_type)
        self.send_header('Content-length',len(content))
        self.end_headers()
       
        self.wfile.write(content)

    def extract_key_from_path(self, path):
        return re.sub(r'/storage/?(\w+)', r'\1', path)

    def n_in_range(self, n, start, stop):
        # Checks if n is in the range [start, stop] on the Chord ring
        if start < stop:
            return True if start < n <= stop else False
        else:
            return True if start < n or n <= stop else False
                
    def closest_preceding_node(self, id):
        # Finds the closest preceding node in the finger table for a given id

        for i in range(M-1, -1, -1):
            if self.n_in_range(fingers[i]['hash'], cur_node['hash'], id):
                return fingers[i]['addr']
        return cur_node['addr']

    def find_successor(self, id):
        # Finds the successor node for a given id
        successor = fingers[0]

        if self.n_in_range(id, cur_node['hash'], successor['hash']):
            return successor['addr']
        else:
            return self.closest_preceding_node(id)
              

    def do_PUT(self):
        # Handles HTTP PUT requests to store a key-value pair
        content_length = int(self.headers.get('content-length', 0))

        key = self.extract_key_from_path(self.path)
        value = self.rfile.read(content_length)

        id = int(sha1(key.encode()).hexdigest(), 16) % RING_SIZE
        # If we arrived at correct node
        if self.n_in_range(id, neighbors[0]['hash'], cur_node['hash']):
            with object_store_lock:
                object_store[key] = value

            # Send OK response
            self.send_whole_response(200, "Value stored for " + key)

        # Forward request using finger table
        else:
            forward_address = self.find_successor(id).split(':')

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((forward_address[0], int(forward_address[1])))
                    s.sendall(f"PUT /storage/{key} HTTP/1.1\r\n".encode())
                    s.sendall(f"Content-Length: {content_length}\r\n".encode())
                    s.sendall(b"\r\n")
                    s.sendall(value)
                    
                    res = s.recv(4096).decode()
                    s.close()
                

                # Forward the response to the original client
                self.send_response(int(res.split()[1]))
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(res.encode())
            except Exception as e:
                self.send_whole_response(500, f"Error forwarding request to successor: {str(e)}")   

    def do_GET(self):
        
        # Handles HTTP GET requests to retrieve a value for a given key
        if self.path.startswith("/storage"):
            key = self.extract_key_from_path(self.path)

            id = int(sha1(key.encode()).hexdigest(), 16) % RING_SIZE

            # Key is on this node
            if self.n_in_range(id, neighbors[0]['hash'], cur_node['hash']):
                with object_store_lock:
                    have_key = key in object_store
                    value = object_store[key] if have_key else None

                if have_key:
                    self.send_whole_response(200, value)
                else:
                    self.send_whole_response(404, "No object with key '%s' on this node" % key)
            
            # Forward request
            else:

                forward_address = self.find_successor(id).split(':')

                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        
                        s.connect((forward_address[0], int(forward_address[1])))
                        s.sendall(f"GET /storage/{key} HTTP/1.1\r\n".encode())                        
                        s.sendall(b"\r\n")
                        
                        forward_response = ""  # Initialize an empty string to store the response

                        # Receive data in chunks of 4096 bytes
                        while True:
                            data = s.recv(4096)
                            if not data:
                                break  # Break the loop if no more data
                            forward_response += data.decode()  # Append received data to the response

                        s.close()

                    self.send_response(int(forward_response.split()[1]))
                    self.wfile.write(forward_response.encode())

                except Exception as e:
                    self.send_whole_response(500, f"Error forwarding request to successor: {str(e)}")



        elif self.path.startswith("/neighbors"):
            neighbor_addresses = [node['addr'] for node in neighbors]
            print(neighbor_addresses)
            self.send_whole_response(200, neighbor_addresses)
            print("OK")

        elif self.path == "/network":
            # Return all nodes in the network
            all_nodes = [node['addr'] for node in ring]  # Extract addresses of all nodes from `ring`
            
            # Send the response as JSON
            self.send_whole_response(200, all_nodes, content_type="application/json")    

        else:
            self.send_whole_response(404, "Unknown path: " + self.path)

def arg_parser():
    # Command-line argument parser for the node
    PORT_DEFAULT = 8000
    DIE_AFTER_SECONDS_DEFAULT = 20 * 60
    parser = argparse.ArgumentParser(prog="node", description="DHT Node")

    parser.add_argument("-p", "--port", type=int, default=PORT_DEFAULT,
            help="port number to listen on, default %d" % PORT_DEFAULT)

    parser.add_argument("--die-after-seconds", type=float,
            default=DIE_AFTER_SECONDS_DEFAULT,
            help="kill server after so many seconds have elapsed, " +
                "in case we forget or fail to kill it, " +
                "default %d (%d minutes)" % (DIE_AFTER_SECONDS_DEFAULT, DIE_AFTER_SECONDS_DEFAULT/60))

    parser.add_argument("neighbors", type=str, nargs="*",
            help="addresses (host:port) of neighbour nodes")

    return parser

class ThreadingHttpServer(HTTPServer, socketserver.ThreadingMixIn):
    pass

def initialize_finger_table(cur_addr):
    # Initializes the finger table and neighbors for the current node
    global ring  # Use the global `ring` variable to store all nodes
    neighbors = []
    fingers = []
    cur_node = {}

    
    # Read node addresses from the specified file
    with open(NODEFILE, 'r') as f:
        for addr in f.readlines():
            addr = addr.strip()
            if addr:
                node_hash = int(sha1(addr.encode()).hexdigest(), 16) % RING_SIZE
                ring.append({'addr': addr, 'hash': node_hash})

    ring.sort(key=lambda a : a['hash']) # Sort the ring based on hash values

    #print("Ring:")
    #print(json.dumps(ring, indent=2))
    # print()

    for i in range(len(ring)):
        node = ring[i]
        if node['addr'] == cur_addr:
            cur_node = node.copy()
            neighbors.append(ring[(i-1) % len(ring)])
            neighbors.append(ring[(i+1) % len(ring)])
            print("Current Node Found:")
            print(cur_node)  # Debug print for cur_node

    # Check if cur_node is set correctly
    if not cur_node:
        print(f"Warning: Current address {cur_addr} not found in ring.")
        raise ValueError("Current address not found in the ring.")

    # Initialize fingers with successors
    for i in range(M):

        finger_nr = (cur_node['hash'] + pow(2,i)) % RING_SIZE

        hash_values = lambda l : [a['hash'] for a in l]  

        while finger_nr not in hash_values(ring):
            finger_nr = (finger_nr + 1) % RING_SIZE
        
        index = [j for j in range(len(ring)) if ring[j]['hash'] == finger_nr][0]
        fingers.append(ring[index])

    return fingers, cur_node, neighbors

def run_server(args):
    global server
    global neighbors
    global fingers
    global cur_node
    server = ThreadingHttpServer(('', args.port), NodeHttpHandler)

    fingers, cur_node, neighbors = initialize_finger_table(f'{server.server_name}:{args.port}')

    # print("Finger table:")
    # print(json.dumps(fingers, indent=2))
    # print("\nNeighbors:")
    # print(neighbors)
    # print()
    # print(cur_node)

    def server_main():
        print("Starting server on port {}. Neighbors: {}".format(args.port, neighbors))
        print()
        server.serve_forever()
        print("Server has shut down")

    def shutdown_server_on_signal(signum, frame):
        print("We get signal (%s). Asking server to shut down" % signum)
        if thread.is_alive():
            server.shutdown()
        server.shutdown()

    # Start server in a new thread, because server HTTPServer.serve_forever()
    # and HTTPServer.shutdown() must be called from separate threads
    thread = threading.Thread(target=server_main)
    thread.daemon = True
    thread.start()

    # Shut down on kill (SIGTERM) and Ctrl-C (SIGINT)
    signal.signal(signal.SIGTERM, shutdown_server_on_signal)
    signal.signal(signal.SIGINT, shutdown_server_on_signal)

    # Wait on server thread, until timeout has elapsed
    #
    # Note: The timeout parameter here is also important for catching OS
    # signals, so do not remove it.
    #
    # Having a timeout to check for keeps the waiting thread active enough to
    # check for signals too. Without it, the waiting thread will block so
    # completely that it won't respond to Ctrl-C or SIGTERM. You'll only be
    # able to kill it with kill -9.
    thread.join(args.die_after_seconds)
    if thread.is_alive():
        print("Reached %.3f second timeout. Asking server to shut down" % args.die_after_seconds)
        server.shutdown()

    print("Exited cleanly")

if __name__ == "__main__":

    parser = arg_parser()
    args = parser.parse_args()
    run_server(args)

