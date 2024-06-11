#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading
# NOTE: Do not import any other modules - the ones above should be sufficient

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=2, count=10)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=2, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: bytes) -> int:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, seq: int, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationHostname, destinationAddress, seq, ttl, time))
        else:
            print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationAddress, seq, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printOneTraceRouteIteration(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):

        # 1. Wait for the socket to receive a reply
        # 2. If reply received, record time of receipt, otherwise, handle timeout
        # 3. Unpack the imcp and ip headers for useful information, including Identifier, TTL, sequence number 
        # 5. Check that the Identifier (ID) matches between the request and reply
        # 6. Return time of receipt, TTL, packetSize, sequence number
    #set socket timeout

        pass

    def sendOnePing(self, icmpSocket, destinationAddress, ID):

       

        # 1. Build ICMP header
        # 2. Checksum ICMP packet using given function
        # 3. Insert checksum into packet
        # 4. Send packet using socket
        # 5. Return time of sending

       
        
        pass

    def doOnePing(self, destinationAddress, packetID, seq_num, timeout):
        # 1. Create ICMP socket
        # 2. Call sendOnePing function
        # 3. Call receiveOnePing function
        # 4. Close ICMP socket
        # 5. Print out the delay (and other relevant details) using the printOneResult method, below is just an example.

        pass

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        # 2. Repeat below args.count times
        # 3. Call doOnePing function, approximately every second, below is just an example
        self.doOnePing('1.1.1.1', 0, 0, 2)

class Traceroute(NetworkApplication):

    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))

        icmp = socket.getprotobyname("icmp")
        udp = socket.getprotobyname("udp")

        ttl = 1
        ips = []
        lost_packets = 0
        port = 8989
        max_hops = 30

        
        delay_first = []
        delay_second = []
        delay_third = []

        all_delay = []

        seq = 0

        while True:
        #creating udp and icmp socket 
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        #ttl value is set to the socket
            udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        #timeout is set to the socket
            udp_socket.settimeout(args.timeout)

        #create a raw socket for sending and receiving icmp packets
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            icmp_socket.settimeout(args.timeout)
        #bind udp socket to local port
            udp_socket.bind(("", port))
            # Send three empty UDP packets to the target host with the given TTL
            start_time = time.time()
            for i in range(3):
                udp_socket.sendto(b"", (args.hostname, port))
        
            try:
                #receive three icmp time exceeded messages
                for i in range(3):
                    data, addr = icmp_socket.recvfrom(1024)
                    seq += 1
                    ips.append(addr[0])
                    rtt = (time.time() - start_time) * 1000
                    #store rtt measurements directly in the lists
                    if i == 0:
                        delay_first.append(rtt)
                    elif i == 1:
                        delay_second.append(rtt)
                    elif i == 2:
                        delay_third.append(rtt)

                    
                    if i == 2:
                        measurements = [delay_first[-1], delay_second[-1], delay_third[-1]]
                        try:
                            hostname = socket.gethostbyaddr(addr[0])[0]
                        except socket.herror:
                            hostname = 'Unknown Hostname'
                        self.printOneTraceRouteIteration(ttl, addr[0], measurements, hostname)
                
                #reset time for next measurement
                start_time = time.time()

                #check for destination unreachable message and handling remains unchanged
                if struct.unpack("B", data[20:21])[0] == 3:
                    
                    packet_length = len(data)
                    self.printOneResult(addr[0],packet_length,rtt,seq,ttl+1,args.hostname)

                    break
            except socket.timeout:
                #timeout handling
                print(f"{ttl}: *request timed out*")
            finally:
                udp_socket.close()
                icmp_socket.close()

            ttl += 1
            if ttl > max_hops:
                print("Maximum number of hops reached")
                break

        #packet loss calculation
        packet_loss = lost_packets / max_hops * 100

        #calculate the sum and average of delays
        sum_of_first_delay = sum(delay_first)
        sum_of_second_delay = sum(delay_second)
        sum_of_third_delay = sum(delay_third)

        all_delay.extend([sum_of_first_delay, sum_of_second_delay, sum_of_third_delay])

        average_delay = sum(all_delay) / len(all_delay)
        minimum_delay = min(all_delay)
        maximum_delay = max(all_delay)

        self.printAdditionalDetails(packet_loss, minimum_delay, average_delay, maximum_delay)

class WebServer(NetworkApplication):

    def handleRequest(tcpSocket):
        # 1. Receive request message from the client on connection socket
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        # 7. Close the connection socket
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        # 2. Bind the server socket to server address and server port
        # 3. Continuously listen for connections to server socket
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        # 5. Close server socket


class Proxy(NetworkApplication):

    def __init__(self, args):

        print('Web Proxy starting on port: %i...' % (args.port))

        #creating proxy socket
        proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #binding the proxy socket to local host and server port
        proxy.bind(('localhost', args.port))

        #isten for connections to server socket
        proxy.listen(1)

        while True:

            #when a connection is accepted, call handlerequest function and passing new connection socket
            client_socket, client_address = proxy.accept()
            print(f"Received connection from {client_address[0]}:{client_address[1]}")

            request = client_socket.recv(4096)
            request_lines = request.decode().split("\r\n")
            method, request_line = request_lines[0].split(maxsplit=1)
            url = request_line.split()[0]
            print(f"Request received: {method} {url}")

            #extracting the hostname from the url
            hostname = url.split('/')[2] if len(url.split('/')) > 2 else ''

            #forward the request to the server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((hostname, 80))
            server_socket.send(request)

            #receive the server response
            response = server_socket.recv(4096)

            #forward the response to the client
            client_socket.send(response)

            #close server socket
            server_socket.close()
            client_socket.close()


# Do not delete or modify the code below
if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
