import logging
import socket
import binascii

logger = logging.getLogger(__name__)

class GdbServer(object):
   
    class __raii(object):
        def __init__(self, gdbs):
            self.gdbs = gdbs
            
        def __enter__(self):
            return self
        
        def __exit__(self, exc_type, exc_value, traceback):
            self.gdbs.close()

   
    def __init__(self, host_port, max_packet_size = 4096):
        self.srv_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv_s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, max_packet_size * 2)
        self.srv_s.bind(host_port)
        self.s = None
    
    def close(self):
        if self.s is not None:
            logger.info("Closing connection")
            self.s.close()
            self.s = None
        if self.srv_s is not None:
            self.srv_s.close()
            self.srv_s = None

    def is_closed(self):
        return self.srv_s is None;

    def wait_connection(self):
        if self.srv_s is None:
            raise Exception("GdbServer has been closed")

        self.srv_s.listen(1)
        (self.s, gdb_addr) = self.srv_s.accept()        
        logger.info("Received connected from %s", gdb_addr)
        
        return self.__raii(self) 

    def _read_packet(self):
        if self.srv_s is None:
            return None

        WAIT_SOP = 0
        WAIT_EOP = 1
    
        state = WAIT_SOP
        packet = b""
        
        while True:
       
            c = self.s.recv(1)

            if len(c) != 1:
                self.close()
                return None

            if state == WAIT_SOP:
                if c == b'$':
                    state = WAIT_EOP
                elif c == b'\x03':
                    logger.debug("received Ctrl+C")
                    return c

            elif state == WAIT_EOP:
                if c == b'#':
                    packet_csum = self.s.recv(2)
                    if len(packet_csum) == 0:
                        return b""
                    else:
                        csum = sum(packet) & 0xff
                        if csum == int.from_bytes(binascii.unhexlify(packet_csum)):
                            return packet.decode()
                        else:
                            logger.error("Invalid checksum")
                            packet = b""
                            csum = 0
                            state = WAIT_SOP
                else:
                    packet += c


    def wait_packet(self):
        try:
            packet = self._read_packet()
            if packet is not None:
                logger.debug("received %r", packet)
                # acknowledge
                self.s.send(b'+')
            return packet
        except socket.error as e:
            logger.error("%s", e)
            self.close()
            return None

    def should_break(self):
        try:
            self.s.setblocking(False)
            c = self.s.recv(1, socket.MSG_PEEK)

            if c == b'\x03':
                logger.debug("Received Ctrl+C")
                self.s.recv(1)
                return True 
        except socket.error as e:
            if e.errno != socket.errno.EAGAIN and e.errno != socket.errno.EWOULDBLOCK:
                logger.error("%s", e)
        finally:
            self.s.setblocking(True)

        return False

    def send_reply(self, reply):
        logger.debug("send(%r)", reply)
        try:
            brep = reply.encode()
            csum = sum(brep) & 0xff
            self.s.send(b'$')
            self.s.send(brep)
            self.s.send(b'#')
            self.s.send(binascii.hexlify(csum.to_bytes(1)))
        except socket.error as e:
            logger.error("%s", e)
            self.s.close()


                