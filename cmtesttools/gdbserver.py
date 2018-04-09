import logging
import socket

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
        csum = 0
        packet = ""
        
        while True:
       
            c = self.s.recv(1)

            if len(c) != 1:
                self.close()
                return None

            if state == WAIT_SOP:
                if c == "$":
                    state = WAIT_EOP
                elif c == "\x03":
                    logger.debug("received Ctrl+C")
                    return c

            elif state == WAIT_EOP:
                if c == "#":
                    packet_csum_str = self.s.recv(2)
                    if len(packet_csum_str) == 0:
                        return ""
                    else:
                        if csum == int(packet_csum_str, 16):
                            return packet
                        else:
                            logger.error("Invalid checksum")
                            packet = ""
                            csum = 0
                            state = WAIT_SOP
                else:
                    packet += c
                    csum = (csum + ord(c)) & 0xff


    def wait_packet(self):
        try:
            packet = self._read_packet()
            if packet is not None:
                logger.debug("received %r", packet)
                # acknowledge
                self.s.send("+")
            return packet
        except socket.error as e:
            logger.error("%s", e)
            self.close()
            return None

    def should_break(self):
        try:
            c = self.s.recv(1, socket.MSG_DONTWAIT | socket.MSG_PEEK)
            if c == "\x03":
                logger.debug("Received Ctrl+C")
                self.s.recv(1)
                return True 
        except socket.error as e:
            if e.errno != socket.errno.EAGAIN and e.errno != socket.errno.EWOULDBLOCK:
                logger.error("%s", e)
        return False

    def send_reply(self, reply):
        def checksum(data):
            checksum = 0
            for c in data:
                checksum += ord(c)
            return checksum & 0xff        

        logger.debug("send(%r)", reply)
        try:
            self.s.send('$%s#%.2x' % (reply, checksum(reply)))
        except socket.error as e:
            logger.error("%s", e)
            self.s.close()


                