import ssl, socket, logging, threading, time

logging.basicConfig(filename="proxy.log", level=logging.DEBUG, format="%(asctime)s - %(message)s")
# ssl.create_default_context(purpose=Purpose.SERVER_AUTH, cafile=None, capath=None, cadata=None)
# In server mode, if you want to authenticate your clients using the SSL layer you’ll also have to specify CERT_REQUIRED
# and similarly check the client certificate. Passing SERVER_AUTH as purpose sets verify_mode to CERT_REQUIRED.
context = ssl.create_default_context(cafile="ca.crt")
context.load_cert_chain(certfile="server.crt", keyfile="server.key")
# hostname don`t match with hostname in cert.
context.check_hostname = False
# Load the key generation parameters for Diffie-Helman (DH) key exchange. This setting doesn’t apply to client sockets.
context.load_dh_params("dh.pem")

bindsocket = socket.socket()
bindsocket.bind(("", 7788))
bindsocket.settimeout(5)
bindsocket.listen(10)
lock = threading.Lock()
event = threading.Event()
clients = {}

class ProxySocket(threading.Thread):
    def __init__(self):
        super().__init__(daemon = True)
        self.running = True

    def stop(self):
        self.running = False

    def run(self):
        logging.critical("Start proxy")
        while self.running:
            try:
                newsocket, fromaddr = bindsocket.accept()
                print(newsocket)
            except socket.timeout:
                continue
            sslsocket = False
            try:
                sslsocket = context.wrap_socket(newsocket, server_side=True)
                #sslsocket = newsocket
                sslsocket.settimeout(5)
                logging.critical("New connection: " + str(fromaddr))
            except (ssl.SSLError, ConnectionResetError) as e:
                logging.critical(str(fromaddr) + " " + str(e))
            if sslsocket:
                name = fromaddr[0] + ":" + str(fromaddr[1])
                # for every host own worker
                clients[name] = Client(sslsocket)
                clients[name].start()
        logging.critical("Stop proxy")

class Client(threading.Thread):
    def __init__(self, conn):
        super().__init__(daemon = True)
        self.running = True
        self.s_socket = conn
        self.ip, self.port = conn.getpeername()
        self.name = self.ip + ":" + str(self.port)
        self.log_msg = "Client " + self.name
        self.crypto = False

    def stop(self):
        self.running = False

    def connect(self):
        self.server = Server(self)
        self.server.start()

    def run(self):
        logging.critical(self.log_msg + " Start")
        self.connect()
        while not event.is_set():
            time.sleep(1)
        while self.running:
            try:
                data = self.s_socket.recv(1024)
                if data:
                    logging.critical(self.log_msg + " > " + str(data))
                    self.server.d_socket.send(data)
                else:
                    logging.critical(self.log_msg + ' empty message')
                    self.running = False
            except socket.timeout:
                continue
            except Exception as e:
                logging.critical(str(e), exc_info=True)
                self.running = False
        # deleting worker from list of workers
        del clients[self.ip + ":" + str(self.port)]
        self.server.running = False
        self.s_socket.shutdown(socket.SHUT_RDWR)
        self.s_socket.close()
        logging.critical(self.log_msg + " close connection")

class Server(threading.Thread):
    def __init__(self, parent):
        super().__init__(daemon = True)
        self.parent = parent
        self.running = True
        self.log_msg = "Server " + parent.name
        self.dest_host = '' # server
        self.dest_port = 3333

    def stop(self):
        self.running = False

    def connect(self):
        logging.critical("%s connect to %s:%d" % (self.log_msg,self.dest_host,self.dest_port))
        self.d_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.d_socket.connect((self.dest_host, self.dest_port))
        self.d_socket.settimeout(5)
        event.set()

    def run(self):
        logging.critical(self.log_msg + " Start")
        try:
            self.connect()
        except:
            self.running = False
        while self.running:
            try:
                data = self.d_socket.recv(1024)
                if data:
                    logging.critical(self.log_msg + " < " + str(data))
                    self.parent.s_socket.send(data)
                else:
                    logging.critical(self.log_msg + ' Empty message')
                    self.running = False
            except socket.timeout:
                continue
            except Exception as e:
                logging.critical(str(e), exc_info=True)
                self.running = False
        self.parent.running = False
        event.clear()
        self.d_socket.shutdown(socket.SHUT_RDWR)
        self.d_socket.close()
        logging.critical(self.log_msg + " Close connection")

proxy = ProxySocket()
proxy.start()
while True:
    time.sleep(5)