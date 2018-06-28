import ssl, socket, logging, threading, time, json, copy, sys
import urllib.parse as urlparse
import socks

USER_AGENT = "NightProxy"
VERSION = [0, 1]

logging.basicConfig(filename="stratum_proxy.log", level=logging.INFO, format="%(asctime)s - %(message)s")
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
bindsocket.settimeout(1)
bindsocket.listen(10)
lock = threading.Lock()
server_connect = threading.Event()
server_ready = threading.Event()
clients = {}
extranounce2_list = []
subscription_reply = {}
notify_reply = {}
difficulty_reply = {}
worker_name = ''

class ProxySocket(threading.Thread):
    def __init__(self):
        super().__init__(daemon = True)
        self.running = True
        self.log_msg = "Main: "

    def stop(self):
        self.running = False

    def run(self):
        logging.info(self.log_msg + "start proxy")
        while self.running:
            while server_ready.is_set() and self.running:
                try:
                    newsocket, fromaddr = bindsocket.accept()
                except socket.timeout:
                    continue
                sslsocket = False
                try:
                    sslsocket = context.wrap_socket(newsocket, server_side=True)
                    #sslsocket = newsocket
                    sslsocket.settimeout(5)
                    logging.info(self.log_msg + "new connection: " + str(fromaddr))
                except (ssl.SSLError, ConnectionResetError) as e:
                    logging.error(str(fromaddr) + " " + str(e))
                if sslsocket:
                    name = fromaddr[0] + ":" + str(fromaddr[1])
                    # for every host own worker
                    clients[name] = Client(sslsocket)
                    clients[name].start()
            time.sleep(1)
        logging.info(self.log_msg + "stop proxy")

class Client(threading.Thread):
    def __init__(self, conn):
        super().__init__(daemon = True)
        self.running = True
        self.conn = conn
        self.ip, self.port = conn.getpeername()
        self.name = self.ip + ":" + str(self.port)
        self.log_msg = "Client " + self.name + ": "
        self.extranounce2 = self.get_extranounce2()
        self.accepted_shares = 0
        self.subscribed = False

    def get_extranounce2(self):
        for i in range(0, 0x7fffffff, 10):
            if i not in extranounce2_list:
                extranounce2_list.append(i)
                return i
        return 0

    def stop(self):
        self.running = False

    def send(self, data):
        try:
            self.conn.send((data + '\n').encode('UTF-8'))
            logging.debug(self.log_msg + data)
        except:
            self.running = False
            logging.error(self.log_msg + 'send data connection error')

    def handle_reply(self, request):

        if request.get('method') == 'mining.subscribe':
            _subscription = copy.deepcopy(subscription_reply)
            _subscription['id'] = request.get('id')
            #send subscribe {"id":1,"result":[[["mining.set_difficulty","1"],["mining.notify","46ed43e60de658e75c9c0c280a44279d"]],"8100024a",4],"error":null}
            _subscription['result'].append(self.extranounce2)
            reply = json.dumps(_subscription)
            self.send(reply)

        elif request.get('method') == 'mining.extranonce.subscribe':
            # send {"id":2,"result":true,"error":null}
            reply = '{"id":%s,"result": true,"error": null}' % request.get("id")
            self.send(reply)

        elif request.get('method') == 'mining.authorize':
            # send {"id":3,"result":true,"error":null}
            reply = '{"id":%s,"result": true,"error": null}' % request.get("id")
            self.send(reply)
            # {"id":null,"method":"mining.set_difficulty","params":[1]}
            #self.send('{"id":null,"method":"mining.set_difficulty","params":[1]}')
            reply = json.dumps(difficulty_reply)
            self.send(reply)
            # {"id":null,"method":"mining.notify","params":["7f","67abb7abb1e3468870c474b31edca05b6aa3c6e7389b6b01668a42fa00000051","02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1f0300e803062f503253482f040abf075b08","7969696d7000000000000100ea56fa000000001976a914956ee94d91a4eedc1c6106b6dcf2c90c5077d35888ac00000000",[],"00000002","1e00d9f5","5b07bf0a",true]}
            reply = json.dumps(notify_reply)
            self.send(reply)
            self.subscribed = True

        elif request.get('method') == 'mining.submit':
            # send to the server
            pool.send_message(request['method'],request['params'],self.name)
            # better log after check in Server obj
            #logging.debug(self.log_msg + 'accepted shares: %d' % self.accepted_shares)

    def run(self):
        logging.info(self.log_msg + "start")
        data = ''
        while server_ready.is_set() and self.running:
            if '\n' in data:
                (line, data) = data.split('\n', 1)
            else:
                try:
                    chunk = self.conn.recv(1024).decode('UTF-8')
                    data += chunk
                    if not chunk:
                        logging.error(self.log_msg + 'receive empty data')
                        self.running = False
                except socket.timeout:
                    continue
                except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError) as e:
                    logging.info(self.log_msg + 'connection error')
                    self.running = False
                except Exception as e:
                    logging.error(str(e), exc_info=True)
                    self.running = False
                continue
            logging.debug(self.log_msg + 'JSON-RPC Server > ' + str(line))
            # handle incoming rpc
            try:
                request = json.loads(line)
            except Exception as e:
                logging.error(self.log_msg + 'JSON-RPC Error: Failed to parse JSON %r (skipping)' % line)
                continue
            try:
                self.handle_reply(request=request)
            except Exception as e:
                output = ''
                output += '\n  ' + json.dumps(request)
                logging.error(self.log_msg + output + '\n' + str(e))
        # deleting worker from list of workers
        del clients[self.name]
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
            self.conn.close()
        except:
            pass
        extranounce2_list.remove(self.extranounce2)
        logging.info(self.log_msg + "close connection")

class Server(threading.Thread):
    def __init__(self,hostname,port,username,password):
        super().__init__(daemon = True)
        self.running = True
        self.log_msg = "Proxy "
        self.dest_host = hostname
        self.dest_port = port
        self.username = username
        self.password = password
        self.requests = {}
        self.message_id = 1
        self.notify = None
        self._extranonce_subscribe = False
        self.accepted_shares = 0
        self.last_client = ''

    def stop(self):
        self.running = False

    def connect(self):
        logging.info("%s connect to %s:%d" % (self.log_msg,self.dest_host,self.dest_port))
        self.dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #self.dest_socket = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        #self.dest_socket.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)

        self.dest_socket.connect((self.dest_host, self.dest_port))
        self.dest_socket.settimeout(1)
        server_connect.set()
        self.send_message(method='mining.subscribe',
                   params=["%s/%s" % (USER_AGENT, '.'.join(str(p) for p in VERSION))])

    def connection_lost(self):
        # reinit
        server_ready.clear()
        server_connect.clear()
        self.requests = {}
        self.message_id = 1
        self.notify = None
        self._extranonce_subscribe = False
        self.last_client = ''

    def send(self, data):
        if server_connect.is_set():
            try:
                self.dest_socket.send((data + '\n').encode('UTF-8'))
            except:
                self.connection_lost()
                logging.error(self.log_msg + 'send data connection error')

    def send_message(self, method, params, client = ''):
        '''Sends a message to the JSON-RPC server'''

        request = dict(id=self.message_id, method=method, params=params)
        message = json.dumps(request)
        self.requests[self.message_id] = request
        self.message_id += 1
        self.send(message)
        logging.debug(self.log_msg + 'JSON-RPC Server < ' + message)
        if client:
            self.last_client = client
        return request

    def send_all(self, message):
        for client in clients:
            if clients[client].subscribed:
                clients[client].send(message)

    def handle_reply(self, request, reply):
        global subscription_reply
        global difficulty_reply
        global notify_reply
        global worker_name

        # New work, stop what we were doing before, and start on this.
        if reply.get('method') == 'mining.notify':
            if 'params' not in reply or len(reply['params']) != 9:
                logging.error(self.log_msg + 'malformed mining.notify message\n' + str(reply))
                raise

            (job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs) = reply['params']
            notify_reply = reply
            # send to all subscribed clients
            self.send_all(json.dumps(reply))
            print(reply)
            logging.info(self.log_msg + 'new job: job_id=%s' % job_id)

        # The server wants us to change our difficulty (on all *future* work)
        elif reply.get('method') == 'mining.set_difficulty':
            if 'params' not in reply or len(reply['params']) != 1:
                logging.error(self.log_msg + 'malformed mining.set_difficulty message\n' + str(reply))
                raise

            (difficulty,) = reply['params']
            difficulty_reply = reply
            # send to all subscribed clients
            self.send_all(json.dumps(reply))
            print(reply)
            logging.info(self.log_msg + 'change difficulty: difficulty=%s' % difficulty)

        # The server change your extranonce1 if you subscribed
        elif reply.get('method') == 'mining.set_extranonce':
            if 'params' not in reply or len(reply['params']) != 2:
                logging.error(self.log_msg + 'malformed mining.set_extranonce message\n' + str(reply))
                raise

            (extranonce1,extranonce2_size) = reply['params']
            # send to all subscribed clients
            self.send_all(reply)
            print(reply)
            logging.info(self.log_msg + 'change extranonce1: extranonce1=%s' % extranonce1)

        # This is a reply to...
        elif request:

            # ...subscribe; set-up the work and request authorization
            if request.get('method') == 'mining.subscribe':
                if 'result' not in reply or len(reply['result']) != 3 or len(reply['result'][0]) != 2:
                    logging.error(self.log_msg + 'reply to mining.subscribe is malformed\n' + str(reply) + '\n' + str(request))
                    raise

                ((mining_notify, subscription_id), extranounce1, extranounce2_size) = reply['result']
                subscription_reply = reply
                print(reply)
                logging.info(self.log_msg + 'subscribed: subscription_id=%s' % subscription_id)

                # Request extranonce.subscription
                self.send_message(method='mining.extranonce.subscribe', params=[])

            elif request.get('method') == 'mining.extranonce.subscribe':
                if 'result' not in reply or not reply['result']:
                    logging.error(self.log_msg + 'subscribed: extranonce subscription error')
                else:
                    self._extranonce_subscribe = True
                    logging.info(self.log_msg + 'subscribed: extranonce subscription')
                print(reply)
                # Request authentication
                self.send_message(method='mining.authorize', params=[self.username, self.password])

            # ...authorize; if we failed to authorize, quit
            elif request.get('method') == 'mining.authorize':
                if 'result' not in reply or not reply['result']:
                    logging.error(self.log_msg + 'failed to authenticate\n')
                    raise

                worker_name =  request['params'][0]
                server_ready.set()
                print(reply)
                logging.info(self.log_msg + 'authorized: worker_name=%s' % worker_name)

            # ...submit; complain if the server didn't accept our submission
            elif request.get('method') == 'mining.submit':
                if 'result' not in reply or not reply['result']:
                    logging.info(self.log_msg + 'share - Invalid')
                else:
                    self.accepted_shares += 1
                    # id need take from client, not always 4 ))
                    if self.last_client:
                        clients[self.last_client].accepted_shares += 1
                        clients[self.last_client].send('{"id":4,"result": true,"error": null}')
                        logging.debug('Client %s accepted shares: %d' % (self.last_client, clients[self.last_client].accepted_shares))
                        self.last_client = ''
                    logging.info(self.log_msg + 'accepted shares: %d' % self.accepted_shares)

            # ??? *shrug*
            else:
                logging.error(self.log_msg + 'unhandled message\n')
                raise

        # ??? *double shrug*
        else:
            logging.error(self.log_msg + 'bad message state\n')
            raise

    def run(self):
        while self.running:
            try:
                self.connect()
            except:
                logging.error(self.log_msg + 'connect timeout')
                time.sleep(30)
                continue

            data = ""
            while server_connect.is_set():
                if '\n' in data:
                    (line, data) = data.split('\n', 1)
                else:
                    try:
                        chunk = self.dest_socket.recv(1024).decode('UTF-8')
                        data += chunk
                        if not chunk:
                            logging.error(self.log_msg + 'receive empty data')
                            self.connection_lost()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logging.error(str(e), exc_info=True)
                        self.connection_lost()
                    continue
                logging.debug(self.log_msg + 'JSON-RPC Server > ' + str(line))
                # handle incoming rpc
                try:
                    reply = json.loads(line)
                except Exception as e:
                    logging.error(self.log_msg + 'JSON-RPC Error: Failed to parse JSON %r (skipping)' % line)
                    continue
                try:
                    request = None
                    if 'id' in reply and reply['id'] in self.requests:
                        request = self.requests[reply['id']]
                    self.handle_reply(request=request, reply=reply)
                except Exception as e:
                    output = ''
                    if request:
                        output += '\n  ' + json.dumps(request)
                    output += '\n  ' + json.dumps(reply)
                    logging.error(self.log_msg + output + '\n' + str(e))
            self.dest_socket.shutdown(socket.SHUT_RDWR)
            self.dest_socket.close()

            logging.info(self.log_msg + 'close connection')

if __name__ == '__main__':

    import argparse

    # Parse the command line
    parser = argparse.ArgumentParser(description="Stratum proxy")

    parser.add_argument('-o', '--url', help='stratum mining server url (eg: stratum+tcp://foobar.com:3333)')
    parser.add_argument('-u', '--user', dest='username', default='', help='username for mining server',
                        metavar="USERNAME")
    parser.add_argument('-p', '--pass', dest='password', default='', help='password for mining server',
                        metavar="PASSWORD")

    parser.add_argument('-O', '--userpass', help='username:password pair for mining server',
                        metavar="USERNAME:PASSWORD")
    parser.add_argument('-s', '--proxy', action='store_true', default='', help='use proxy')
    parser.add_argument('-d', '--debug', action='store_true', help='show extra debug information')

    options = parser.parse_args(sys.argv[1:])

    message = None

    if options.debug:
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

    # Get the username/password
    username = options.username
    password = options.password
    if options.userpass:
        if username or password:
            message = 'May not use -O/-userpass in conjunction with -u/--user or -p/--pass'
        else:
            try:
                (username, password) = options.userpass.split(':')
            except Exception as e:
                message = 'Could not parse username:password for -O/--userpass'

    # Was there an issue? Show the help screen and exit.
    if message:
        parser.print_help()
        print
        print
        message
        sys.exit(1)

    if options.url:
        url = urlparse.urlparse(options.url)
        hostname = url.hostname or ''
        port = url.port or 9997
        pool = Server(hostname,port,username,password)
        pool.start()
        proxy = ProxySocket()
        proxy.start()
while True:
    time.sleep(5)