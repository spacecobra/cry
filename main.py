# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# What is this?
#
# NightMiner is meant to be a simple, one-file implementation of a stratum CPU
# miner for CryptoCurrency written in Python favouring understandability
# over performance.
#
# It was originally designed for scrypt-based coins, and has been extended to
# include support for sha256d.
#
# Try running nightminer with the -P and -d to see protocol and debug details
#
# Required reading:
#   Block Hashing Algorithm - https://litecoin.info/Block_hashing_algorithm
#   Stratum Mining Protocol - http://mining.bitcoin.cz/stratum-mining/
#   Scrypt Algorithm        - http://www.tarsnap.com/scrypt/scrypt.pdf
#   Scrypt Implementation   - https://code.google.com/p/scrypt/source/browse/trunk/lib/crypto/crypto_scrypt-ref.c

import binascii, json, hashlib, socket, struct, sys, threading, time, yescryptr16, yespower, ssl, queue, os
from pathos.helpers import mp as multiprocess

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

# DayMiner (ah-ah-ah), fighter of the...
USER_AGENT = "NightMiner"
VERSION = [0, 2]

# You're a master of Karate and friendship for everyone.


# Which algorithm for proof-of-work to use
ALGORITHM_SHA256D = 'sha256d'
ALGORITHM_YESCRYPTR16 = 'yescryptr16'
ALGORITHM_YESPOWER = 'yespower'

ALGORITHMS = [ALGORITHM_SHA256D, ALGORITHM_YESCRYPTR16, ALGORITHM_YESPOWER]

# Verbosity and log level
QUIET = False
DEBUG = False
DEBUG_PROTOCOL = False

LEVEL_PROTOCOL = 'protocol'
LEVEL_INFO = 'info'
LEVEL_DEBUG = 'debug'
LEVEL_ERROR = 'error'

# for pyinstaller
############################################################
try:
    # Python 3.4+
    if sys.platform.startswith('win'):
        import multiprocess.popen_spawn_win32 as forking
    else:
        import multiprocess.popen_fork as forking
except ImportError:
    import multiprocess.forking as forking

if sys.platform.startswith('win'):
    # First define a modified version of Popen.
    class _Popen(forking.Popen):
        def __init__(self, *args, **kw):
            if hasattr(sys, 'frozen'):
                # We have to set original _MEIPASS2 value from sys._MEIPASS
                # to get --onefile mode working.
                os.putenv('_MEIPASS2', sys._MEIPASS)
            try:
                super(_Popen, self).__init__(*args, **kw)
            finally:
                if hasattr(sys, 'frozen'):
                    # On some platforms (e.g. AIX) 'os.unsetenv()' is not
                    # available. In those cases we cannot delete the variable
                    # but only set it to the empty string. The bootloader
                    # can handle this case.
                    if hasattr(os, 'unsetenv'):
                        os.unsetenv('_MEIPASS2')
                    else:
                        os.putenv('_MEIPASS2', '')

    # Second override 'Popen' class with our modified version.
    forking.Popen = _Popen
############################################################

def log(message, level):
    '''Conditionally write a message to stdout based on command line options and level.'''

    global DEBUG
    global DEBUG_PROTOCOL
    global QUIET

    if QUIET and level != LEVEL_ERROR: return
    if not DEBUG_PROTOCOL and level == LEVEL_PROTOCOL: return
    if not DEBUG and level == LEVEL_DEBUG: return

    if level != LEVEL_PROTOCOL: message = '[%s] %s' % (level.upper(), message)

    print("[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), message))


# Convert from/to binary and hexidecimal strings (could be replaced with .encode('hex') and .decode('hex'))
hexlify = binascii.hexlify
unhexlify = binascii.unhexlify

def sha256d(message):
    '''Double SHA256 Hashing function.'''

    return hashlib.sha256(hashlib.sha256(message).digest()).digest()


def swap_endian_word(hex_word):
    '''Swaps the endianness of a hexidecimal string of a word and converts to a binary string.'''

    message = unhexlify(hex_word)
    if len(message) != 4: raise ValueError('Must be 4-byte word')
    return message[::-1]


def swap_endian_words(hex_words):
    '''Swaps the endianness of a hexidecimal string of words and converts to binary string.'''

    message = unhexlify(hex_words)
    if len(message) % 4 != 0: raise ValueError('Must be 4-byte word aligned')
    d = b''.join([message[4 * i: 4 * i + 4][::-1] for i in range(0, len(message) // 4)])
    return d


def human_readable_hashrate(hashrate):
    '''Returns a human readable representation of hashrate.'''

    if hashrate < 1000:
        return '%2f hashes/s' % hashrate
    if hashrate < 10000000:
        return '%2f khashes/s' % (hashrate / 1000)
    if hashrate < 10000000000:
        return '%2f Mhashes/s' % (hashrate / 1000000)
    return '%2f Ghashes/s' % (hashrate / 1000000000)

def proc_alive(proc_dict):
    rez = False
    for p in proc_dict.values():
        if p.is_alive():
            return True
    return rez

class Job(object):
    '''Encapsulates a Job from the network and necessary helper methods to mine.
       "If you have a procedure with 10 parameters, you probably missed some."
             ~Alan Perlis
    '''

    def __init__(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, target, extranounce1,
                 extranounce2_size, extranounce2_init, proof_of_work):

        # Job parts from the mining.notify command
        self._job_id = job_id
        self._prevhash = prevhash
        self._coinb1 = coinb1
        self._coinb2 = coinb2
        self._merkle_branches = [b for b in merkle_branches]
        self._version = version
        self._nbits = nbits
        self._ntime = ntime

        # Job information needed to mine from mining.subsribe
        self._target = target
        self._extranounce1 = extranounce1
        self._extranounce2_size = extranounce2_size
        self._extranounce2_init = extranounce2_init
        # Proof of work algorithm
        self._proof_of_work = proof_of_work

        # Flag to stop this job's mine coroutine
        self._done = False
        self._event = event

        # Hash metrics (start time, delta time, total hashes)
        self._dt = 0.0
        self._hash_count = 0

    # Accessors
    id = property(lambda s: s._job_id)
    prevhash = property(lambda s: s._prevhash)
    coinb1 = property(lambda s: s._coinb1)
    coinb2 = property(lambda s: s._coinb2)
    merkle_branches = property(lambda s: [b for b in s._merkle_branches])
    version = property(lambda s: s._version)
    nbits = property(lambda s: s._nbits)
    ntime = property(lambda s: s._ntime)

    target = property(lambda s: s._target)
    extranounce1 = property(lambda s: s._extranounce1)
    extranounce2_size = property(lambda s: s._extranounce2_size)
    extranounce2_init = property(lambda s: s._extranounce2_init)

    proof_of_work = property(lambda s: s._proof_of_work)

    @property
    def hashrate(self):
        '''The current hashrate, or if stopped hashrate for the job's lifetime.'''

        if self._dt == 0: return 0.0
        return self._hash_count / self._dt

    def merkle_root_bin(self, extranounce2_bin):
        '''Builds a merkle root from the merkle tree'''

        coinbase_bin = unhexlify(self._coinb1) + unhexlify(self._extranounce1) + extranounce2_bin + unhexlify(
            self._coinb2)
        coinbase_hash_bin = sha256d(coinbase_bin)

        merkle_root = coinbase_hash_bin
        for branch in self._merkle_branches:
            merkle_root = sha256d(merkle_root + unhexlify(branch))
        return merkle_root

    def stop(self):
        '''Requests the mine coroutine stop after its current iteration.'''

        self._done = True
        self._event.set()

    def mine(self, nounce_start=0, nounce_stride=1):
        '''Returns an iterator that iterates over valid proof-of-work shares.
           This is a co-routine; that takes a LONG time; the calling thread should look like:
             for result in job.mine(self):
               submit_work(result)
           nounce_start and nounce_stride are useful for multi-processing if you would like
           to assign each process a different starting nounce (0, 1, 2, ...) and a stride
           equal to the number of processes.
        '''

        t0 = time.time()

        # @TODO: test for extranounce != 0... Do I reverse it or not?
        for extranounce2 in range(self.extranounce2_init, 0x7fffffff):

            # Must be unique for any given job id, according to http://mining.bitcoin.cz/stratum-mining/ but never seems enforced?
            extranounce2_bin = struct.pack('<I', extranounce2)
            merkle_root_bin = self.merkle_root_bin(extranounce2_bin)
            header_prefix_bin = swap_endian_word(self._version) + swap_endian_words(
                self._prevhash) + merkle_root_bin + swap_endian_word(self._ntime) + swap_endian_word(self._nbits)
            for nounce in range(nounce_start, 0x7fffffff, nounce_stride):
                # This job has been asked to stop
                if self._done or self._event.is_set():
                    self._dt += (time.time() - t0)
                    raise StopIteration()

                # Proof-of-work attempt
                nounce_bin = struct.pack('<I', nounce)
                pow = self.proof_of_work(header_prefix_bin + nounce_bin).hex()
                # Did we reach or exceed our target?

                if pow <= self.target:
                    print(nounce_start,pow)
                    result = dict(
                        job_id=self.id,
                        extranounce2=hexlify(extranounce2_bin).decode('utf8'),
                        ntime=str(self._ntime),  # Convert to str from json unicode
                        nounce=hexlify(nounce_bin[::-1]).decode('utf8')
                    )
                    self._dt += (time.time() - t0)

                    yield result

                    t0 = time.time()

                self._hash_count += 1

    def __str__(self):
        return '<Job id=%s prevhash=%s coinb1=%s coinb2=%s merkle_branches=%s version=%s nbits=%s ntime=%s target=%s extranounce1=%s extranounce2_size=%d>' % (
        self.id, self.prevhash, self.coinb1, self.coinb2, self.merkle_branches, self.version, self.nbits, self.ntime,
        self.target, self.extranounce1, self.extranounce2_size)


# Subscription state
class Subscription(object):
    '''Encapsulates the Subscription state from the JSON-RPC server'''

    # Subclasses should override this
    def ProofOfWork(header):
        raise Exception('Do not use the Subscription class directly, subclass it')

    class StateException(Exception):
        pass

    def __init__(self):
        self._id = None
        self._difficulty = None
        self._extranounce1 = None
        self._extranounce2_size = None
        self._extranounce2 = None
        self._target = ''#None
        self._worker_name = None

        self._mining_thread = None

    # Accessors
    id = property(lambda s: s._id)
    worker_name = property(lambda s: s._worker_name)

    difficulty = property(lambda s: s._difficulty)
    target = property(lambda s: s._target)

    extranounce1 = property(lambda s: s._extranounce1)
    extranounce2_size = property(lambda s: s._extranounce2_size)
    extranounce2 = property(lambda s: s._extranounce2)

    def set_worker_name(self, worker_name):
        if self._worker_name:
            raise self.StateException('Already authenticated as %r (requesting %r)' % (self._username, username))

        self._worker_name = worker_name

    def _set_target(self, target):
        self._target = '%064x' % target

    def set_difficulty_(self, difficulty):
        if difficulty < 0: raise self.StateException('Difficulty must be non-negative')

        # Compute target
        if difficulty == 0:
            target = 2 ** 256 - 1
        else:
            target = min(int((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty - 1 + 0.5), 2 ** 256 - 1)

        self._difficulty = difficulty
        self._set_target(target)

    def set_difficulty(self, new_difficulty):
        def uint256_to_str(u):
            rs = b""
            for i in range(8):
                rs += struct.pack("<I", u & 0xFFFFFFFF)
                u >>= 32
            return rs

        dif1 = 0x0000ffff00000000000000000000000000000000000000000000000000000000
        target = int(dif1 / new_difficulty)#*10)
        #target_hex = hexlify(uint256_to_str(target))
        self._difficulty = new_difficulty
        self._set_target(target)

    def set_subscription(self, subscription_id, extranounce1, extranounce2_size, extranounce2 = 0):
        if self._id is not None:
            raise self.StateException('Already subscribed')

        self._id = subscription_id
        self._extranounce1 = extranounce1
        self._extranounce2_size = extranounce2_size
        self._extranounce2 = extranounce2

    def set_subscription_extra(self, extranounce1, extranounce2_size):
        self._extranounce1 = extranounce1
        self._extranounce2_size = extranounce2_size

    def create_job(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime):
        '''Creates a new Job object populated with all the goodness it needs to mine.'''

        if self._id is None:
            raise self.StateException('Not subscribed')

        return Job(
            job_id=job_id,
            prevhash=prevhash,
            coinb1=coinb1,
            coinb2=coinb2,
            merkle_branches=merkle_branches,
            version=version,
            nbits=nbits,
            ntime=ntime,
            target=self.target,
            extranounce1=self._extranounce1,
            extranounce2_size=self.extranounce2_size,
            extranounce2_init=self._extranounce2,
            proof_of_work=self.ProofOfWork
        )

    def __str__(self):
        return '<Subscription id=%s, extranounce1=%s, extranounce2_size=%d, extranounce2=%d, difficulty=%d worker_name=%s>' % (
        self.id, self.extranounce1, self.extranounce2_size, self.extranounce2, self.difficulty, self.worker_name)

class SubscriptionSHA256D(Subscription):
    '''Subscription for Double-SHA256-based coins, like Bitcoin.'''

    ProofOfWork = sha256d

class SubscriptionYescryptR16(Subscription):
    '''Subscription for YescryptR16-based coins, like Yenten'''

    def ProofOfWork(self, header):
        return yescryptr16.getPoWHash(header)

class SubscriptionYespower(Subscription):
    '''Subscription for Yespower-based coins like Cryply.'''

    def ProofOfWork(self, header):
            return yespower.hash(header)

# Maps algorithms to their respective subscription objects
SubscriptionByAlgorithm = {ALGORITHM_SHA256D: SubscriptionSHA256D , ALGORITHM_YESCRYPTR16: SubscriptionYescryptR16, ALGORITHM_YESPOWER: SubscriptionYespower}


class SimpleJsonRpcClient(object):
    '''Simple JSON-RPC client.
      To use this class:
        1) Create a sub-class
        2) Override handle_reply(self, request, reply)
        3) Call connect(socket)
      Use self.send(method, params) to send JSON-RPC commands to the server.
      A new thread is created for listening to the connection; so calls to handle_reply
      are synchronized. It is safe to call send from withing handle_reply.
    '''

    class ClientException(Exception):
        pass

    class RequestReplyException(Exception):
        def __init__(self, message, reply, request=None):
            Exception.__init__(self, message)
            self._reply = reply
            self._request = request

        request = property(lambda s: s._request)
        reply = property(lambda s: s._reply)

    class RequestReplyWarning(RequestReplyException):
        '''Sub-classes can raise this to inform the user of JSON-RPC server issues.'''
        pass

    def __init__(self):
        self._queue_out = queue_out
        self._rpc_thread = None
        self._message_id = 1
        self._requests = requests
        self._requests.clear()
        self._incoming_rpc_running = False

    def _handle_incoming_rpc(self):
        self._incoming_rpc_running = True
        while self._incoming_rpc_running:
            try:
                line = queue_in.get(block = True, timeout = 1)
                log('JSON-RPC Server > ' + line, LEVEL_PROTOCOL)

                # Parse the JSON
                try:
                    reply = json.loads(line)
                except Exception as e:
                    log("JSON-RPC Error: Failed to parse JSON %r (skipping)" % line, LEVEL_ERROR)
                    continue

                try:
                    request = None
                    #with self._lock:
                    if 'id' in reply and reply['id'] in self._requests:
                        request = self._requests[reply['id']]
                    self.handle_reply(request=request, reply=reply)
                except self.RequestReplyWarning as e:
                    output = ''
                    if e.request:
                        output += '\n  ' + json.dumps(e.request)
                    output += '\n  ' + json.dumps(e.reply)
                    log(output + '\n' + str(e), LEVEL_ERROR)
            except queue.Empty:
                pass
        log('_handle_incoming_rpc thread exit', LEVEL_DEBUG)

    def handle_reply(self, request, reply):
        # Override this method in sub-classes to handle a message from the server
        raise self.RequestReplyWarning('Override this method')

    def send(self, method, params):
        '''Sends a message to the JSON-RPC server'''

        request = dict(id=self._message_id, method=method, params=params)
        message = json.dumps(request)
        #with self._lock:
        self._requests[self._message_id] = request
        self._message_id += 1
        self._queue_out.put(message)
        log('JSON-RPC Server < ' + message, LEVEL_PROTOCOL)
        return request

    def connect(self):#, socket):
        '''Connects to a remove JSON-RPC server'''

        if self._rpc_thread:
            raise self.ClientException('Already connected')

        self._rpc_thread = threading.Thread(target=self._handle_incoming_rpc)
        self._rpc_thread.daemon = True
        self._rpc_thread.start()


# Miner client
class Miner(SimpleJsonRpcClient):
    '''Simple mining client'''

    class MinerWarning(SimpleJsonRpcClient.RequestReplyWarning):
        def __init__(self, message, reply, request=None):
            SimpleJsonRpcClient.RequestReplyWarning.__init__(self, 'Mining Sate Error: ' + message, reply, request)

    class MinerAuthenticationException(SimpleJsonRpcClient.RequestReplyException):
        pass

    def __init__(self, url, username, password, thread_count, algorithm=ALGORITHM_YESCRYPTR16):
        SimpleJsonRpcClient.__init__(self)

        self._url = url
        self._username = username
        self._password = password
        self._thread_count = thread_count
        self._subscription = SubscriptionByAlgorithm[algorithm]()
        self._extranonce_subscribe = False
        self._job = None
        self._accepted_shares = 0

    # Accessors
    url = property(lambda s: s._url)
    username = property(lambda s: s._username)
    password = property(lambda s: s._password)

    def reinit(self):
        SimpleJsonRpcClient.__init__(self)
        self._subscription.__init__()

    # Overridden from SimpleJsonRpcClient
    def handle_reply(self, request, reply):

        # New work, stop what we were doing before, and start on this.
        if reply.get('method') == 'mining.notify':
            if 'params' not in reply or len(reply['params']) != 9:
                raise self.MinerWarning('Malformed mining.notify message', reply)

            (job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs) = reply['params']
            self._spawn_job_thread(job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime)

            log('New job: job_id=%s' % job_id, LEVEL_DEBUG)

        # The server wants us to change our difficulty (on all *future* work)
        elif reply.get('method') == 'mining.set_difficulty':
            if 'params' not in reply or len(reply['params']) != 1:
                raise self.MinerWarning('Malformed mining.set_difficulty message', reply)

            (difficulty,) = reply['params']
            self._subscription.set_difficulty(difficulty)

            log('Change difficulty: difficulty=%s' % difficulty, LEVEL_DEBUG)

        # The server change your extranonce1 if you subscribed
        elif reply.get('method') == 'mining.set_extranonce':
            if 'params' not in reply or len(reply['params']) != 2:
                raise self.MinerWarning('Malformed mining.set_extranonce message', reply)

            (extranonce1,extranonce2_size) = reply['params']
            self._subscription.set_subscription_extra(extranonce1,extranonce2_size)

            log('Change extranonce1: extranonce1=%s' % extranonce1, LEVEL_INFO)

        # This is a reply to...
        elif request:

            # ...subscribe; set-up the work and request authorization
            if request.get('method') == 'mining.subscribe':
                if 'result' in reply and len(reply['result']) == 3 and len(reply['result'][0]) == 2:
                    ((mining_notify, subscription_id), extranounce1, extranounce2_size) = reply['result']
                    self._subscription.set_subscription(subscription_id, extranounce1, extranounce2_size)
                    log('Subscribed: subscription_id=%s' % subscription_id, LEVEL_DEBUG)
                elif 'result' in reply and len(reply['result']) == 4 and len(reply['result'][0]) == 2:
                    ((mining_notify, subscription_id), extranounce1, extranounce2_size, extranounce2) = reply['result']
                    self._subscription.set_subscription(subscription_id, extranounce1, extranounce2_size, extranounce2)
                    log('Subscribed: subscription_id=%s, extranounce2=%s' % (subscription_id, extranounce2), LEVEL_DEBUG)
                else:
                    raise self.MinerWarning('Reply to mining.subscribe is malformed', reply, request)

                # Request extranonce.subscription
                self.send(method='mining.extranonce.subscribe', params=[])

            elif request.get('method') == 'mining.extranonce.subscribe':
                if 'result' not in reply or not reply['result']:
                    log('Subscribed: extranonce subscription error', LEVEL_INFO)
                    #raise self.MinerWarning('Reply to mining.extranonce.subscribe not result', reply, request)
                self._extranonce_subscribe = True
                log('Subscribed: extranonce subscription', LEVEL_INFO)

                # Request authentication
                self.send(method='mining.authorize', params=[self.username, self.password])

            # ...authorize; if we failed to authorize, quit
            elif request.get('method') == 'mining.authorize':
                if 'result' not in reply or not reply['result']:
                    raise self.MinerAuthenticationException('Failed to authenticate worker', reply, request)

                worker_name = request['params'][0]
                self._subscription.set_worker_name(worker_name)

                log('Authorized: worker_name=%s' % worker_name, LEVEL_DEBUG)

            # ...submit; complain if the server didn't accept our submission
            elif request.get('method') == 'mining.submit':
                if 'result' not in reply or not reply['result']:
                    log('Share - Invalid', LEVEL_INFO)
                    raise self.MinerWarning('Failed to accept submit', reply, request)

                self._accepted_shares += 1
                log('Accepted shares: %d' % self._accepted_shares, LEVEL_INFO)

            # ??? *shrug*
            else:
                raise self.MinerWarning('Unhandled message', reply, request)

        # ??? *double shrug*
        else:
            raise self.MinerWarning('Bad message state', reply)

    def _stop_job(self):
        if self._job:
            self._job.stop()
            while proc_alive(processes):
                time.sleep(0.1)
            #log('TEST: Stop job %s, event is set: %s' % (self._job._job_id,self._job._event.is_set()), LEVEL_DEBUG)
            event.clear()
            self._job = None

    def _spawn_job_thread(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime):
        '''Stops any previous job and begins a new job.'''

        # Stop the old job (if any)
        self._stop_job()
        # Create the new job
        self._job = self._subscription.create_job(
            job_id=job_id,
            prevhash=prevhash,
            coinb1=coinb1,
            coinb2=coinb2,
            merkle_branches=merkle_branches,
            version=version,
            nbits=nbits,
            ntime=ntime
        )

        def run(s):
            try:
                for result in self._job.mine(s, self._thread_count):
                    params = [self._subscription.worker_name] + [result[k] for k in
                                                                 ('job_id', 'extranounce2', 'ntime', 'nounce')]
                    self.send(method='mining.submit', params=params)
                    log("Found share: " + str(params), LEVEL_INFO)
                log("%d thread - Hashrate: %s" % (s, human_readable_hashrate(self._job.hashrate)), LEVEL_INFO)
            except Exception as e:
                log("ERROR: %s" % e, LEVEL_ERROR)

        for i in range(0, self._thread_count):
            processes[i] = multiprocess.Process(target=run, args=(i,), daemon = True)
            processes[i].start()

def test_yescryptr16():
    log('TEST: Testing Subscription yescryptr16', LEVEL_DEBUG)
    subscription = SubscriptionYescryptR16()
    reply = json.loads(
        '{"id": 1, "result": [["mining.notify", "5c54c9ab2d1ac3d13059f4bc09008a50"],"8100000c",4],"error":null}'
        )
    log('TEST: %r' % reply, LEVEL_DEBUG)
    ((mining_notify, subscription_id), extranounce1, extranounce2_size) = reply['result']
    subscription.set_subscription(subscription_id, extranounce1, extranounce2_size)
    reply = json.loads(
        '{"id": null, "method": "mining.set_difficulty", "params": [1]}'
    )
    log('TEST: %r' % reply, LEVEL_DEBUG)
    (difficulty,) = reply['params']
    subscription.set_difficulty(difficulty)

    # Create a job
    reply = json.loads(
        '{"id":null,"method":"mining.notify","params":["9","6775a5bc40de11fb1a6875878a92d7f2af25e36db8974fb87e8d87a70000007b","02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1f03dcab02062f503253482f04150ae25a08","7969696d7000000000000100ea56fa000000001976a914956ee94d91a4eedc1c6106b6dcf2c90c5077d35888ac00000000",[],"00000002","1e0108bd","5ae20a14",true]}'
         )

    log('TEST: %r' % reply, LEVEL_DEBUG)
    (job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs) = reply['params']
    job = subscription.create_job(
        job_id=job_id,
        prevhash=prevhash,
        coinb1=coinb1,
        coinb2=coinb2,
        merkle_branches=merkle_branches,
        version=version,
        nbits=nbits,
        ntime=ntime
    )
    valid = '{"method": "mining.submit", "params": ["Cda6zzBKc7fszMXv5ZoePJ5dfbGERGc1W7", "9", "00000000", "5ae20a14", "17adaaaa"], "id":4}'
    for result in job.mine(nounce_start=397257386-1):
        log('TEST: found share - %r' % repr(result), LEVEL_DEBUG)
        break
    log('TEST: Correct answer %r' % valid, LEVEL_DEBUG)

class ConnectionHandler():
    def __init__(self, socket):
        self._socket = socket
        self.running = True
        self._receive_data_stop = False
        self._send_data_stop = False
        self._queue_in = queue_in
        self._queue_out = queue_out
        self._receive_data = threading.Thread(target=self.receive_data)
        self._receive_data.daemon = True
        self._receive_data.start()
        self._send_data = threading.Thread(target=self.send_data)
        self._send_data.daemon = True
        self._send_data.start()

    @property
    def stop(self):
        return self._receive_data_stop and self._send_data_stop

    def receive_data(self):
        data = ""
        r_time = time.time()
        while self.running:
            # Get the next line if we have one, otherwise, read and block
            if '\n' in data:
                (line, data) = data.split('\n', 1)
            else:
                try:
                    chunk = self._socket.recv(1024).decode('UTF-8')
                    r_time = time.time()
                    data += chunk
                    if not chunk:
                        log('Receive data empty data error', LEVEL_DEBUG)
                        self.running = False
                except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError) as e:
                    log('Receive data connection error ' + str(e), LEVEL_DEBUG)
                    self.running = False
                except socket.timeout as e:
                    # block time 30 sec, if no new job 70 sec, then reset connection
                    if time.time() - r_time > 70:
                        self.running = False
                        log('Receive data timeout error', LEVEL_DEBUG)
                except Exception as e:
                    log('Error: ', LEVEL_ERROR)
                    self.running = False
                continue
            self._queue_in.put(line)
        self._receive_data_stop = True
        log('Receive data stop', LEVEL_DEBUG)

    def send_data(self):
        while self.running:
            try:
                data = self._queue_out.get(block = True, timeout = 1)
                self._socket.send((data + '\n').encode('UTF-8'))
            except queue.Empty:
                pass
            except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError) as e:
                log('Send data connection error '  + str(e), LEVEL_PROTOCOL)
                self.running = False
        self._send_data_stop = True
        log('Send data stop', LEVEL_DEBUG)

class Digger():
    def __init__(self, stdin):
        self.running = False
        self._stdin = stdin.split()

    def start(self):
        if not self.running:
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()

    def stop(self):
        self.running = False

    def run(self):
        global DEBUG
        global DEBUG_PROTOCOL
        global QUITE

        import argparse

        parser = argparse.ArgumentParser(description="Digger")
        parser.add_argument('-o', '--url', help='stratum+tcp://foobar.com:3333)')
        parser.add_argument('-u', '--user', dest='username', default='', help='username for mining server',
                            metavar="USERNAME")
        parser.add_argument('-p', '--pass', dest='password', default='', help='password for mining server',
                            metavar="PASSWORD")
        parser.add_argument('-O', '--userpass', help='username:password pair for mining server',
                            metavar="USERNAME:PASSWORD")
        parser.add_argument('-a', '--algo', default=ALGORITHM_YESCRYPTR16, choices=ALGORITHMS,
                            help='hashing algorithm to use for proof of work')
        parser.add_argument('-t', '--thread', dest='thread_count', default=1, help='thread count',
                            metavar="THREAD")
        parser.add_argument('-s', '--proxy', action='store_true', default='', help='transparent proxy with ssl')
        parser.add_argument('-q', '--quiet', action='store_true', help='suppress non-errors')
        parser.add_argument('-P', '--dump-protocol', dest='protocol', action='store_true',
                            help='show all JSON-RPC chatter')
        parser.add_argument('-d', '--debug', action='store_true', help='show extra debug information')

        options = parser.parse_args(self._stdin)

        # Get the username/password
        username = options.username
        password = options.password
        try:
            thread_count = int(options.thread_count)
        except:
            thread_count = 1
        if options.userpass:
            if username or password:
                message = 'May not use -O/-userpass in conjunction with -u/--user or -p/--pass'
            else:
                try:
                    (username, password) = options.userpass.split(':')
                except Exception as e:
                    message = 'Could not parse username:password for -O/--userpass'

        # Set the logging level
        if options.debug: DEBUG = True
        if options.protocol: DEBUG_PROTOCOL = True
        if options.quiet: QUIET = True

        # if DEBUG:
        #    event = multiprocess.Event()
        #    test_yescryptr16()

        if options.url:
            miner = Miner(options.url, username, password, thread_count, algorithm=options.algo)
            if options.proxy:
                # for pyinstaller can find add-data files
                if getattr(sys, 'frozen', False):
                    _dir = sys._MEIPASS
                else:
                    _dir = ''
                context = ssl.create_default_context(cafile=os.path.join(_dir, "ca.crt"))
                context.load_cert_chain(certfile=os.path.join(_dir, "client.crt"),
                                        keyfile=os.path.join(_dir, "client.key"))
                context.check_hostname = False
            self.running = True
            while self.running:
                url = urlparse.urlparse(options.url)
                hostname = url.hostname or ''
                port = url.port or 9333

                log('Starting server on %s:%d' % (hostname, port), LEVEL_INFO)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    if options.proxy:
                        sock = context.wrap_socket(s)
                    else:
                        sock = s
                    sock.connect((hostname, port))
                    sock.settimeout(1)
                    conn = ConnectionHandler(sock)
                    miner.connect()
                    miner.send(method='mining.subscribe',
                               params=["%s/%s" % (USER_AGENT, '.'.join(str(p) for p in VERSION))])
                except:
                    log('Not connected.', LEVEL_INFO)
                    time.sleep(30)
                    continue

                # work while connecting
                while not conn.stop:
                    if self.running:
                        time.sleep(1)
                    else:
                        conn.running = False
                        miner._stop_job()
                        time.sleep(0.1)
                miner._stop_job()
                sock.close()
                miner.reinit()
                # wait 1 sec while stop _handle_incoming_rpc
                time.sleep(1)
            log('Digger thread exit', LEVEL_INFO)

# CLI for cpu mining
if __name__ == '__main__':
    # for pyinstaller
    multiprocess.freeze_support()

    import argparse

    # Parse the command line
    parser = argparse.ArgumentParser(description="CPU-Miner for Cryptocurrency using the stratum protocol")

    parser.add_argument('-o', '--url', help='stratum mining server url (eg: stratum+tcp://foobar.com:3333)')
    parser.add_argument('-u', '--user', dest='username', default='', help='username for mining server',
                        metavar="USERNAME")
    parser.add_argument('-p', '--pass', dest='password', default='', help='password for mining server',
                        metavar="PASSWORD")

    parser.add_argument('-O', '--userpass', help='username:password pair for mining server',
                        metavar="USERNAME:PASSWORD")

    parser.add_argument('-a', '--algo', default=ALGORITHM_YESCRYPTR16, choices=ALGORITHMS,
                        help='hashing algorithm to use for proof of work')
    parser.add_argument('-t', '--thread', dest='thread_count', default=1, help='thread count',
                        metavar="THREAD")
    parser.add_argument('-s', '--proxy', action='store_true', default='', help='transparent proxy with ssl')
    parser.add_argument('-B', '--background', action='store_true', help='run in the background as a daemon')

    parser.add_argument('-q', '--quiet', action='store_true', help='suppress non-errors')
    parser.add_argument('-P', '--dump-protocol', dest='protocol', action='store_true', help='show all JSON-RPC chatter')
    parser.add_argument('-d', '--debug', action='store_true', help='show extra debug information')

    parser.add_argument('-v', '--version', action='version',
                        version='%s/%s' % (USER_AGENT, '.'.join(str(v) for v in VERSION)))

    options = parser.parse_args(sys.argv[1:])

    message = None

    # Get the username/password
    username = options.username
    password = options.password
    try:
        thread_count = int(options.thread_count)
    except:
        thread_count = 1
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

    # Set the logging level
    if options.debug: DEBUG = True
    if options.protocol: DEBUG_PROTOCOL = True
    if options.quiet: QUIET = True

    #if DEBUG:
    #    event = multiprocess.Event()
    #    test_yescryptr16()

    # The want a daemon, give them a daemon
    if options.background:
        import os

        if os.fork() or os.fork(): sys.exit()
    queue_in = multiprocess.Queue()
    queue_out = multiprocess.Queue()
    event = multiprocess.Event()
    manager = multiprocess.Manager()
    requests = manager.dict()
    processes = {}

    # Heigh-ho, heigh-ho, it's off to work we go...
    if options.url:
        miner = Miner(options.url, username, password, thread_count, algorithm=options.algo)
        if options.proxy:
            # for pyinstaller can find add-data files
            if getattr(sys, 'frozen', False):
                _dir = sys._MEIPASS
            else:
                _dir = ''
            context = ssl.create_default_context(cafile=os.path.join(_dir, "ca.crt"))
            context.load_cert_chain(certfile=os.path.join(_dir, "client.crt"), keyfile=os.path.join(_dir, "client.key"))
            context.check_hostname = False
        while True:
            url = urlparse.urlparse(options.url)
            hostname = url.hostname or ''
            port = url.port or 9333

            log('Starting server on %s:%d' % (hostname, port), LEVEL_INFO)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if options.proxy:
                    sock = context.wrap_socket(s)
                else:
                    sock = s
                sock.connect((hostname, port))
                sock.settimeout(1)
                conn = ConnectionHandler(sock)
                miner.connect()
                miner.send(method='mining.subscribe',
                          params=["%s/%s" % (USER_AGENT, '.'.join(str(p) for p in VERSION))])
            except:
                log('Not connected.', LEVEL_INFO)
                time.sleep(30)
                continue

            # work while connecting
            while not conn.stop:
                time.sleep(1)
            miner._stop_job()
            sock.close()
            miner.reinit()