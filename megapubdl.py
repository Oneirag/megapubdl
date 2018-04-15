#! /usr/bin/python
# by pts@fazekas.hu at Tue Oct 11 13:12:47 CEST 2016
# modified by oneirag@yahoo.es on 2018/04/16

""":" #megapubdl: Download public files from MEGA (mega.nz).


megapubdl is command-line tool for Unix implemented as a Python script to
download public files (with a public URL) from MEGA (mega.nz, mega.co.nz).
It works with Python 3.6 and needs only the requests and `openssl' external tool or
PyCrypto installed.

Usage:

  megapubdl.py "https://mega.nz/#!..."
"""

#
# TODO(pts): Improve error handling (especially socket errors and parse errors).
#

import base64
import os
import random
import re
import socket
import stat
import struct
import subprocess
import sys
import traceback
import json as builtin_json  # From Python 2.6.
import requests


def import_get(module, name, default):
    try:
        __import__(module)
    except ImportError:
        return default
    return getattr(__import__('sys').modules[module], name, default)


def parse_json(data):
    return builtin_json.loads(data)


def dump_json(obj):
    return builtin_json.dumps(obj)


# --- Crypto.

openssl_prog = False

if import_get('Crypto.Cipher.AES', 'MODE_CBC', None) is not None:
    # PyCrypto, implemented in C (no Python implementation). Tested and found
    # working with pycrypto-2.3.
    def aes_cbc(is_encrypt, data, key, iv='\0' * 16):
        if len(key) != 16:
            raise ValueError
        if len(iv) != 16:
            raise ValueError
        from Crypto.Cipher import AES
        aes_obj = AES.new(key, AES.MODE_CBC, iv)
        if is_encrypt:
            return aes_obj.encrypt(data)
        else:
            return aes_obj.decrypt(data)
else:
    openssl_prog = True


    def aes_cbc(is_encrypt, data, key, iv='\0' * 16):
        if len(key) != 16:
            raise ValueError
        if len(iv) != 16:
            raise ValueError
        encdec = ('-d', '-e')[bool(is_encrypt)]
        p = subprocess.Popen(
            (openssl_prog, 'enc', encdec, '-aes-128-cbc', '-nopad',
             '-K', key.encode('hex'), '-iv', iv.encode('hex')),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            got, _ = p.communicate(data)
        finally:
            p.stdin.close()
            exitcode = p.wait()
        if exitcode:
            raise ValueError('Error running openssl enc.')
        if len(got) != len(data):
            raise ValueError('openssl enc output size mismatch.')
        assert len(got) == len(data)
        return got


if import_get('Crypto.Cipher.AES', 'MODE_CTR', None) is not None:
    # PyCrypto, implemented in C (no Python implementation). Tested and found
    # working with pycrypto-2.3.
    def yield_aes_ctr(data_iter, key, iv='\0' * 16, bufsize=None):
        if len(key) != 16:
            raise ValueError
        if len(iv) != 16:
            raise ValueError
        if isinstance(data_iter, (str, bytes)):
            data_iter = (data_iter,)
        data_iter = iter(data_iter)
        # PyCrypto, implemented in C (no Python implementation).
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
        counter = Counter.new(8 * len(key), initial_value=int(iv.hex(), 16))
        aes_obj = AES.new(key, AES.MODE_CTR, counter=counter)
        yield ''  # This is important, it signifies that decryption has started.
        encrypt = aes_obj.encrypt  # .encrypt and .decrypt do the same.
        for data in data_iter:
            yield encrypt(data)




def aes_cbc_encrypt_a32(data, key):
    return str_to_a32(aes_cbc(True, a32_to_str(data), a32_to_str(key)))


def aes_cbc_decrypt_a32(data, key):
    return str_to_a32(aes_cbc(False, a32_to_str(data), a32_to_str(key)))


def stringhash(str, aeskey):
    s32 = str_to_a32(str)
    h32 = [0, 0, 0, 0]
    for i in range(len(s32)):
        h32[i % 4] ^= s32[i]
    for r in range(0x4000):
        h32 = aes_cbc_encrypt_a32(h32, aeskey)
    return a32_to_base64((h32[0], h32[2]))


def encrypt_key(a, key):
    return sum(
        (aes_cbc_encrypt_a32(a[i:i + 4], key)
         for i in range(0, len(a), 4)), ())


def decrypt_key(a, key):
    return sum(
        (aes_cbc_decrypt_a32(a[i:i + 4], key)
         for i in range(0, len(a), 4)), ())


def decrypt_attr(attr, key):
    attr = aes_cbc(False, attr, a32_to_str(key)).rstrip(b'\0').decode()
    return attr.startswith('MEGA{"') and parse_json(attr[4:])


def a32_to_str(a):
    return struct.pack('>%dI' % len(a), *a)


def str_to_a32(b):
    if len(b) % 4:
        # pad to multiple of 4
        b += '\0' * (4 - len(b) % 4)
    return struct.unpack('>%dI' % (len(b) / 4), b)


def base64_url_decode(data):
    data += '=='[(2 - len(data) * 3) % 4:]
    for search, replace in (('-', '+'), ('_', '/'), (',', '')):
        data = data.replace(search, replace)
    return base64.b64decode(data)


def base64_to_a32(s):
    return str_to_a32(base64_url_decode(s))


def base64_url_encode(data):
    data = base64.b64encode(data)
    for search, replace in ((b'+', b'-'), (b'/', b'_'), (b'=', b'')):
        data = data.replace(search, replace)
    return data


def a32_to_base64(a):
    return base64_url_encode(a32_to_str(a))


# more general functions
def make_id(length):
    possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join(random.choice(possible) for _ in range(length))


def send_http_request(url, data=None, timeout=None, params=None, stream=False):
    r = requests.get(url, data=data, timeout=timeout, params=params, stream=stream)
    return r


MEGA_ERRORS = {
    0: 'API_OK',  # Success
    -1: 'API_EINTERNAL',
    # An internal error has occurred. Please submit a bug report, detailing the exact circumstances in which this error occurred.
    -2: 'API_EARGS',  # You have passed invalid arguments to this command.
    -3: 'API_EAGAIN',
    # (always at the request level): A temporary congestion or server malfunction prevented your request from being processed. No data was altered. Retry. Retries must be spaced with exponential backoff.
    -4: 'API_ERATELIMIT',
    # You have exceeded your command weight per time quota. Please wait a few seconds, then try again (this should never happen in sane real-life applications).
    -5: 'API_EFAILED',  # The upload failed. Please restart it from scratch.
    -6: 'API_ETOOMANY',  # Too many concurrent IP addresses are accessing this upload target URL.
    -7: 'API_ERANGE',  # The upload file packet is out of range or not starting and ending on a chunk boundary.
    -8: 'API_EEXPIRED',  # The upload target URL you are trying to access has expired. Please request a fresh one.
    -9: 'API_EOENT',  # Object (typically, node or user) not found
    -10: 'API_ECIRCULAR',  # Circular linkage attempted
    -11: 'API_EACCESS',  # Access violation (e.g., trying to write to a read-only share)
    -12: 'API_EEXIST',  # Trying to create an object that already exists
    -13: 'API_EINCOMPLETE',  # Trying to access an incomplete resource
    -14: 'API_EKEY',  # A decryption operation failed (never returned by the API)
    -15: 'API_ESID',  # Invalid or expired user session, please relogin
    -16: 'API_EBLOCKED',  # User blocked
    -17: 'API_EOVERQUOTA',  # Request over quota
    -18: 'API_ETEMPUNAVAIL',  # Resource temporarily not available, please try again later
    -19: 'API_ETOOMANYCONNECTIONS',  # Too many connections on this resource
    -20: 'API_EWRITE',  # Write failed
    -21: 'API_EREAD',  # Read failed
    -22: 'API_EAPPKEY',  # Invalid application key; request not processed
}


class RequestError(ValueError):
    """Error in API request."""


class Mega(object):
    def __init__(self, options=None):
        self.bufsize = 65536
        self.schema = 'https'
        self.domain = 'mega.co.nz'
        self.timeout = 160  # max time (secs) to wait for resp from api requests
        self.sid = None
        self.sequence_num = random.randint(0, 0xFFFFFFFF)
        self.request_id = make_id(10)

        if options is None:
            options = {}
        self.options = options

    def _login(self):
        master_key = [random.randint(0, 0xFFFFFFFF)] * 4
        password_key = [random.randint(0, 0xFFFFFFFF)] * 4
        session_self_challenge = [random.randint(0, 0xFFFFFFFF)] * 4

        user = self._api_request({
            'a': 'up',
            'k': a32_to_base64(encrypt_key(master_key, password_key)).decode(),
            'ts': base64_url_encode(a32_to_str(session_self_challenge) +
                                    a32_to_str(encrypt_key(session_self_challenge, master_key))).decode()
        })

        resp = self._api_request({'a': 'us', 'user': user})
        # if numeric error code response
        if isinstance(resp, int):
            raise RequestError(resp)
        encrypted_master_key = base64_to_a32(resp['k'])
        self.master_key = decrypt_key(encrypted_master_key, password_key)
        if 'tsid' not in resp:
            raise RequestError('Missing tsid.')
        tsid = base64_url_decode(resp['tsid'])
        key_encrypted = a32_to_str(
            encrypt_key(str_to_a32(tsid[:16]), self.master_key))
        if key_encrypted == tsid[-16:]:
            self.sid = resp['tsid']

    def _api_request(self, data, folder_id=None):
        params = {}
        if folder_id:
            params['n'] = folder_id
        params['id'] = self.sequence_num

        self.sequence_num += 1

        if self.sid:
            params.update({'sid': self.sid})

        # ensure input data is a list
        if not isinstance(data, list):
            data = [data]

        url = '%s://g.api.%s/cs' % (self.schema, self.domain)
        hr = send_http_request(url, data=dump_json(data), timeout=self.timeout, params=params)
        if hr.status_code != 200:
            raise RequestError('HTTP not OK: %s %s' % (hr.status_code, hr.reason))
        json_resp = hr.json()
        if isinstance(json_resp, int):
            raise RequestError('%s (%s)' % (MEGA_ERRORS.get(json_resp), json_resp))
        if isinstance(json_resp[0], int):
            raise RequestError('%s (%s)' % (MEGA_ERRORS.get(json_resp[0]), json_resp[0]))
        return json_resp[0]

    @classmethod
    def _parse_url(self, url):
        """Returns (file_id, file_key."""
        i = url.find('/#!')
        if i < 0:
            raise RequestError('Key missing from URL.')
        path = url[i + 3:].split('!')
        return path[:2]

    @classmethod
    def get_file_id(self, url):
        return self._parse_url(url)[0]

    def list_files(self, folder_url, filter_func=None):
        """
        Get a list of files in a public folder link of mega
        Example use:
            mega = Mega()
            list = mega.list_files('https://mega.nz/#F!O4YA2JgD!n2b4iSHQDruEsYUvTQP5_w')
            for name, val in list.iteritems():
                mega.download_public_file(val)

        :param folder_url: a public link such as 'https://mega.nz/#F!O4YA2JgD!n2b4iSHQDruEsYUvTQP5_w'
        :param filter_func: a function to filter the names of the files, returning True for the files to keep in the list
        :return: a dictionary. Key is the name of the file
                    file_info['folder_id'] = folder_id (to pass to download file)
                    file_info['ts'] = file timestamp
                    file_info['url'] = public_link (to pass to download file)
                    file_info['filename'] = file name

        """
        if self.sid is None:
            self._login()

        folder_id, orig_folder_key = folder_url.split("!")[1:]  # TODO: error check

        folder_key = base64_to_a32(orig_folder_key)  # if is_public:

        if len(folder_key) == 4:
            k = folder_key
        elif len(folder_key) == 8:
            k = (folder_key[0] ^ folder_key[4],
                 folder_key[1] ^ folder_key[5],
                 folder_key[2] ^ folder_key[6],
                 folder_key[3] ^ folder_key[7])
        else:
            raise Exception("Invalid key, please verify your MEGA url.")

        if len(folder_key) > 4:
            iv = folder_key[4:6] + (0, 0)
            meta_mac = folder_key[6:8]

        retval = {}
        folder_data = self._api_request({'a': 'f', 'c': 1, 'ca': 1, 'r': 1}, folder_id)
        for node in folder_data['f']:
            if node['t'] == 0:  # Just files
                if node['k']:
                    node_k = node['k']
                    file_key = node_k[node_k.find(':') + 1:]
                    file_key = decrypt_key(base64_to_a32(file_key), folder_key)
                    public_link_key = base64_url_encode(a32_to_str(file_key))
                    public_link = "https://mega.nz/#!{}!{}".format(
                        node['h'],
                        public_link_key.decode()
                    )
                    file_key = (file_key[0] ^ file_key[4],
                                file_key[1] ^ file_key[5],
                                file_key[2] ^ file_key[6],
                                file_key[3] ^ file_key[7])
                    attribs = decrypt_attr(base64_url_decode(node['a']), file_key)
                    file_name = attribs['n']
                    if filter_func:
                        if not filter_func(file_name):
                            continue
                    file_info = {}
                    file_info['folder_id'] = folder_id
                    file_info['ts'] = node['ts']
                    file_info['url'] = public_link
                    file_info['filename'] = file_name
                    retval[file_name] = file_info
        return retval

    def download_public_file(self, file_info, target_dir=""):

        dl = self.download_url(file_info['url'], file_info['folder_id'], is_public=True)
        dl_info = next(dl)
        print(dl_info['name'], dl_info['size'])  # TODO: use logging
        next(dl)  # Start the download.
        file_name = os.path.join(target_dir, dl_info['name'])
        if not os.path.exists(file_name):
            with open(file_name, 'wb') as f:
                for data in dl:
                    f.write(data)

    def download_url(self, url, folder_id=None, is_public=True):
        """Starts downloading a file from Mega, based on URL.

        Example usage:

          mega = Mega()
          dl = mega.download_url('https://mega.nz/#!ptJElSYC!qEPvI7qJkjvreVxpLU7CoJc4sxF3X7p1DH5WEMmPs5U')
          dl_info = dl.next()
          print (dl_info['name'], dl_info['size'])
          dl.next()  # Start the download.
          f = open(dl_info['name'], 'wb')
          try:
            for data in dl:
              f.write(data)
          finally:
            f.close()
        """
        if self.sid is None:
            self._login()
        file_id, file_key = self._parse_url(url)
        file_key = base64_to_a32(file_key)  #
        if is_public:
            file_data = self._api_request({'a': 'g', 'g': 1, 'n': file_id}, folder_id)
        else:
            file_data = self._api_request({'a': 'g', 'g': 1, 'p': file_id}, folder_id)
        k = (file_key[0] ^ file_key[4], file_key[1] ^ file_key[5],
             file_key[2] ^ file_key[6], file_key[3] ^ file_key[7])
        iv = file_key[4:6] + (0, 0)
        meta_mac = file_key[6:8]

        # Seems to happens sometime... When  this occurs, files are
        # inaccessible also in the official also in the official web app.
        # Strangely, files can come back later.
        if 'g' not in file_data:
            raise RequestError('File not accessible now.')
        file_url = file_data['g']  # Can be non-ASCII UTF-8.
        file_size = int(file_data['s'])  # Was already an int.
        attribs = base64_url_decode(file_data['at'])
        attribs = decrypt_attr(attribs, k)
        file_name = attribs['n']  # Can be non-ASCII UTF-8.
        key_str = a32_to_str(k)
        assert len(key_str) == 16
        iv_str = struct.pack('>LLLL', iv[0], iv[1], 0, 0)
        assert len(iv_str) == 16

        yield {'name': file_name, 'size': file_size, 'url': file_url, 'key': key_str, 'iv': iv_str, 'id': file_id}

        hr = send_http_request(file_url, timeout=self.timeout, stream=True)
        if hr.status_code != 200:
            raise RequestError('HTTP download link not OK: %s %s' % (hr.status_code, hr.reason))
        ct = hr.headers['content-type'].lower()
        if ct.startswith('text/'):  # Typically 'application/octet-stream'.
            raise RequestError('Unexpected content-type: %s' % ct)
        yield_size = 0
        for pdata in yield_aes_ctr(
                hr.iter_content(self.bufsize),
                key_str, iv_str, self.bufsize):
            yield pdata
            yield_size += len(pdata)
        if yield_size != file_size:
            raise RequestError('File size mismatch: got=%d expected=%d' %
                               (yield_size, file_size))


def get_module_docstring():
    return __doc__


def get_doc(doc=None):
    if doc is None:
        doc = get_module_docstring()
    doc = doc.rstrip()
    doc = re.sub(r'\A:"\s*#', '', doc, 1)
    doc = re.sub(r'\n(\ntype python.*)+\nexec python -- .*', '', doc, 1)
    return doc


def fix_ext(filename):
    a, b = os.path.splitext(filename)
    return a + b.lower()


def download_mega_url(url, mega):
    print('info: Downloading URL: %s' % url, sys.stderr)
    file_id = mega.get_file_id(url)
    prefix = 'mega_%s_' % file_id
    entries = [e for e in os.listdir('.') if e.startswith(prefix) and not e.endswith('.tmpdl')]
    if entries:
        for entry in entries:
            print('info: Already present, keeping %s bytes in file: %s' % (
                os.stat(entry).st_size, entry), sys.stderr)
        return
    dl = mega.download_url(url)
    try:
        dl_info = dl.next()
    except RequestError as e:
        if str(e).startswith('API_EOENT ('):  # File not found on MEGA.
            open(prefix + 'not_found.err', 'wb').close()
        raise
    filename = prefix + fix_ext('_'.join(dl_info['name'].split()))
    try:
        st = os.stat(filename)
    except OSError as e:
        st = None
    if st and stat.S_ISREG(st.st_mode) and st.st_size == dl_info['size']:
        print('info: Already downloaded, keeping %s bytes in file: %s' % (
            dl_info['size'], filename), sys.stderr)
        return
    print('info: Saving file of %s bytes to file: %s' % (dl_info['size'], filename), sys.stderr)
    marker = dl.next()  # Start the download.
    assert marker == ''
    filename_tmpdl = filename + '.tmpdl'
    try:
        f = open(filename_tmpdl, 'wb')
        try:
            for data in dl:
                f.write(data)
        finally:
            f.close()
        os.rename(filename_tmpdl, filename)
        filename_tmpdl = ''  # Don't attempt to remove it.
    finally:
        if filename_tmpdl:
            try:
                os.remove(filename_tmpdl)
            except OSError:
                pass


def main(argv):
    if len(argv) < 2 or argv[1] == '--help':
        print(get_doc())
        sys.exit(0)
    mega = Mega()
    had_error = False
    for url in argv[1:]:
        try:
            download_mega_url(url, mega)
        except (socket.error, IOError, OSError, ValueError):
            traceback.print_exc()
            had_error = True
    sys.exit(2 * bool(had_error))


if __name__ == '__main__':
    sys.exit(main(sys.argv))
