README for megapubdl
""""""""""""""""""""

megapubdl is command-line tool for Unix implemented as a Python script to
download public files (with a public URL) from MEGA (mega.nz, mega.co.nz).
It also allows listing files in a public folder and download them.
It works with Python 3.6 and and needs only the `requests` and `openssl`
external tool or PyCrypto installed.

The implementation of megapubdl is based on
https://github.com/richardasaurus/mega.py/blob/master/mega/mega.py

Differences from mega.py:

* megapubdl is a single .py file (with no .py library dependencies).
* megapubdl works with either `pycrypto' or the `openssl' external tool,
  while mega.py depends on the former.
* megapubdl needs a Unix system to run. (Porting to Windows is possible.)
* megapubdl supports only 2 uses cases: downloading public files and listing contents of a public folder.
* megapubdl works with older versions of libssl.

__END__
