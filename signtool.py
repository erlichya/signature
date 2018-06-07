'''
Copyright 2018 MyHeritage Inc.

Permission is hereby granted, free of charge, to any person obtaining 
a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the rights to use, 
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be 
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
IN THE SOFTWARE.
'''


import sys
import argparse
import subprocess
import tempfile
import logging

logging.basicConfig(level=logging.DEBUG)

# this can be anything, but cannot be blank
# it will be discarded, but it does need to be the same 
# for --sign and --verify
trusted_comment = 'X123'

def init_args():
    parser = argparse.ArgumentParser(
        description="Signature Tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Typical Usage:

  python signtool.py --init --secretkeyfile file.sec --publickeyfile file.pub

  python signtool.py --sign --secretkeyfile file.sec --infile infile.csv --outfile signed.csv

  python signtool.py --verify --publickeyfile file.pub --infile signed.csv


Alt?
  python signtool.py --init --secretkeyfile file.sec --publickeyfile file.pub

  python signtool.py --sign infile.csv --secretkeyfile file.sec --outfile signed.csv

  python signtool.py --verify signed.csv --publickeyfile file.pub
"""
    )
    parser.add_argument('--infile')
    parser.add_argument('--outfile')
    parser.add_argument('--publickeyfile')
    parser.add_argument('--secretkeyfile')

    parser.add_argument('--init', help = 'Generate private/public key', action='store_true')
    parser.add_argument('--force', help = 'Over-write previous private/public key files', action='store_true')

    parser.add_argument('--sign', action='store_true')

    parser.add_argument('--verify', action='store_true')

    args = parser.parse_args()
    return args

def show_help(args):
    print('Expected : --sign or --verify or --init')
    print('Got : %s' % args)
    sys.exit(-1)

def handle_args(args):
    if args.sign:
        sign(args)
    elif args.verify:
        verify(args)
    elif args.init:
        init(args)
    else:
        show_help(args)

def init(args):

    if args.publickeyfile is None or args.secretkeyfile is None:
        logging.error("Please specify files using --secretkeyfile and --publickeyfile")
        sys.exit(1)

    cmd = ['minisign','-G','-p',args.publickeyfile,'-s',args.secretkeyfile]

    if args.force:
        cmd.append('-f')

    logging.info("Please type your password:")
    process = subprocess.Popen(cmd,stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()
    print stdout

    #print('returncode:', completed.returncode)
    #print('Have {} bytes in stdout:\n{}'.format(
    #    len(completed.stdout),
    #    completed.stdout.decode('utf-8'))
    #)

def sign(args):

    if args.secretkeyfile is None or args.infile is None or args.outfile is None:
         logging.error("Please specify files using --secretkeyfile, --infile, and --outfile")       
         sys.exit(1)

    tf = tempfile.NamedTemporaryFile()
    cmd = ['minisign','-S','-H','-m',args.infile, '-t',trusted_comment,'-c','auntrusted','-x',tf.name,'-s',args.secretkeyfile]
    process = subprocess.Popen(cmd,stdout=subprocess.PIPE)
    print ' '.join(cmd)
    stdout, stderr = process.communicate()
    print stdout

    tf.readline() # discard untrusted comment
    signature1 = tf.readline().strip()
    tf.readline() # discard trusted comment
    signature2 = tf.readline().strip()

    eol = '\n' # *nix
    with open(args.infile,'rb') as infh:
        with open(args.outfile,'wb') as outfh:
            topline = infh.readline()
            outfh.write(topline)

            last2 = topline[-2:]
            if last2 == '\r\n':
                eol = last2 # dos
            elif last2[-1] == '\r':
                eol = '\r\n' # mac

            #beol = bytes(eol,'ascii')
            beol = bytes(eol)

            aline = infh.readline()

            while aline and aline.startswith(b'#') and not aline.startswith(b'# rsid'):
                outfh.write(aline)
                aline = infh.readline()

            outfh.write(b'##signature1=')
            outfh.write(signature1)
            outfh.write(beol)

            outfh.write(b'##signature2=')
            outfh.write(signature2)
            outfh.write(beol)

            outfh.write(aline)

            chunksize = 8192

            chunk = infh.read(chunksize)
            while chunk:
                outfh.write(chunk)
                chunk = infh.read(chunksize)

    outfh.close()
    infh.close()

def verify(args):


    if args.publickeyfile is None or args.infile is None:
         logging.error("Please specify files using --publickeyfile and --infile")       
         sys.exit(1)

    sigfh = tempfile.NamedTemporaryFile()
    outfh = tempfile.NamedTemporaryFile()

    with open(args.infile,'rb') as infh:
        aline = infh.readline()

        signature1 = None
        signature2 = None

        while aline and aline.startswith(b'#'):
            if aline.startswith(b'##signature'):
                if aline.startswith(b'##signature1='):
                    signature1 = aline[13:].strip()

                elif aline.startswith(b'##signature2='):
                    signature2 = aline[13:].strip()
            else:
                outfh.write(aline)
            aline = infh.readline()
        outfh.write(aline)

        if not (signature1 and signature2):
            sys.stderr.write("Does not look like a signed file\n")
            sys.exit(-2)

        sigfh.write(b'untrusted comment: \n')
        sigfh.write(signature1)
        sigfh.write(bytes('\ntrusted comment: %s\n' % trusted_comment))
        sigfh.write(signature2)
        sigfh.write(b'\n')
        sigfh.flush()


        chunksize = 8192

        chunk = infh.read(chunksize)
        while chunk:
            outfh.write(chunk)
            chunk = infh.read(chunksize)

    outfh.flush()




    cmd = ['minisign','-V','-x',sigfh.name,'-m',outfh.name,'-p',args.publickeyfile]
    process = subprocess.Popen(cmd,stdout=subprocess.PIPE)
    stdout = process.communicate()
    print stdout

def main():
    args = init_args()
    handle_args(args)

if __name__ == '__main__':
    main()
