import os
import sys
import argparse
import pyhsm
import pyhsm.yubikey
import struct
import sqlalchemy

default_device = "/dev/ttyACM0"
default_dir = "/var/cache/yubikey-ksm/aeads"

def parse_args():
    """
    Parse the command line arguments
    """
    parser = argparse.ArgumentParser(description = "Generate secrets for YubiKeys using YubiHSM",
                                     add_help=True,
                                     formatter_class = argparse.ArgumentDefaultsHelpFormatter,
                                     )
    parser.add_argument('-D', '--device',
                        dest='device',
                        default=default_device,
                        required=False,
                        help='YubiHSM device',
                        )
    parser.add_argument('-U', '--urldb',
                        dest='urldb',
                        required=True,
                        help='Mysql Database',
                        )
    parser.add_argument('-O', '--output-dir', '--aead-dir',
                        dest='output_dir',
                        default=default_dir,
                        required=False,
                        help='Output directory (AEAD base dir)',
                        )
    parser.add_argument('-c', '--count',
                        dest='count',
                        type=int, default=1,
                        required=False,
                        help='Number of secrets to generate',
                        )
    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true', default=False,
                        help='Enable verbose operation',
                        )
    parser.add_argument('--public-id-chars',
                        dest='public_id_chars',
                        type=int, default=12,
                        required=False,
                        help='Number of chars in generated public ids',
                        )
    parser.add_argument('--key-handles',
                        dest='key_handles',
                        nargs='+',
                        required=True,
                        help='Key handles to encrypt the generated secrets with',
                        )
    parser.add_argument('--start-public-id',
                        dest='start_id',
                        required=False,
                        help='The first public id to generate AEAD for',
                        )

    parser.add_argument('--random-nonce',
                        dest='random_nonce',
                        required=False,
                        action='store_true', default=False,
                        help='Let the HSM generate nonce',
                        )

    return parser.parse_args()

def args_fixup(args):
    if not os.path.isdir(args.output_dir):
        sys.stderr.write("Output directory '%s' does not exist.\n" % (args.output_dir))
        sys.exit(1)

    keyhandles_fixup(args)

    #Si pas d'identifiant fourni il va le chercher dans la base de donnees
    if args.start_id:
        args.start_id = start_id_fixup(args.start_id)
    else:
        myresult = get_last_id(args.urldb)
        for val in myresult:
            print (val[0])
            args.start_id = start_id_fixup(val[0])+1

    print (args.start_id)
     

def start_id_fixup(start_id):
    try:
        n = int(start_id)
    except ValueError:
        hexstr = pyhsm.yubikey.modhex_decode(start_id)
        n = int(hexstr, 16)

    if(n <= 0):
        sys.stderr.write("Start ID must be greater than 0, was %d\n" % (n))
        sys.exit(1)

    return n
        
def get_last_id(urldb):

    engine = sqlalchemy.create_engine(urldb)
    connection = engine.connect()
    sql = sqlalchemy.sql.text("SELECT max(public_id) FROM aead_table;")
    # insert the query
    result = connection.execute(sql).fetchall()
    return result


def keyhandles_fixup(args):
    """
    Walk through the supplied key handles and normalize them, while keeping
    the input format too (as value in a dictionary). The input format is
    used in AEAD filename paths.
    """
    new_handles = {}
    for val in args.key_handles:
        for this in val.split(','):
            n = pyhsm.util.key_handle_to_int(this)
            new_handles[n] = this

    args.key_handles = new_handles

def insert_query(publicId, aead, keyhandle, urldb):
    engine = sqlalchemy.create_engine(urldb)
    metadata = sqlalchemy.MetaData()
    aeadobj = sqlalchemy.Table('aead_table', metadata, autoload=True, autoload_with=engine)
    connection = engine.connect()

    # turn the keyhandle into an integer
    if not keyhandle == aead.key_handle:
        print("WARNING: keyhandle does not match aead.key_handle")
        return None

    # creates the query object
    try:
        sql = aeadobj.insert().values(public_id=publicId, keyhandle=aead.key_handle, nonce=aead.nonce, aead=aead.data)
        # insert the query
        result = connection.execute(sql)
        return result
    except sqlalchemy.exc.IntegrityError:
        pass
    return None

def gen_keys(hsm, args):
    for int_id in range(args.start_id, args.start_id + args.count):

        public_id = ("%x" % int_id).rjust(args.public_id_chars, '0')
        padded_id = pyhsm.yubikey.modhex_encode(public_id)
        num_bytes = len(pyhsm.aead_cmd.YHSM_YubiKeySecret('a' * 16, 'b' * 6).pack())
        hsm.load_random(num_bytes)

        for kh in args.key_handles.keys():
            # numero de la clef a utiliser
            if args.random_nonce:
                nonce = ""
            else:
                nonce = public_id.decode('hex')

            aead = hsm.generate_aead(nonce, kh)
            pt = pyhsm.soft_hsm.aesCCM(hsm.keys[kh], aead.key_handle, aead.nonce, aead.data, decrypt = True)
            key = pt[:pyhsm.defines.KEY_SIZE]
            uid = pt[pyhsm.defines.KEY_SIZE:]
            
            print("ykpersonalize -1 -ofixed=%s -ouid=%s -a%s" % (padded_id,uid.encode('hex'),key.encode('hex')))

        if not insert_query(padded_id, aead, kh, args.urldb):
            print("WARNING: could not insert %s" % public_id)

    print ("\nDone\n NE PAS OUBLIER DANS LE FREERADIUS /ETC/PASSWD && /ETC/SHADOW")


def main():
    
    # Check des arguments par le parser
    args = parse_args()

    # quelques traitements sur les arguments
    args_fixup(args)

    # Retour console 
    print ("Nombre de clef a generer	: %s" % (args.count))
    print ("start public_id		: %s (0x%x)" % (args.start_id, args.start_id))
    print ("YHSM device		: %s" % (args.device))

    validation = raw_input("\nVoulez vous proceder ? (y/N)\n")
    if validation and (validation.lower() == "yes" or validation.lower()== "y") :
        hsm = pyhsm.soft_hsm.SoftYHSM.from_file(args.device)
        gen_keys(hsm, args) 


if __name__ == '__main__':
    main()