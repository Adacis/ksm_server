import os
import re
import sys
import fcntl
import argparse
import traceback
import struct
import sqlalchemy
import pyhsm

def parse_args():
    parser = argparse.ArgumentParser(description = 'Decrypt AEADs',
                                     add_help = True,
                                     formatter_class = argparse.ArgumentDefaultsHelpFormatter,
                                     )
    parser.add_argument('-D', '--device',
                        dest='device',
                        required=True,
                        help='YubiHSM device',
                        )
    parser.add_argument('--public-id',
                        dest='public_id',
                        required=True,
                        help='The first public id to decrypt',
                        metavar='INT-OR-MODHEX',
                        )

    return parser.parse_args()

def main():

    args = parse_args()
    

    engine = sqlalchemy.create_engine('mysql://'+os.environ['USER']+':'+os.environ['PASSWORD']+'@'+os.environ['DATABASEHOST']+'/'+os.environ['DATABASE'])
    connection = engine.connect()
    sql = sqlalchemy.sql.text("SELECT * FROM aead_table WHERE public_id = :public_id;")
    result = connection.execute(sql, {'public_id': args.public_id}).fetchall()
    
    hsm = pyhsm.soft_hsm.SoftYHSM.from_file(args.device)
    pt = pyhsm.soft_hsm.aesCCM(hsm.keys[result[0][1]], result[0][1], result[0][3], result[0][2], decrypt = True)
    key = pt[:pyhsm.defines.KEY_SIZE]
    uid = pt[pyhsm.defines.KEY_SIZE:]
    
    print("ykpersonalize -1 -ofixed={} -ouid={} -a{}".format(args.public_id, uid.hex(), key.hex()))

if __name__ == '__main__':
    main()
