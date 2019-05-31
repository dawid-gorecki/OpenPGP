from PGPMessages.message import PGPMessage
import argparse

def main():
    parser = argparse.ArgumentParser(description="OpenPGP implementation.")
    parser.add_argument('-o', "--outfile", required=False, help='Output file.', type=str)
    parser.add_argument('--key', required=False, help='File containing key.', type=str)
    parser.add_argument('--infile', required=True, help='Input file.', type=str)
    parser.add_argument('--verify', action='store_true', help='Verify message.')
    parser.add_argument('--list-packets', action='store_true', help='List packets in file.')
    parser.add_argument('--sign', action='store_true', help='Sign data file.')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt PGP file.')
    parser.add_argument('--unpack', action='store_true', help='Unpack message in PGP packet.')
    args = parser.parse_args()
    if args.verify:
        if args.key is None:
            print('Please provide a key.')
        else:
            msg = PGPMessage()
            key_msg = PGPMessage()
            msg.open_pgp_file(args.infile)
            key_msg.open_pgp_file(args.key)
            verified = msg.verify_message(key_msg)
            if args.outfile is not None and verified:
                msg.unpack_message(args.outfile)
            elif args.outfile is not None:
                print('Message not unpacked.')
    elif args.list_packets:
        msg = PGPMessage()
        msg.open_pgp_file(args.infile)
        msg.list_packets()
    elif args.sign:
        if args.key is None:
            print('Please provide a key.')
        elif args.outfile is None:
            print('Please provide output file name.')
        else:
            msg = PGPMessage()
            msg.open_data_file(args.infile)
            key_msg = PGPMessage()
            key_msg.open_pgp_file(args.key)
            msg.sign_message(key_msg)
            msg.write_gpg_file(args.outfile)
    elif args.decrypt:
        if args.key is None:
            print('Please provide a key.')
        elif args.outfile is None:
            print('Please provide output file name.')
        else:
            msg = PGPMessage()
            msg.open_pgp_file(args.infile)
            key_msg = PGPMessage()
            key_msg.open_pgp_file(args.key)
            out_msg = PGPMessage()
            out_msg.from_bytes(msg.decrypt_message(key_msg))
            out_msg.write_gpg_file(args.outfile)
    elif args.unpack:
        if args.outfile is None:
            print('Please provide output file name.')
        else:
            msg = PGPMessage()
            msg.open_pgp_file(args.infile)
            msg.unpack_message(args.outfile)

if __name__=='__main__':
    main()