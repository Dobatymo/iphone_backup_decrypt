from argparse import ArgumentParser

from iphone_backup_decrypt import EncryptedBackup

def main():
    parser = ArgumentParser()
    parser.add_argument("--backup-path", required=True)
    parser.add_argument("--out-path", required=True)
    parser.add_argument("--passphrase", required=False)
    args = parser.parse_args()

    if args.passphrase:
        passphrase = args.passphrase
    else:
        passphrase = input("Please enter the backup passphrase: ")

    backup = EncryptedBackup(backup_directory=args.backup_path, passphrase=passphrase)
    backup.extract_all(args.out_path)

if __name__ == "__main__":
    main()
