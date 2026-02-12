MaildirTools - Email analysis and conversion utilities for Maildir and mbox formats.

Copyright (C) 2026 Philippe TEMESI - https://www.tems.be


OVERVIEW:
MaildirTools is a Rust-based command-line tool that provides two main functionalities:

    Email Analysis - Extract metadata, headers, and content from email files

    Format Conversion - Convert between Maildir directories and mbox files

FEATURES:
Email Analysis:

    Extract sender, recipient, subject, and CC/BCC information

    Display SMTP transit servers and extract IP addresses

    Verify DKIM signatures and show signing domains

    Decode Base64 and Quoted-Printable encoded content

    Extract and save attachments

    View plain text and HTML email bodies

    Bulk mode for script-friendly output

Maildir/mbox Conversion:

    Convert Maildir directories (cur/, new/, tmp/) to mbox format

    Convert mbox files to Maildir directory structure

    Preserves email timestamps during conversion

    Handles large email collections efficiently

INSTALLATION:
Prerequisites: Rust and Cargo (install from rustup.rs)

From Source:
git clone https://github.com/philtems/maildirtools.git
cd maildirtools
cargo build --release
sudo cp target/release/maildirtools /usr/local/bin/

Using Cargo:
cargo install --git https://github.com/philtems/maildirtools

USAGE - EMAIL ANALYSIS:
Basic email inspection: maildirtools email.eml
Show sender, recipient, subject: maildirtools email.eml -s -d -subject
Extract SMTP IP addresses: maildirtools email.eml -smtp -ip
Check DKIM status: maildirtools email.eml -dkim
Save attachments: maildirtools email.eml -f ./attachments/
Bulk mode: maildirtools email.eml -dkim -bulk

USAGE - MAILDIR/MBOX CONVERSION:
Maildir to mbox: maildirtools --tombox --maildir ~/Maildir/ --mbox ~/backup.mbox
mbox to Maildir: maildirtools --tomaildir --maildir ~/Maildir/ --mbox ~/archive.mbox

COMMAND LINE OPTIONS - ANALYSIS:
-s Show sender
-d Show recipient
-subject Show subject
-c Show CC/BCC recipients
-smtp Show SMTP transit servers
-ip Show only IP addresses from SMTP servers (with -smtp)
-dkim Show DKIM information (absent, valid, invalid)
-bulk Bulk mode: display results without comments, one per line
-f <path> Save attachments to the given path
-text Show plain text body
-html Show HTML body

COMMAND LINE OPTIONS - CONVERSION:
--tombox Convert Maildir to mbox
--tomaildir Convert mbox to Maildir
--maildir <path> Specify Maildir folder path
--mbox <file> Specify mbox file path

COMMAND LINE OPTIONS - GENERAL:
--help Display help information
--version Display version information

EXAMPLES:
Extract sender and subject from multiple emails:
for email in Maildir/cur/*; do
echo "=== $email ==="
maildirtools "$email" -s -subject -bulk
done

Find all IP addresses that have handled your emails:
maildirtools inbox.eml -smtp -ip | sort -u

Backup Maildir to mbox and compress:
maildirtools --tombox --maildir ~/Maildir --mbox ~/backup.mbox
gzip ~/backup.mbox

Restore from mbox backup:
gunzip ~/backup.mbox.gz
maildirtools --tomaildir --maildir ~/Maildir --mbox ~/backup.mbox

TECHNICAL DETAILS:
MaildirTools handles:

    Encodings: UTF-8, Windows-1252, ISO-8859-1

    Transfer encodings: Base64, Quoted-Printable

    Header encodings: RFC 2047 (=?UTF-8?B?...?=)

    Email formats: Standard RFC 2822 messages

    Maildir structure: cur/, new/, tmp/ directories

    mbox format: Standard mboxo variant with "From " lines


AUTHOR:
Philippe TEMESI
Website: https://www.tems.be
GitHub: @philtems
Repository: https://github.com/philtems/maildirtools

SUPPORT:
If you encounter any issues or have questions, please open an issue on GitHub:
https://github.com/philtems/maildirtools/issues
