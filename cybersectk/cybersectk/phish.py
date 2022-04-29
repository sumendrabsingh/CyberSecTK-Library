import csv
import email
import imaplib
import html.parser #BeautifulSoup is a non-standard library
import quopri
import pathlib
import time

def phish(email=None, password=None, server=None, l=False, mailbox=None, process=1):
    '''The phish function produces a personal corpus of phishing features 
    extracted from an IMAP server of the user's choice.

    Parameters:
    email    (str):  Email login. Required.
    password (str):  Email password. Note, modern email services require app passwords. Required.
    server   (str):  IMAP server. This method connects via SSL port 993 only. Required.
    l        (bool): List IMAP mailboxes to console for use with next argument. Required.
    mailbox  (str):  Mailbox to use. Optional if l = True, else required.
    process  (int):  Number of emails to process. Default: 1, Max: 100.

    Returns:
    None

    Output:
    CSV. File will be placed in current working directory containing various phishing 
    feature extractions. The filename is dynamic to support multiple runs of this function. 
    Filename will be a combination of email address provided to function and current 
    date time stamp. Additionally, each message email processed will be placed in a "msg"
    folder at the root of the CyberSecTK folder hierarchy. 
    '''

    if not email and not password and not server:
        print(f'Required params missing. Can not continue.')
        return
    elif email and password and server and l == True:
        if not all(isinstance(i, str) for i in [email, password, server]):
            print(f'Invalid param types supplied. Unable to continue.')
            return
        print_mailbox_list(email, password, server)
        return
    elif email and password and server and l == False and mailbox and process:
        if not all(isinstance(i, str) for i in [email, password, server, mailbox]):
            print(f'Invalid param types supplied. Unable to continue.')
            return
        if not isinstance(process, int):
            print(f'Invalid param types supplied. Unable to continue.')
            return            
        main(email, password, server, l, mailbox, process)
        return
    else:
        print(f'Params invalid. Review help for assistance.')

def main(ema, pwd, srv, l, mlb, prc):
    mail_ids = []
    # linkparser = LinkParser()
    imap_ssl = connect_to_server(srv)
    mail = login_to_server(ema, pwd, imap_ssl)
    feedback = 'Processing.'
    terms = phishing_terms()
    illegal_chars = {47: 95, 60: 95, 62: 95, 58: 95, 34: 95, 92: 95, 124: 95, 63: 95, 42: 95}
    fieldnames = ['Message_ID', 'From', 'To', 'Subject', 'DKIM', 'SPF', 'DMARC', 'Anchor_HREF', 'Weight_Gain']

    if prc > 100:
        prc = 100

    statusse, messages = mail.select(mlb, readonly=True)    
    statussr, data = mail.search(None, 'ALL')

    messages = int(messages[0])

    if messages <= 0:
        print(f'Mailbox empty, unable to proceed.')
        return
    
    pathlib.Path('./msg').mkdir(parents=True, exist_ok=True)

    timestr = time.strftime("%Y%m%d-%H%M%S")

    reportfile = './' + ema + '.' + timestr + '.csv'

    with open(reportfile, 'w', newline = '', encoding='utf-8') as csv_report_file:
        writer = csv.DictWriter(csv_report_file, fieldnames=fieldnames)
        writer.writeheader()

    for block in data:
        mail_ids += block.split()

    # for i in mail_ids[0:prc]:
    for i in range(messages, messages - prc, -1):
        weight_gain = 0
        statussf, data = mail.fetch(str(i), '(RFC822)')

        feedback += '.'

        print('\r' + feedback, end='', flush=True)

        for response_part in data:
            if isinstance(response_part, tuple):
                # https://stackoverflow.com/questions/2802726/putting-a-simple-if-then-else-statement-on-one-line
                message = 'None' if email.message_from_bytes(response_part[1]) is None else email.message_from_bytes(response_part[1])
                mail_from, fc = ('None', 0) if message['from'] is None else email.header.decode_header(message['from'])[0]
                mail_to, tc = ('None', 0) if message['to'] is None else email.header.decode_header(message['to'])[0]
                mail_subject, sc = ('None', 0) if message['subject'] is None else email.header.decode_header(message['subject'])[0]
                message_id = message['message-id']
                auth_results = message.get("Authentication-Results", None)

                if message.is_multipart():
                    mail_content = ''
                    parts = walk_message(message)
                    for part in parts:                        
                        mail_content += str(part, 'utf-8', 'ignore')
                else:
                    mail_content = message.get_payload()
                    if mail_content.isascii():
                        mail_content = quopri.decodestring(mail_content).decode("utf-8", "ignore")

                if fc:
                    mail_from = str(mail_from, fc)
                if tc:
                    mail_to = str(mail_to, tc)
                if sc:
                    mail_subject = str(mail_subject, sc)

                dkim = 'None'
                spf = 'None'
                dmarc = 'None'
                if auth_results != None:
                    auth_results = auth_results.lower()
                    ar = auth_results.split()
                    for item in ar:
                        if item.startswith('dkim'):
                            s = item.split('=')
                            dkim = s[1].upper()
                        elif item.startswith('spf'):
                            s = item.split('=')
                            spf = s[1].upper()
                        elif item.startswith('dmarc'):
                            s = item.split('=')
                            dmarc = s[1].upper()

                message_id_normalized = message_id.translate(illegal_chars)                
                with open('./msg/' + message_id_normalized + ".txt", "w", encoding="utf-8") as f:
                    f.write(mail_content)
            
                for key, value in terms.items():
                    hits = mail_content.lower().count(key)
                    if hits > 0:
                        weight_gain += float(value) * hits

                linkparser = LinkParser()

                linkparser.feed(mail_content)

                with open(reportfile, 'a', newline='', encoding='utf-8') as csv_report_file:
                    writer = csv.DictWriter(csv_report_file, fieldnames=fieldnames)
                    for element in linkparser.data:
                        if element:
                            #  ['Message_ID', 'From', 'To', 'Subject', 'DKIM', 'SPF', 'DMARC', 'Anchor_HREF', 'Weight_Gain']
                            writer.writerow({'Message_ID': message_id, 'From': mail_from, 'To': mail_to, 'Subject': mail_subject, 'DKIM': dkim, 'SPF': spf, 'DMARC': dmarc, 'Anchor_HREF': element, 'Weight_Gain': weight_gain })

    print(f'\nCompleted! Dataset written to ' + reportfile.replace(reportfile[:3], '') + '.')
    mail.close()
    mail.logout()

class LinkParser(html.parser.HTMLParser):
    def __init__(self):
        html.parser.HTMLParser.__init__(self)
        self.data = []
        self.capture = False

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            # self.capture = True
            for attr in attrs:
                if attr[0] == 'href':
                    if attr[1].startswith('http'):
                        self.data.append(attr[1])

    # def handle_endtag(self, tag):
    #     if tag == 'a':
    #         self.capture = False
    
    # def handle_data(self, data):
    #     if self.capture:
    #         data = data.strip()
    #         if data:
    #             self.data.append(data)
    #         else:
    #             self.data.append(' ')

def walk_message(m):
    for part in m.walk():
        # if part.get_content_maintype() == 'multipart' or part.get_content_maintype() == 'image' or part.get_content_maintype() == 'application':
        #     continue
        # yield part.get_payload(decode=True)
        if part.get_content_maintype() == "text":
            yield part.get_payload(decode=True)
        # yield part.get_payload()

def phishing_terms():
    with open('cybersectk/phishing_terms', newline='', encoding='utf-8') as input:
        reader = csv.reader(input)
        terms = {rows[0]:rows[1] for rows in reader}
        return terms

def print_mailbox_list(ema, pwd, svr):
    try:
        imap_ssl = connect_to_server(svr)
        mail = login_to_server(ema, pwd, imap_ssl)
        print(f'\n**********\nList of mailboxes on ' + svr + '.\n')
        for server in mail.list()[1]:
            l = server.decode().split(' "/" ')
            print(l[0] + " = " + l[1])
        print(f'\nEnd of list.\n**********')
        mail.logout()
    except Exception as e:
        print(f'Error obtaining list of mailboxes.')
        print(f'ErrorType: {0}, Error: {1}'.format(type(e), __name__, e))

def connect_to_server(svr):
    try:
        imap_ssl = imaplib.IMAP4_SSL(svr, 993)
        return imap_ssl        
    except Exception as e:
        print(f'Error connecting to IMAP server.')
        print("ErrorType : {}, Error : {}".format(type(e).__name__, e))
        imap_ssl = None

def login_to_server(ema, pwd, imap_ssl):
    try:
        imap_ssl.login(ema, pwd)
        return imap_ssl
    except Exception as e:
        print(f'Error logging into to IMAP server.')
        print("ErrorType : {}, Error : {}".format(type(e).__name__, e))
        imap_ssl = None