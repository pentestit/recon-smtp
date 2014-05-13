# packages required for framework integration
import module
# module specific packages
import socket
import re
import time

# Module is a simple port of smtp-user-enum.pl from 
# http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum

class Module(module.Module):

    def __init__(self, params):
        module.Module.__init__(self, params)
        # module options
        self.register_option('rhost', None, 'yes', 'Remote mail server to query.')
        self.register_option('rport', 25, 'yes', 'Remote port of listening mail server.')
        self.register_option('method', 'VRFY', 'yes', 'Method of verification to use: VRFY, EXPN, or RCPT.')
        self.register_option('delay', 3000, 'yes', 'Delay (ms) between sequential requests to the mail server.')
        self.register_option('clobber', False, 'yes', 'Drop existing entries in \'verified\' table.')
        self.register_option('from', None, 'no', 'MAIL FROM address to use with RCPT verification method.')
        self.info = {
                     'Name': 'SMTP User Enumerator',
                     'Author': 'Cody Wass',
                     'Description': 'Queries a mail server using addresses in the \'contacts\' database to determine which are valid.  Results are currently stored in a newly created \'verified\' table.',
                     }

    def module_run(self):
        self.output("Starting smtp-user-enum module...")
        self.output("---------------------------------------------------------")
        self.output("|                     Scan Results                      |")
        self.output("---------------------------------------------------------")

        if not self.options['from'] and self.options['method'] == 'RCPT':
            self.alert('Using RCPT with no \'from\' address specified - using user@example.com.')
            self.options['from'] = 'user@example.com'
        
        # Prepare table to hold results
        if self.options['clobber']:
            self.query("DROP TABLE IF EXISTS verified")
            self.query("CREATE TABLE verified (email TEXT)")
        else:
            self.query("CREATE TABLE IF NOT EXISTS verified (email TEXT)")
        
        # Grab email addresses from the database
        email_list = self.query('SELECT email FROM contacts WHERE email IS NOT NULL')
        
        # Make sure we actually got results
        if len(email_list) == 0:
                self.error('No email addresses found in table')
                return
        
        # Step through entries in our result set
        for entry in email_list:
            self.verify_email(entry[0]) 
            time.sleep(self.options['delay'] / 1000)

        self.output("---------------------------------------------------------")
        self.output("|                    Scan Finished                      |")
        self.output("---------------------------------------------------------")


    def verify_email(self, email):

        # Make sure we successfully create the socket for SMTP communication.
        # Would wrap in try, but framework catches timeout/socket errors.   
        server_conn = socket.create_connection([self.options['rhost'], self.options['rport']])
        # Read server's 220 ready.
        data = server_conn.recv(1024)
        self.verbose('Server says: ' + data)

        if (data[:3] == '220'):
        # server responded with '220 go ahead'

            if (self.options['method'] == 'VRFY'):
                # Send our HELO.
                server_conn.send('HELO\r\n')
                data = server_conn.recv(1024)
                # Send VRFY and grab response.
                self.verbose('Trying address: ' + email + '...')
                server_conn.send('VRFY ' + email + '\r\n')

            elif (self.options['method'] == 'EXPN'):
                # Send our HELO.
                server_conn.send('HELO\r\n')
                data = server_conn.recv(1024)
                # Send EXPN and grab response.
                self.verbose('Trying address: ' + email + '...')
                server_conn.send('EXPN ' + email + '\r\n')

            elif (self.options['method'] == 'RCPT'):
                # Send our HELO.
                server_conn.send('HELO\r\n')
                data = server_conn.recv(1024)
                server_conn.send('MAIL FROM:<' + self.options['from'] + '>\r\n')
                data = server_conn.recv(1024)
                self.verbose('Trying address: ' + email + '...')
                server_conn.send('RCPT TO:<' + email + '>\r\n')

            else:
                self.error('Unknown method: ' + self.options['method'] + ' in use.')
        

            # Grab server's response.
            data = server_conn.recv(1024)

            # Check server response for match.
            if (re.search(r'2\d\d', data)):
                # We got a 2xx response, should mean user exists.
                self.output(email + ' exists!')
                self.verbose('Server reponse: ' + data)

                # Add email to verified-contacts table.
                self.query('INSERT INTO verified VALUES (?)', (email,))
                
            elif (re.search(r'5\d\d', data)):
                # 5xx response, user does not exist.
                self.verbose(email + ' does not exist.')
                self.verbose('Server response: ' + data)

            else:
                # Other (4xx or similar) response. Print out to user.
                self.output('Unknown response: ' + data)

            # Reset SMTP connection in preparation for another loop.
            server_conn.send('RSET\r\n')
            data = server_conn.recv(1024)
            
            # Blow away socket for next connection.
            server_conn.shutdown(socket.SHUT_RDWR)
            server_conn.close()
            return

        else:
            self.error('ERROR: Server didn\'t respond with \'220\'.')
            self.error('ERROR: Response was: ' + data)

            server_conn.shutdown(socket.SHUT_RDWR)
            server_conn.close()
            return
