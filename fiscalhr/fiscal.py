# -*- coding: utf-8 -*-

'''Helper class for fiscalization in Croatia'''

from __future__ import absolute_import

import re
from uuid import uuid4
from hashlib import md5
from datetime import datetime

import ssl
import httplib
import urllib2
from backports.ssl_match_hostname import match_hostname

from pytz import timezone
from pkg_resources import resource_filename

from OpenSSL import crypto
from xmldsig import XMLDSIG

from suds.client import Client
from suds.sax.parser import Parser
from suds.sax.element import Element
from suds.plugin import MessagePlugin
from suds.transport.https import HttpTransport
from suds.bindings.binding import envns as soap_envns

from logging import getLogger


LOGGER = getLogger(__name__)


class Fiscal():
    '''Helper class for fiscalization in Croatia'''

    TEST_LOCATION = 'https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest'


    def __init__(self, key_path, cert_path, key_passphrase=None,
                 ca_path=None, cis_ca_path=None, cis_cert_cn=None,
                 wsdl_location=None, test=False):

        self.default_ns = 'fis'

        self.key_path = key_path
        self.key_passphrase = key_passphrase

        resource_path = 'fiskalizacija_service/'

        if not ca_path:
            ca_path = resource_path + 'certs/'
            ca_path += 'demo2014_chain.pem' if test else 'FinaRDCChain.pem'
            ca_path = resource_filename(__name__, ca_path)

        # FIX: cis still uses old CA, they shall probably switch to `ca_path`
        if not cis_ca_path:
            cis_ca_path = resource_path + 'certs/'
            cis_ca_path += 'old_democacert.pem' if test else 'old_RDCca.pem'
            cis_ca_path = resource_filename(__name__, cis_ca_path)

        if not cis_cert_cn:
            cis_cert_cn = 'fiskalcistest' if test else 'fiskalcis'

        if not wsdl_location:
            wsdl_location = 'file://'
            wsdl_location += resource_filename(__name__,
                resource_path + 'wsdl/FiskalizacijaService.wsdl')

        xmldsig_plugin = XmlDSigMessagePlugin(key_path, cert_path,
                                              key_passphrase=key_passphrase,
                                              ca_path=ca_path,
                                              cis_ca_path=cis_ca_path,
                                              cis_cert_cn=cis_cert_cn)

        suds_options = {
            'cache': None,
            'prettyxml': True,
            'timeout': 20,
            'plugins': [xmldsig_plugin],
        }

        if test:
            suds_options['location'] = self.TEST_LOCATION

        self.client = Client(wsdl_location, **suds_options)
        self.client.options.transport = CustomHttpTransport(ca_certs=ca_path)

    def send(self, method_name, data, nosend=False, raw_response=False):
        '''Send request'''

        method = getattr(self.client.service, method_name)
        if not method:
            raise ValueError('Unknown method: %s' % method_name)

        header = self.generate_header()

        if (hasattr(data, 'OznakaZatvaranja')
                and not data.OznakaZatvaranja.value):
            del data.OznakaZatvaranja

        if nosend:
            pre_nosend = self.client.options.nosend
            self.client.options.nosend = True

        response = method(header, data)

        if nosend:
            self.client.options.nosend = pre_nosend
            response = response.envelope
        elif not raw_response:
            response = self.process_response(header, response)

        return response

    def process_response(self, request_hdr, response):
        '''Process response and return response data in dictionary'''

        response = dict(response)

        if 'Zaglavlje' not in response:
            raise Exception('No header in response')
        if 'IdPoruke' not in response['Zaglavlje']:
            raise Exception('No header id in response')
        if str(request_hdr.IdPoruke) != str(response['Zaglavlje']['IdPoruke']):
            raise Exception('Request and response header id do not match')
        del response['Zaglavlje']

        if 'Greske' in response:
            errors = []
            for err in response['Greske']:
                errors.append(dict(err[1][0]))
            raise Exception(errors)

        if 'Signature' in response:
            del response['Signature']

        response['Success'] = True

        return response

    def echo(self, msg):
        '''Send and verify Fiskal CIS echo request'''

        reply = self.client.service.echo(msg)
        if reply == msg:
            print("Echo test successful with reply: %s" % (reply, ))
        else:
            print("Echo test failed with reply: %s" % (reply, ))

    def generate_header(self):
        '''Generate header for Fiskal CIS request'''

        zaglavlje = self.create('Zaglavlje')
        zaglavlje.IdPoruke = uuid4()
        zaglavlje.DatumVrijeme = self.format_time()
        return zaglavlje

    def create(self, name):
        '''Create instances of suds objects and types defined in WSDL'''

        if ':' in name:
            wtype = self.client.factory.create(name)
        else:
            wtype = self.client.factory.create("%s:%s"
                                               % (self.default_ns, name))
        return wtype

    def get_zki_data(self, racun):
        '''Returns data required for receipt signature (ZKI)'''

        zki_fields = (
            'Oib',
            'DatVrijeme',
            'BrRac.BrOznRac',
            'BrRac.OznPosPr',
            'BrRac.OznNapUr',
            'IznosUkupno',
        )

        if not racun:
            raise Exception('Racun not defined')

        racun = dict(racun)

        zki_data = []
        for field in zki_fields:
            field = field.split('.')
            val = racun.get(field[0])
            if val and len(field) == 2:
                val = dict(val).get(field[1])
            if not val:
                raise ValueError('Not defined: %s' % field)
            if 'DatVrijeme' in field:
                val = datetime.strptime(val,
                                        self.get_time_format('DatumVrijeme'))
                val = self.format_time(val, 'RacunDatumVrijeme')
            zki_data.append(str(val))

        return zki_data

    def generate_zki(self, racun):
        '''Generates receipt signature (ZKI)'''

        zki_data = self.get_zki_data(racun)
        zki_data = ''.join(zki_data)
        zki = self.generate_sha1_rsa_md5_signature(zki_data)
        return zki

    def generate_sha1_rsa_md5_signature(self, data):
        '''Generates SHA1-RSA-MD5 hash required for receipt signature (ZKI)'''

        key_pem = open(self.key_path).read()

        if self.key_passphrase:
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem,
                                          self.key_passphrase)
        else:
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)

        signature = crypto.sign(pkey, data, 'sha1')
        signature = md5(signature).hexdigest()

        return signature

    @classmethod
    def localtime_now(cls):
        '''Return the current local date and time in Croatia'''

        return datetime.now(timezone('Europe/Zagreb'))

    @classmethod
    def format_time(cls, local_time=None, type_name='DatumVrijeme'):
        '''Returns local date and time in requested format'''

        time_format = cls.get_time_format(type_name)

        if local_time is None:
            local_time = cls.localtime_now()
        elif not local_time.tzinfo:
            local_time = timezone('Europe/Zagreb').localize(local_time)
        else:
            local_time = local_time.astimezone(timezone('Europe/Zagreb'))

        return local_time.strftime(time_format)

    @classmethod
    def get_time_format(cls, type_name='DatumVrijeme'):
        '''Returns date and time format strings used in Fiskal communication'''

        if type_name == 'DatumVrijeme':
            time_format = '%d.%m.%YT%H:%M:%S'
        elif type_name == 'RacunDatumVrijeme':
            time_format = '%d.%m.%Y %H:%M:%S'
        elif type_name == 'Datum':
            time_format = '%d.%m.%Y'
        else:
            raise ValueError('Unknown type name: %s' % type_name)

        return time_format

    @classmethod
    def format_decimal(cls, decimal):
        '''Formats float for Fiskal communication'''

        return '%.2f' % decimal


class XmlDSigMessagePlugin(MessagePlugin):
    '''Suds message plugin for generating and verifying XML signatures'''

    DTD_TEST_ID = '<!DOCTYPE test [<!ATTLIST %s Id ID #IMPLIED>]>'
    RE_DTD_TEST = re.compile(r'<!DOCTYPE\s+test\s+.*?]>\r?\n?', flags=re.I|re.S)

    RE_XML_HEADER = re.compile(r'<\?xml\s+.*?\?>', flags=re.I|re.S)

    def __init__(self, key_path, cert_path, key_passphrase=None,
                 ca_path=None, cis_ca_path=None, cis_cert_cn=None):

        self.key_path = key_path
        self.cert_path = cert_path
        self.key_passphrase = key_passphrase

        self.ca_path = ca_path
        self.cis_ca_path = cis_ca_path
        self.cis_cert_cn = cis_cert_cn

    def sending(self, context):
        '''Signs XML before sending'''

        signature_template = '''
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
              <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
              <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
              <Reference URI="#%(REFERENCE_ID)s">
                <Transforms>
                  <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                  <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                </Transforms>
                <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                <DigestValue></DigestValue>
              </Reference>
              </SignedInfo>
              <SignatureValue />
              <KeyInfo>
                <X509Data>
                  <X509Certificate />
                </X509Data>
              </KeyInfo>
            </Signature>
        '''

        envelope_element = Parser().parse(string=context.envelope).root()
        envelope_element.refitPrefixes()

        body = envelope_element.getChild('Body')
        payload = body[0]

        qname = payload.qname()
        if 'Echo' in qname:
            return

        reference_id = "refId:%s" % uuid4()
        payload.set('Id', reference_id)
        signature_template %= {'REFERENCE_ID': reference_id}

        signature_element = Parser().parse(string=signature_template).root()
        payload.append(signature_element)

        envelope = self.DTD_TEST_ID % qname
        envelope += envelope_element.str()
        envelope = envelope.encode('utf-8')

        signer = XMLDSIG()
        signer.load_key(self.key_path,
                        password=self.key_passphrase,
                        cert_path=self.cert_path)
        context.envelope = signer.sign(envelope)
        context.envelope = self.RE_DTD_TEST.sub('', context.envelope)

    def received(self, context):
        '''Verifies XML signature of received message'''

        def _extract_keyinfo_cert(payload):
            '''Extract the signing certificate from KeyInfo.'''

            cert_der = payload.getChild('Signature')
            cert_der = cert_der.getChild('KeyInfo')
            cert_der = cert_der.getChild('X509Data')
            cert_der = cert_der.getChild('X509Certificate').getText().strip()
            cert_der = cert_der.decode('base64')
            return cert_der

        def _verify_cn(cert, cis_cert_cn):
            '''Verify signature certificate common name'''

            common_name = cert.get_subject().commonName

            if common_name != cis_cert_cn:
                raise Exception('Invalid certificate common name in response: '
                                '%s != %s' % (cis_cert_cn, common_name))

        def _verify_cert(cert, issuer_cert_path):
            '''Verify cert was issued by issuer_cert_path.'''

            try:
                store = crypto.X509Store()

                with open(issuer_cert_path) as f:
                    _ca = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
                    store.add_cert(_ca)

                store_ctx = crypto.X509StoreContext(store, cert)
                store_ctx.verify_certificate()

            except Exception as e:
                raise Exception('CIS certificate not issued by CIS CA')

        def _fault(code, msg):
            '''Generate fault XML'''

            faultcode = Element('faultcode').setText(code)
            faultstring = Element('faultstring').setText(msg)
            fault = Element('Fault').append([faultcode, faultstring])
            body = Element('Body').append(fault)
            envelope = Element('Envelope', ns=soap_envns)
            envelope.append(body)
            envelope.refitPrefixes()

            return envelope.str()


        valid_signature = False

        try:
            if not self.cis_ca_path:
                raise Exception('Certificate Authority not defined')

            reply_element = Parser().parse(string=context.reply).root()
            body = reply_element.getChild('Body')
            payload = body[0]
            qname = payload.qname()
            cert_der = _extract_keyinfo_cert(payload)
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)

            if 'Echo' in qname or 'Fault' in qname:
                LOGGER.warning('Not verifying certificate for qname: %s', qname)
                return

            if self.cis_cert_cn:
                _verify_cn(cert, self.cis_cert_cn)
            else:
                LOGGER.warning('CIS certificate common name not configured')

            # explicit signing cert CA check
            if self.cis_ca_path:
                _verify_cert(cert, self.cis_ca_path)
            else:
                LOGGER.warning('CIS certificate CA not configured')

            reply = self.DTD_TEST_ID % qname
            reply += self.RE_XML_HEADER.sub('', context.reply)

            verifier = XMLDSIG()

            # signing cert's CA
            verifier.load_cert(self.cis_ca_path)

            # signing cert given with KeyInfo
            verifier.load_key(cert_der, key_format='cert-der')

            valid_signature = verifier.verify(reply)

        except Exception as exc:
            LOGGER.exception('%s: %s', exc, context.reply)
            context.reply = _fault('Client',
                                   'Invalid response signature: %s' % exc)
        else:
            if not valid_signature:
                LOGGER.error('Invalid response signature: %s', context.reply)
                context.reply = _fault('Client',
                                       'Invalid response signature')


class CustomHttpTransport(HttpTransport):
    '''
    Class just for adding CustomHTTPErrorProcessor to urllib2
    handlers list
    '''

    def __init__(self, **kwargs):
        if 'ca_certs' in kwargs:
            self.ca_certs = kwargs['ca_certs']
            del kwargs['ca_certs']

        HttpTransport.__init__(self, **kwargs)

    def u2handlers(self):
        '''Adds CustomHTTPErrorProcessor to handlers list'''

        handlers = HttpTransport.u2handlers(self)
        handlers.append(VerifiedHTTPSHandler(ca_certs=self.ca_certs))
        handlers.append(CustomHTTPErrorProcessor())
        return handlers


class CustomHTTPErrorProcessor(urllib2.BaseHandler):
    '''
    Error processor for urllib2 which returns response data (i.e. does not
    raise exception) on HTTP error code 500 (Internal Server Error) because
    Fiskal CIS returns HTTP 500 on all errors
    '''

    def http_error_500(self, request, response, code, msg, hdrs):
        '''Return response data on HTTP error code 500'''

        return response


class CertValidatingHTTPSConnection(httplib.HTTPConnection):
    '''
    HTTP connection class with SSL hostname verification

    https://gist.github.com/schlamar/2993700
    '''

    default_port = httplib.HTTPS_PORT

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 ca_certs=None, strict=None, **kwargs):

        httplib.HTTPConnection.__init__(self, host, port, strict, **kwargs)
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_certs = ca_certs
        if self.ca_certs:
            self.cert_reqs = ssl.CERT_REQUIRED
        else:
            self.cert_reqs = ssl.CERT_NONE

    def connect(self):
        httplib.HTTPConnection.connect(self)
        self.sock = ssl.wrap_socket(self.sock, keyfile=self.key_file,
                                    certfile=self.cert_file,
                                    cert_reqs=self.cert_reqs,
                                    ca_certs=self.ca_certs)
        if self.cert_reqs & ssl.CERT_REQUIRED:
            cert = self.sock.getpeercert()
            hostname = self.host.split(':', 0)[0]
            # Fix for invalid subjectAltName in cis.porezna-uprava.hr certificate
            if 'subjectAltName' in cert:
                del cert['subjectAltName']
            match_hostname(cert, hostname)


class VerifiedHTTPSHandler(urllib2.HTTPSHandler):
    '''
    urllib2 handler class which verifies SSL hostname

    https://gist.github.com/schlamar/2993700
    '''

    def __init__(self, **kwargs):
        urllib2.HTTPSHandler.__init__(self)
        self._connection_args = kwargs

    def https_open(self, req):
        def http_class_wrapper(host, **kwargs):
            full_kwargs = dict(self._connection_args)
            full_kwargs.update(kwargs)
            return CertValidatingHTTPSConnection(host, **full_kwargs)

        return self.do_open(http_class_wrapper, req)
