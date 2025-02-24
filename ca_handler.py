from __future__ import print_function
import idna
import subprocess
import re
import json
from typing import Tuple, List
# pylint: disable=e0401
from acme_srv.helper import load_config, cert_pem2der, b64_encode, csr_san_get, config_eab_profile_load, \
    config_headerinfo_load, eab_profile_header_info_check


class CAhandler(object):
    """ HARICA CA  handler """

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.allowed_domainlist = []
        self.eab_handler = None
        self.eab_profiling = False
        self.header_info_field = False
        self.requester_email = None
        self.requester_password = None
        self.requester_totp_seed = None
        self.validator_email = None
        self.validator_password = None
        self.validator_totp_seed = None

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _allowed_domainlist_check(self, sans: List[str]) -> str:
        """ check allowed domainlist """
        self.logger.debug('CAhandler._allowed_domainlist_check()')

        error = None
        invalid_domains = []
        # check CN and SAN against whitelist
        for domain in sans:
            if not self._is_domain_whitelisted(domain, self.allowed_domainlist):
                invalid_domains.append(domain)
                error = 'Either CN or SANs are not allowed by the configuration'

        self.logger.debug(f'CAhandler._allowed_domainlist_check() ended with {error} for {",".join(invalid_domains)}')
        return error

    def _is_domain_whitelisted(self, domain: str, whitelist: List[str]) -> bool:
        """ compare domain to whitelist returns false if not matching"""
        if not domain:
            return False

        domain = domain.lower().strip()
        encoded_domain_base = None
        encoded_domain = None

        # Handle wildcard input *before* IDNA decoding.
        if domain.startswith("*."):
            domain_base = domain[2:]
            try:
                encoded_domain_base = idna.encode(domain_base)
            except idna.IDNAError as e:
                self.logger.error(f'Invalid domain format in csr: {e}')
                return False
        else:
            try:
                encoded_domain = idna.encode(domain)
            except idna.IDNAError as e:
                self.logger.error(f'Invalid domain format in csr: {e}')
                return False

        for pattern in whitelist:
            if not pattern:
                continue

            pattern = pattern.lower().strip()

            if pattern.startswith("*."):
                pattern_base = pattern[2:]
                try:
                    encoded_pattern_base = idna.encode(pattern_base)
                except idna.IDNAError as e:
                    self.logger.error(f'Invalid pattern configured in allowed_domainlist: {e}')
                    continue

                if domain.startswith("*."):
                    # Both input and pattern are wildcards. Check if input domain base includes the pattern
                    if encoded_domain_base.endswith(encoded_pattern_base):
                        return True
                else:
                    # Input is not a wildcard, pattern is. Check endswith. Add '.' to pattern base so it's not approving the base domain
                    # for example domain foo.bar shouldn't match with pattern *.foo.bar
                    if encoded_domain.endswith(b"." + encoded_pattern_base):
                        return True
            else:
                try:
                    encoded_pattern = idna.encode(pattern)
                except idna.IDNAError as e:
                    self.logger.error(f'Invalid pattern configured in allowed_domainlist: {e}')
                    continue

                if domain.startswith("*."):
                    # Input is wildcard, pattern is not. No direct match possible
                    continue
                elif encoded_domain == encoded_pattern:
                    return True

        return False

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = load_config(self.logger, 'CAhandler')
        if 'CAhandler' in config_dic:
            if 'allowed_domainlist' in config_dic['CAhandler']:
                try:
                    self.allowed_domainlist = json.loads(config_dic['CAhandler']['allowed_domainlist'])
                except Exception as err:
                    self.logger.error('CAhandler._config_load(): failed to parse allowed_domainlist: %s', err)

        self.requester_email = config_dic['CAhandler'].get('requester_email', None)
        self.requester_password = config_dic['CAhandler'].get('requester_password', None)
        self.requester_totp_seed = config_dic['CAhandler'].get('requester_totp_seed', None)
        self.validator_email = config_dic['CAhandler'].get('validator_email', None)
        self.validator_password = config_dic['CAhandler'].get('validator_password', None)
        self.validator_totp_seed = config_dic['CAhandler'].get('validator_totp_seed', None)


        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(self.logger, config_dic)
        # load header info
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)

        self.logger.debug('CAhandler._config_load() ended')

    def _extract_certificates(self, text: str) -> Tuple[str, str] :
        """
        Extracts the certificate and its chain in pem base64 format from the Harica go client stdout.
        """
        cert_pattern = re.findall(r'(-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----)', text, re.DOTALL)

        if not cert_pattern:
            print("No certificates found.")
            return None, None

        single_cert = cert_pattern[0]  # The first certificate (end-entity)
        full_chain = "\n".join(cert_pattern)  # The full chain

        return single_cert, full_chain

    def _extract_domains(self, sans_list: List[str]) -> str:
        """
        Parses the returned list from the csr_san_get helper function and extracts only the
        domain names (without the "DNS:" prefix) into a comma-separated string.

        Returns:
            A comma-separated string of domain names, e.g., "example.com,www.example.com".
            Returns an empty string if no DNS SANs are found.
        """
        domains = []
        for san in sans_list:
            if san.startswith("DNS:"):
                domains.append(san[4:])  # Extract the part after "DNS:"
        return ",".join(domains)

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        sans = self._extract_domains(csr_san_get(self.logger, csr))
        sans_list = sans.split(',')
        error = self._allowed_domainlist_check(sans_list)

        csr_fix = f'-----BEGIN CERTIFICATE REQUEST-----\n{csr}\n-----END CERTIFICATE REQUEST-----\n'

        if not error:
            error = eab_profile_header_info_check(self.logger, self, csr, 'template_name')

        if not error:
            if sans:
                try:
                    # Run the Go tool and capture output
                    result = subprocess.run(
                        ["/var/www/acme2certifier/harica", "gen-cert", "--domains", sans,
                         "--requester-email", self.requester_email, "--requester-password", self.requester_password,
                         "--validator-email", self.validator_email, "--validator-password", self.validator_password,
                         "--validator-totp-seed", self.validator_totp_seed, "--csr", csr_fix],
                        capture_output=True,
                        text=True,
                        check=True,
                    )

                    single_cert_pem, cert_bundle = self._extract_certificates(result.stdout)
                    cert_raw = b64_encode(self.logger, cert_pem2der(single_cert_pem))

                except subprocess.CalledProcessError as e:
                    # Capture and print stderr logs if there's an error
                    self.logger.error(f'Certificate.enroll() error: ' + e.stderr)
                    error = e.stderr
            else:
                error = "No valid SAN's found in the csr."
                self.logger.error(error)
        else:
            self.logger.error('CAhandler.enroll: CSR rejected. %s', error)
        self.logger.debug('Certificate.enroll() ended')

        return (error, cert_bundle, cert_raw, poll_indentifier)

    def poll(self, cert_name: str, poll_identifier: str, _csr: str) -> Tuple[str, str, str, str, bool]:
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = "No poll implemented"
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert: str, _rev_reason: str, _rev_date: str) -> Tuple[int, str, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        self.logger.debug('Certificate.revoke() ended')
        return (code, message, detail)

    def trigger(self, payload: str) -> Tuple[str, str, str]:
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = "Not implemented"
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: %s', error)
        return (error, cert_bundle, cert_raw)
