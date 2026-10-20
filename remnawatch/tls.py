"""TLS handshakes run in bounded worker threads, never in the accept loop."""
import ssl


class TLSListener:
    tls_context = None

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(5)
        try:
            return self.tls_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), address
        except BaseException:
            sock.close()
            raise


def context(certificate, private_key):
    result = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    result.minimum_version = ssl.TLSVersion.TLSv1_2
    result.load_cert_chain(certificate, private_key)
    return result
