use rustls::{
	client::{ServerCertVerified, ServerCertVerifier},
	ServerName,
};

/// A wrapper around the client version of the tokio_rustls enum.
pub type _ClientTlsStream<T> = tokio_rustls::client::TlsStream<T>;
/// A wrapper around the server version of the tokio_rustls enum
pub type ServerTlsStream<T> = tokio_rustls::server::TlsStream<T>;
/// A wrapper type around the tokio_rustls TlsStream enum
pub type TlsStreamEnum<T> = tokio_rustls::TlsStream<T>;

/// This custom struct is used to bypass certificate validation when needed, typically for development and testing.
///
/// This is **NOT** intended for production use.
pub(crate) struct CertVerifier;
impl ServerCertVerifier for CertVerifier {
	fn verify_server_cert(
		&self, _end_entity: &rustls::Certificate, _intermediates: &[rustls::Certificate], _server_name: &ServerName,
		_scts: &mut dyn Iterator<Item = &[u8]>, _ocsp_response: &[u8], _now: std::time::SystemTime,
	) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
		Ok(ServerCertVerified::assertion())
	}
}
