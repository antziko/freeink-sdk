#pragma once

// FreeInk SDK — TLS 1.3 secure client.
//
// WHY: the precompiled mbedTLS shipped in the ESP-IDF/pioarduino package has
// TLS 1.3 compiled out as empty stubs (PSA crypto prerequisites disabled), so
// WiFiClientSecure / esp_http_client cannot reach TLS-1.3-only servers
// (e.g. KOSync at kosync.ak-team.com:3042 — handshake fails with
// -0x7780 MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE). A -D Kconfig flag can't change a
// precompiled .a, and a custom_sdkconfig rebuild fails on managed-component
// dependencies. The only fix that doesn't rebuild ESP-IDF is to bring our own
// TLS stack compiled from source: wolfSSL, which supports TLS 1.3 + PSA.
//
// SecureClient is an Arduino Client wrapping a wolfSSL session over a plain
// WiFiClient transport, independent of system mbedTLS.
//
// OPT-IN: enable with -DFREEINK_NET_WOLFSSL=1 and add wolfSSL to lib_deps. With
// the flag off, this compiles to an inert no-op (connectSecure() returns false)
// so the rest of the SDK builds without the wolfSSL dependency present.

#include <Arduino.h>
#include <Client.h>
#include <WiFiClient.h>

namespace freeink {

class SecureClient : public Client {
 public:
  SecureClient() = default;
  ~SecureClient() override;

  // Certificate / verification configuration (applied before connect()).
  void setCACert(const char* rootCA);
  void setInsecure();  // skip peer verification (testing only)

  // Connect and perform a TLS 1.3 handshake to host:port (uses the SNI host).
  int connect(IPAddress ip, uint16_t port) override;
  int connect(const char* host, uint16_t port) override;

  size_t write(uint8_t b) override;
  size_t write(const uint8_t* buf, size_t size) override;
  int available() override;
  int read() override;
  int read(uint8_t* buf, size_t size) override;
  int peek() override;
  void flush() override;
  void stop() override;
  uint8_t connected() override;
  operator bool() override { return connected(); }

  // True if the library was built with wolfSSL TLS 1.3 support enabled.
  static bool tls13Available();

  // wolfSSL_get_error() code from the read that ended the session, or 0 while healthy.
  // A mid-stream death is otherwise indistinguishable from a clean peer close by the
  // time it reaches a caller — both just stop the body — and this is the number that
  // tells them apart (MEMORY_E is -125, i.e. the receive buffer for an incoming record
  // could not be allocated). It was already being captured and printed to Serial, which
  // on a serial-less device meant the one diagnostic that matters was never visible.
  int lastReadError() const { return _lastReadErr; }

  // True when the last handshake resumed a cached session instead of running a full one.
  // This is the only way to tell the two apart from a log: both end in "handshake ok".
  bool sessionResumed() const { return _resumed; }

  // Phase split of the last connect(), so a caller's end-to-end "time to first byte"
  // number can be attributed. Session tickets cut the TLS leg to ~90ms, at which point
  // the leg that dominates a resumed download's per-hop cost is NOT this class's --
  // without the split there is no way to tell client-side setup from server think time.
  // tcpConnectMs covers DNS + the TCP SYN exchange (both live inside WiFiClient::connect).
  uint32_t tcpConnectMs() const { return _tcpMs; }
  uint32_t tlsHandshakeMs() const { return _tlsMs; }

 private:
  int connectWithMethod(const char* host, uint16_t port, void* method, const char* label);
  // Hand the finished session to the one-slot cache (called from stop(), before the
  // WOLFSSL object is freed) / take it back for host:port. See the cache notes in the .cpp.
  void saveSession();
  bool restoreSession(const char* host, uint16_t port);
  // stop(), plus eviction of the cached session when this handshake had restored one.
  void failHandshake();

  WiFiClient _transport;
  const char* _rootCA = nullptr;
  bool _insecure = false;
  void* _ssl = nullptr;  // WOLFSSL* (opaque to keep wolfSSL headers out of here)
  void* _ctx = nullptr;  // WOLFSSL_CTX*
  bool _connected = false;
  int _lastReadErr = 0;  // see lastReadError()
  // Host of the session currently owned by _ssl, recorded only once the handshake
  // succeeds so that stop() files the session under the right key. A name that does not
  // fit is never cached: a truncated key could alias two hosts onto one session.
  char _host[64] = {0};
  uint16_t _port = 0;
  bool _resumed = false;     // see sessionResumed()
  bool _usedStored = false;  // this connect restored a cached session
  uint32_t _tcpMs = 0;       // see tcpConnectMs()
  uint32_t _tlsMs = 0;       // see tlsHandshakeMs()
};

// Reusable backing block for wolfSSL's per-record receive buffer.
//
// WHY: wolfSSL frees its dynamic input buffer after every record it hands to the
// application (ReceiveData -> ShrinkInputBuffer, internal.c:24858) and allocates a
// fresh one for the next record (GrowInputBuffer -> XMALLOC(size + usedLength + align),
// internal.c:10784). With the 16384-byte records a default nginx sends, that is one
// ~16.4KB CONTIGUOUS allocation per record -- roughly 105 of them across a 1.7MB
// download. Post-WiFi the X3 has ~43KB free with a ~20KB largest block, so each one is
// a lottery against the transfer's own allocation churn, and device captures show it
// losing after ~200KB on every HTTPS attempt (MEMORY_E, -125). The identical file over
// plain HTTP, through the same sink and the same activity, completes at 1.7MB with zero
// retries -- the difference is entirely this buffer.
//
// Buying one block up front and serving those requests out of it turns the free/alloc
// cycle into a flag toggle, so after the first success it cannot fail again. Requests
// outside the record-size band go straight to malloc, so nothing else is affected.
//
// Scoped by RAII: while no lease is held the block does not exist and wolfSSL allocates
// exactly as it does today, which keeps connections that never stream a large body
// (KOSync, OPDS feed fetches) on the unchanged path.
class TlsRecordSlab {
 public:
  TlsRecordSlab();   // buys the block (and installs the allocators) on the first lease
  ~TlsRecordSlab();  // releases both when the last lease goes away
  TlsRecordSlab(const TlsRecordSlab&) = delete;
  TlsRecordSlab& operator=(const TlsRecordSlab&) = delete;

  // False when the block could not be bought: every allocation then behaves as before.
  bool active() const { return _owned; }

  static size_t size();      // bytes in the block
  static uint32_t hits();    // record-band requests served from the block
  static uint32_t misses();  // record-band requests that fell through to malloc
  // Largest request the block could not serve, whether because it was already taken or
  // because it exceeded size(). Non-zero alongside a MEMORY_E is what says the block is
  // mis-sized rather than mis-aimed.
  static uint32_t largestMiss();

 private:
  bool _owned = false;
};

}  // namespace freeink
