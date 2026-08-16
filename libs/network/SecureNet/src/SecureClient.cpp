#include "SecureClient.h"

// wolfSSL is only pulled in when explicitly enabled. This keeps the default SDK
// build free of the wolfSSL dependency while leaving a single, well-defined
// integration point for the TLS 1.3 transport.
#if defined(FREEINK_NET_WOLFSSL)
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/memory.h>

#include <atomic>
#include <cstdlib>
#include <cstring>
#endif

namespace freeink {

bool SecureClient::tls13Available() {
#if defined(FREEINK_NET_WOLFSSL)
  return true;
#else
  return false;
#endif
}

SecureClient::~SecureClient() { stop(); }

void SecureClient::setCACert(const char* rootCA) { _rootCA = rootCA; }
void SecureClient::setInsecure() { _insecure = true; }

#if defined(FREEINK_NET_WOLFSSL)

namespace {
// Bridge wolfSSL's I/O to the underlying WiFiClient transport.
int wcSend(WOLFSSL* /*ssl*/, char* buf, int sz, void* ctx) {
  auto* t = static_cast<WiFiClient*>(ctx);
  const int n = t->write(reinterpret_cast<const uint8_t*>(buf), sz);
  if (n <= 0) {
    // A dead transport must surface as CONN_CLOSE: mapping it to WANT_WRITE
    // makes the handshake spin until the deadline instead of failing fast.
    if (!t->connected()) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return WOLFSSL_CBIO_ERR_WANT_WRITE;
  }
  return n;
}
int wcRecv(WOLFSSL* /*ssl*/, char* buf, int sz, void* ctx) {
  auto* t = static_cast<WiFiClient*>(ctx);
  if (!t->connected() && t->available() == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
  if (t->available() == 0) return WOLFSSL_CBIO_ERR_WANT_READ;
  const int n = t->read(reinterpret_cast<uint8_t*>(buf), sz);
  if (n <= 0) return WOLFSSL_CBIO_ERR_WANT_READ;
  return n;
}

bool isWantIo(const int err) {
  // Only the wolfSSL_get_error() codes. The WOLFSSL_CBIO_ERR_* callback return
  // codes never come out of wolfSSL_get_error and collide with fatal wolfCrypt
  // errors (MP_MEM is -2 == WOLFSSL_CBIO_ERR_WANT_READ); matching them here made
  // an out-of-memory handshake spin until the deadline instead of failing fast.
  return err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE;
}
}  // namespace

int SecureClient::connectWithMethod(const char* host, uint16_t port, void* method, const char* label) {
  _lastReadErr = 0;  // per-connection: never report a previous session's death
#if defined(FREEINK_WOLFSSL_DEBUG)
  // Routes wolfSSL's internal trace through wolfSSL_Arduino_Serial_Print (the
  // application provides that hook). Shows exactly where a handshake stalls.
  static bool debugEnabled = false;
  if (!debugEnabled) {
    wolfSSL_Debugging_ON();
    debugEnabled = true;
  }
#endif
  const uint32_t started = millis();
  stop();
  const uint32_t timeoutMs = getTimeout();
  _transport.setConnectionTimeout(timeoutMs);
  if (!_transport.connect(host, port)) {
    if (Serial) Serial.printf("[SecureClient] TCP connect failed (%s): %s:%u\n", label, host, port);
    return 0;
  }

  auto* ctx = wolfSSL_CTX_new(static_cast<WOLFSSL_METHOD*>(method));
  if (!ctx) {
    if (Serial) Serial.printf("[SecureClient] CTX alloc failed (%s), free heap %u\n", label, (unsigned)ESP.getFreeHeap());
    _transport.stop();
    return 0;
  }
  _ctx = ctx;

  if (_insecure) {
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, nullptr);
  } else if (_rootCA) {
    wolfSSL_CTX_load_verify_buffer(ctx, reinterpret_cast<const unsigned char*>(_rootCA),
                                   strlen(_rootCA), WOLFSSL_FILETYPE_PEM);
  }
  wolfSSL_SetIORecv(ctx, wcRecv);
  wolfSSL_SetIOSend(ctx, wcSend);

  auto* ssl = wolfSSL_new(ctx);
  if (!ssl) {
    if (Serial) Serial.printf("[SecureClient] SSL alloc failed (%s), free heap %u\n", label, (unsigned)ESP.getFreeHeap());
    stop();
    return 0;
  }
  _ssl = ssl;
  wolfSSL_SetIOReadCtx(ssl, &_transport);
  wolfSSL_SetIOWriteCtx(ssl, &_transport);
  wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host, strlen(host));
#if defined(WOLFSSL_TLS13) && defined(HAVE_CURVE25519)
  // MEMFIX-PORT: pin the TLS 1.3 key_share to X25519. wolfSSL's default is a
  // P-256 share, generated with fast-math bignums that WOLFSSL_SMALL_STACK
  // heap-allocates at ~4KB apiece (FP_MAX_BITS-sized) -- at the free-heap
  // levels a reading session leaves (~45-50KB) that keygen fails with MP_MEM
  // and the ClientHello is never sent. Curve25519 uses fixed 32-byte field
  // arithmetic with no bignum temporaries. A server without X25519 answers
  // with a HelloRetryRequest and wolfSSL falls back to its group list.
  wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519);
#endif
#ifdef HAVE_MAX_FRAGMENT
  // Ask the peer to cap TLS records at 2KB (RFC 6066 max_fragment_length).
  // wolfSSL sizes its receive buffer to each incoming record, so a default
  // 16KB record demands a ~17KB contiguous allocation per record -- measured
  // failing (MEMORY_E mid-download) at the ~20KB free heap a busy activity
  // leaves. With 2KB records the receive buffer stays trivial. Servers that
  // ignore the extension keep 16KB records and behave as before.
  wolfSSL_UseMaxFragment(ssl, WOLFSSL_MFL_2_11);
#endif

  // The recv callback is non-blocking (returns WANT_READ when no bytes are
  // buffered), so wolfSSL_connect must be retried across handshake round-trips
  // rather than called once.
  const uint32_t deadline = millis() + timeoutMs;
  int ret;
  while ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
    const int err = wolfSSL_get_error(ssl, ret);
    if (!isWantIo(err)) {
      if (Serial) Serial.printf("[SecureClient] wolfSSL_connect failed (%s): %d\n", label, err);
      stop();
      return 0;
    }
    if (static_cast<int32_t>(millis() - deadline) >= 0) {
      if (Serial) {
        Serial.printf("[SecureClient] handshake timeout (%s): last err %d, transport %s, free heap %u\n", label, err,
                      _transport.connected() ? "up" : "down", (unsigned)ESP.getFreeHeap());
      }
      stop();
      return 0;
    }
    delay(5);
  }
  _connected = true;
  if (Serial) {
    Serial.printf("[SecureClient] handshake ok (%s): %s / %s in %lu ms\n", label, wolfSSL_get_version(ssl),
                  wolfSSL_get_cipher(ssl), (unsigned long)(millis() - started));
  }
  return 1;
}

int SecureClient::connect(const char* host, uint16_t port) {
  // Negotiate the highest mutually supported version rather than pinning TLS 1.3:
  // self-hosted / Let's Encrypt nginx often tops out at TLS 1.2, and a 1.3-only
  // client fails those handshakes outright. v23 still selects 1.3 when the peer
  // offers it (WOLFSSL_TLS13 is enabled) and falls back to 1.2 otherwise.
  if (connectWithMethod(host, port, wolfSSLv23_client_method(), "auto")) return 1;

  // Some TLS 1.2-only servers are intolerant of a TLS 1.3-capable ClientHello
  // and abort with a fatal handshake_failure alert. Retry with an explicit
  // TLS 1.2 ClientHello before giving up.
  if (Serial) Serial.println("[SecureClient] retrying with TLS 1.2-only handshake");
  return connectWithMethod(host, port, wolfTLSv1_2_client_method(), "tls1.2");
}

int SecureClient::connect(IPAddress ip, uint16_t port) {
  char host[16];
  snprintf(host, sizeof(host), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return connect(host, port);
}

size_t SecureClient::write(const uint8_t* buf, size_t size) {
  if (!_connected) return 0;
  const int n = wolfSSL_write(static_cast<WOLFSSL*>(_ssl), buf, size);
  return n > 0 ? static_cast<size_t>(n) : 0;
}

int SecureClient::read(uint8_t* buf, size_t size) {
  if (!_connected) return -1;
  auto* ssl = static_cast<WOLFSSL*>(_ssl);
  const int n = wolfSSL_read(ssl, buf, size);
  if (n > 0) return n;

  const int err = wolfSSL_get_error(ssl, n);
  if (isWantIo(err)) return 0;
  if (err == WOLFSSL_ERROR_ZERO_RETURN) {
    _connected = false;
    return 0;
  }
  // A mid-stream failure is invisible to callers (they just see the connection
  // die); the error code distinguishes an OOM (MEMORY_E -125) from a peer
  // drop or MAC failure. Recorded as well as printed: the Serial line below is
  // dead weight on a device with no cable, which is exactly where these failures
  // are reported from, so lastReadError() is what actually reaches a log.
  _lastReadErr = err;
  if (Serial) Serial.printf("[SecureClient] read failed: %d, free heap %u\n", err, (unsigned)ESP.getFreeHeap());
  _connected = false;
  return -1;
}

int SecureClient::available() {
  if (!_connected) return 0;
  return wolfSSL_pending(static_cast<WOLFSSL*>(_ssl)) + _transport.available();
}

void SecureClient::stop() {
  if (_ssl) { wolfSSL_free(static_cast<WOLFSSL*>(_ssl)); _ssl = nullptr; }
  if (_ctx) { wolfSSL_CTX_free(static_cast<WOLFSSL_CTX*>(_ctx)); _ctx = nullptr; }
  _transport.stop();
  _connected = false;
}

uint8_t SecureClient::connected() { return _connected && _transport.connected(); }

// --- TlsRecordSlab (see SecureClient.h for why this exists) ---

namespace {
// GetInputData() calls GrowInputBuffer(ssl, curSize, usedLength), which asks for
// curSize + usedLength + align: MAX_RECORD_SIZE is 16384 (internal.h:2292), align is at
// most 16 (settings.h:2320), and usedLength at the growing call is the few header bytes
// left over from the previous read, so 1KB of headroom covers it.
//
// The exact figure is 17408 because that is measured, not guessed: the reservation this
// replaces asked for 17408 bytes at this same point in 38 consecutive device transfers
// and got it every time. Going bigger for extra headroom would trade a certainty for a
// maybe — if the block cannot be bought the whole mechanism is inactive.
constexpr size_t SLAB_SIZE = 16384 + 1024;
// Only divert requests big enough to be a record buffer. Handing the block to a 2KB
// caller would strand it for the rest of the transfer, which is the failure this is
// meant to prevent.
constexpr size_t SLAB_MIN_REQUEST = 8192;

uint8_t* g_slab = nullptr;
std::atomic<bool> g_slabBusy{false};
uint32_t g_slabHits = 0;
uint32_t g_slabMisses = 0;
// Largest request that was in the band but could not be served, and the largest that
// overshot SLAB_SIZE entirely. If a capture ever shows tlsErr=-125 with slabHit>0 and
// slabOver>0, SLAB_SIZE is the thing to change — without this the two are guesswork.
uint32_t g_slabMaxMiss = 0;
uint32_t g_slabMaxOver = 0;
// Atomic so that two leases taken from different tasks cannot race the refcount down to
// zero twice and free the block while a session still points at it. The counters above
// are diagnostics only and are left plain.
std::atomic<int> g_slabLeases{0};

// wolfSSL_SetAllocators takes plain C signatures (no WOLFSSL_STATIC_MEMORY and no
// WOLFSSL_DEBUG_MEMORY in this build), and wolfSSL_Malloc/Free/Realloc route through
// them for every XMALLOC/XFREE/XREALLOC in the library.
void* slabMalloc(size_t size) {
  if (size >= SLAB_MIN_REQUEST && g_slab) {
    if (size > SLAB_SIZE) {
      if (size > g_slabMaxOver) g_slabMaxOver = static_cast<uint32_t>(size);
    } else if (!g_slabBusy.exchange(true)) {
      // exchange, not a read-then-write: the claim has to be atomic or two owners could
      // walk away with the same block. Uncontended here (one TLS session at a time), so
      // this costs a single instruction on the record path.
      ++g_slabHits;
      return g_slab;
    } else {
      ++g_slabMisses;
      if (size > g_slabMaxMiss) g_slabMaxMiss = static_cast<uint32_t>(size);
    }
  }
  return malloc(size);
}

void slabFree(void* ptr) {
  if (ptr == nullptr) return;
  if (ptr == g_slab) {
    g_slabBusy.store(false);
    return;
  }
  free(ptr);
}

void* slabRealloc(void* ptr, size_t size) {
  if (ptr != g_slab) return realloc(ptr, size);
  // wolfSSL grows the record buffer with XMALLOC + XMEMCPY rather than XREALLOC, so this
  // is not expected to fire — but realloc() must never be handed a pointer it does not
  // own. Copy out and give the block back instead.
  void* out = malloc(size);
  if (out) {
    memcpy(out, g_slab, size < SLAB_SIZE ? size : SLAB_SIZE);
    g_slabBusy.store(false);
  }
  return out;
}
}  // namespace

TlsRecordSlab::TlsRecordSlab() {
  if (g_slab == nullptr && g_slabLeases.load() == 0) {
    // Raw malloc rather than makeUniqueNoThrow: the pointer is handed to wolfSSL's C
    // allocator hooks and has to outlive every scope here, so there is no owner to give
    // it to. Freed in the destructor of the last lease.
    g_slab = static_cast<uint8_t*>(malloc(SLAB_SIZE));
    if (g_slab) {
      g_slabBusy.store(false);
      g_slabHits = 0;
      g_slabMisses = 0;
      g_slabMaxMiss = 0;
      g_slabMaxOver = 0;
      wolfSSL_SetAllocators(slabMalloc, slabFree, slabRealloc);
    }
  }
  if (g_slab) {
    g_slabLeases.fetch_add(1);
    _owned = true;
  }
}

TlsRecordSlab::~TlsRecordSlab() {
  if (!_owned) return;
  if (g_slabLeases.fetch_sub(1) > 1) return;  // fetch_sub returns the value BEFORE the decrement
  // Never pull the block out from under a live session. This cannot happen the way the
  // downloader uses it (the lease outlives every SecureHttpClient it covers), but if a
  // connection ever did outlive its lease, keeping the block and the allocators costs
  // SLAB_SIZE until the next lease reuses and then releases it — dropping them would
  // corrupt the session instead.
  if (g_slabBusy.load()) return;
  wolfSSL_SetAllocators(nullptr, nullptr, nullptr);
  free(g_slab);
  g_slab = nullptr;
}

size_t TlsRecordSlab::size() { return SLAB_SIZE; }
uint32_t TlsRecordSlab::hits() { return g_slabHits; }
uint32_t TlsRecordSlab::misses() { return g_slabMisses; }
uint32_t TlsRecordSlab::largestMiss() { return g_slabMaxMiss > g_slabMaxOver ? g_slabMaxMiss : g_slabMaxOver; }

#else  // !FREEINK_NET_WOLFSSL — inert stub so the SDK builds without wolfSSL.

TlsRecordSlab::TlsRecordSlab() = default;
TlsRecordSlab::~TlsRecordSlab() = default;
size_t TlsRecordSlab::size() { return 0; }
uint32_t TlsRecordSlab::hits() { return 0; }
uint32_t TlsRecordSlab::misses() { return 0; }
uint32_t TlsRecordSlab::largestMiss() { return 0; }

int SecureClient::connect(const char* host, uint16_t port) {
  (void)host; (void)port;
  if (Serial) Serial.println("[SecureClient] TLS 1.3 unavailable: build with -DFREEINK_NET_WOLFSSL=1");
  return 0;
}
int SecureClient::connect(IPAddress ip, uint16_t port) { (void)ip; (void)port; return 0; }
size_t SecureClient::write(const uint8_t* buf, size_t size) { (void)buf; (void)size; return 0; }
int SecureClient::read(uint8_t* buf, size_t size) { (void)buf; (void)size; return -1; }
int SecureClient::available() { return 0; }
void SecureClient::stop() { _transport.stop(); _connected = false; }
uint8_t SecureClient::connected() { return 0; }

#endif

// --- transport-agnostic single-byte helpers (shared) ---
size_t SecureClient::write(uint8_t b) { return write(&b, 1); }
int SecureClient::read() {
  uint8_t b;
  return read(&b, 1) == 1 ? b : -1;
}
int SecureClient::peek() { return -1; }
void SecureClient::flush() {}

}  // namespace freeink
