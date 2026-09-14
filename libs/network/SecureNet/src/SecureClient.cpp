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

// --- one-slot session cache (see saveSession/restoreSession) ---
//
// WHY file-static rather than a member: HttpDownloader constructs a fresh
// SecureHttpClient (and so a fresh SecureClient) inside its resume-hop loop, so a
// per-object cache would be destroyed between every hop -- exactly the hops that need
// it. One slot is enough because the device talks to one host at a time; a second host
// simply evicts the first and pays a full handshake, which is today's behaviour.
//
// Ownership: wolfSSL_get1_session() bumps the refcount because ssl->session is created
// by wolfSSL_NewSession(), which stamps it WOLFSSL_SESSION_TYPE_HEAP (internal.c:7594,
// ssl_sess.c:3671) -- so the object outlives wolfSSL_free() and is released here with
// wolfSSL_SESSION_free(). Not a WOLFSSL_CTX-owned pointer, so freeing the CTX in stop()
// does not touch it.
WOLFSSL_SESSION* g_session = nullptr;
char g_sessionHost[64] = {0};
uint16_t g_sessionPort = 0;

void dropSession() {
  if (g_session) {
    wolfSSL_SESSION_free(g_session);
    g_session = nullptr;
  }
  g_sessionHost[0] = '\0';
  g_sessionPort = 0;
}

bool isWantIo(const int err) {
  // Only the wolfSSL_get_error() codes. The WOLFSSL_CBIO_ERR_* callback return
  // codes never come out of wolfSSL_get_error and collide with fatal wolfCrypt
  // errors (MP_MEM is -2 == WOLFSSL_CBIO_ERR_WANT_READ); matching them here made
  // an out-of-memory handshake spin until the deadline instead of failing fast.
  return err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE;
}
}  // namespace

void SecureClient::saveSession() {
  // Called from stop(), i.e. after every read on this session has been made -- which is
  // the only correct moment, because a TLS 1.3 NewSessionTicket is post-handshake
  // application-layer data and lands in ssl->session during wolfSSL_read, not during
  // wolfSSL_connect. Snapshotting at handshake time would cache a ticketless session.
  if (!_ssl || _host[0] == '\0') return;
  auto* fresh = wolfSSL_get1_session(static_cast<WOLFSSL*>(_ssl));
  if (!fresh) return;
  if (!wolfSSL_SessionIsSetup(fresh)) {
    // A failed or half-built handshake: drop the reference get1 just took and keep
    // whatever was already cached.
    wolfSSL_SESSION_free(fresh);
    return;
  }
  // Take over the reference get1_session added, THEN release the previous slot holder.
  // Order matters when they are the same object (wolfSSL_set_session points ssl->session
  // straight at ours and up-refs it): releasing first would work on a count of 2, but
  // doing it in this order means the pointer is never momentarily unowned.
  WOLFSSL_SESSION* prev = g_session;
  g_session = fresh;
  strncpy(g_sessionHost, _host, sizeof(g_sessionHost) - 1);
  g_sessionHost[sizeof(g_sessionHost) - 1] = '\0';
  g_sessionPort = _port;
  if (prev) wolfSSL_SESSION_free(prev);
}

bool SecureClient::restoreSession(const char* host, uint16_t port) {
  if (!g_session || !_ssl) return false;
  if (port != g_sessionPort || strcmp(host, g_sessionHost) != 0) return false;
  if (wolfSSL_set_session(static_cast<WOLFSSL*>(_ssl), g_session) != WOLFSSL_SUCCESS) {
    // Expired, wrong role, or the cache rejected it. Not an error -- fall through to a
    // full handshake -- but the slot is useless now, so give the memory back.
    dropSession();
    return false;
  }
  return true;
}

int SecureClient::connectWithMethod(const char* host, uint16_t port, void* method, const char* label) {
  _lastReadErr = 0;  // per-connection: never report a previous session's death
  _resumed = false;
  _usedStored = false;
  _tcpMs = 0;
  _tlsMs = 0;
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
  const uint32_t tcpStart = millis();
  if (!_transport.connect(host, port)) {
    if (Serial) Serial.printf("[SecureClient] TCP connect failed (%s): %s:%u\n", label, host, port);
    return 0;
  }
  _tcpMs = millis() - tcpStart;  // includes DNS: WiFiClient::connect resolves the name

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
  // Must precede wolfSSL_connect: set_session is what puts the cached ticket in the
  // ClientHello's pre_shared_key extension.
  _usedStored = restoreSession(host, port);

  // The recv callback is non-blocking (returns WANT_READ when no bytes are
  // buffered), so wolfSSL_connect must be retried across handshake round-trips
  // rather than called once.
  const uint32_t tlsStart = millis();
  const uint32_t deadline = tlsStart + timeoutMs;
  int ret;
  while ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
    const int err = wolfSSL_get_error(ssl, ret);
    if (!isWantIo(err)) {
      if (Serial) Serial.printf("[SecureClient] wolfSSL_connect failed (%s): %d\n", label, err);
      // Keep the FIRST failure of this connect(): the auto-version attempt is the one that
      // negotiated, and the TLS 1.2 fallback below would otherwise overwrite its verdict.
      if (_lastHandshakeErr == 0) _lastHandshakeErr = err;
      failHandshake();
      return 0;
    }
    if (static_cast<int32_t>(millis() - deadline) >= 0) {
      if (Serial) {
        Serial.printf("[SecureClient] handshake timeout (%s): last err %d, transport %s, free heap %u\n", label, err,
                      _transport.connected() ? "up" : "down", (unsigned)ESP.getFreeHeap());
      }
      if (_lastHandshakeErr == 0) _lastHandshakeErr = err;
      failHandshake();
      return 0;
    }
    delay(5);
  }
  _lastHandshakeErr = 0;  // a fallback that connects clears the failed attempt before it
  _connected = true;
  _tlsMs = millis() - tlsStart;
  _resumed = wolfSSL_session_reused(ssl) == 1;
  // Record the key only now: stop() files the session under _host, and a handshake that
  // never completed must not overwrite the slot belonging to a host that did. A name too
  // long for the buffer is left empty, which disables caching for this connection --
  // truncating could alias two hosts onto one session.
  if (strlen(host) < sizeof(_host)) {
    strncpy(_host, host, sizeof(_host) - 1);
    _host[sizeof(_host) - 1] = '\0';
    _port = port;
  } else {
    _host[0] = '\0';
  }
  if (Serial) {
    Serial.printf("[SecureClient] handshake ok (%s): %s / %s in %lu ms%s\n", label, wolfSSL_get_version(ssl),
                  wolfSSL_get_cipher(ssl), (unsigned long)(millis() - started), _resumed ? " (resumed)" : "");
  }
  return 1;
}

void SecureClient::failHandshake() {
  // A handshake that died after we offered a cached session is the one case where the
  // cache itself is suspect (expired ticket, server rotated its STEK, resumption
  // rejected fatally). Throw it away so the immediate retry -- and the TLS 1.2 fallback
  // in connect() -- runs clean. Fail-closed: the cost of being wrong is one full
  // handshake, which is what every connection did before this existed.
  const bool poisoned = _usedStored;
  stop();
  if (poisoned) dropSession();
}

int SecureClient::connect(const char* host, uint16_t port) {
  // Per connect(), not per attempt: connectWithMethod runs twice below and the caller
  // reads one verdict.
  _lastHandshakeErr = 0;
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
  if (Serial) {
    Serial.printf("[SecureClient] read failed: %d, free heap %u, max block %u\n", err, (unsigned)ESP.getFreeHeap(),
                  (unsigned)ESP.getMaxAllocHeap());
  }
  _connected = false;
  return -1;
}

int SecureClient::available() {
  if (!_connected) return 0;
  return wolfSSL_pending(static_cast<WOLFSSL*>(_ssl)) + _transport.available();
}

void SecureClient::stop() {
  saveSession();  // must precede wolfSSL_free: it reads ssl->session
  if (_ssl) { wolfSSL_free(static_cast<WOLFSSL*>(_ssl)); _ssl = nullptr; }
  if (_ctx) { wolfSSL_CTX_free(static_cast<WOLFSSL_CTX*>(_ctx)); _ctx = nullptr; }
  _transport.stop();
  _connected = false;
}

uint8_t SecureClient::connected() { return _connected && _transport.connected(); }

// --- TlsRecordSlab (see SecureClient.h for why this exists) ---

namespace {
// GetInputData() calls GrowInputBuffer(ssl, curSize, usedLength), which asks for
// curSize + usedLength + align: align is at most 16 (settings.h:2320) and usedLength at
// the growing call is the few header bytes left over from the previous read.
//
// 5120, not 17408. The old figure assumed the peer sends MAX_RECORD_SIZE (16384) records.
// It does not, and that assumption made this whole mechanism inert: 17408 was never once
// buyable on a device, so every capture shows active=0 / slabHit=0.
//
// What the peer actually sends, measured through a TCP relay that frames the CLEARTEXT
// TLS record headers (scripts/tls_record_probe.py) against the real origin over HTTP/1.1:
//
//     bytes into connection      record size
//     0        ..  59,957        1,386
//     59,957   .. 230,583        4,246
//     230,583  ..                16,401
//
// It is a ramp, not a constant, and it restarts on every new connection. So the wall a
// hop actually dies on is 4,246 -- and 37 x 1,386 = 51,282 against the smallest hop ever
// observed on X3, 51,731. That is the failure: the hop clears the 1,386 phase and cannot
// allocate for the step to 4,246.
//
// 5120 covers 4,246 + header + align with room. Sizing between here and 16401 buys almost
// nothing: past 230,583 the ramp jumps straight to the TLS maximum, so an 11KB block would
// clear a handful of 8-10KB transition records and then die anyway. And 16401 needs the
// 17408 block that two boards have now proven cannot be bought. The ceiling this creates
// is therefore ~230KB per hop, by design and not by accident.
constexpr size_t SLAB_SIZE = 5120;
// Only divert requests big enough to be a record buffer. Handing the block to a small
// caller would strand it for the rest of the transfer, which is the failure this is meant
// to prevent. 4096 sits below the 4,246-byte requests that matter and above the 1,386-byte
// phase, which already succeeds through plain malloc and must keep doing so.
constexpr size_t SLAB_MIN_REQUEST = 4096;

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
void SecureClient::saveSession() {}
bool SecureClient::restoreSession(const char* host, uint16_t port) { (void)host; (void)port; return false; }
void SecureClient::failHandshake() { stop(); }

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
